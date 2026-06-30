#!/usr/bin/env python3
"""
Vulnerability Discovery Pipeline — Claude Agent SDK 编排器

一键执行完整漏洞发现流程:
  Phase 1: Program Analysis  → 分析 CLI 结构、调用链、漏洞路径评分
  Phase 2: Preprocess        → AFL++ 编译、策略设计、种子生成、输出 fuzz_manifest.json
  Phase 3: Execute Fuzz      → 读取 manifest，启动 batch 1，验证后退出
  Phase 4: Issue Generator   → 生成 GitHub Issue 报告

所有编译 / fuzz 命令通过 Docker SDK 在 AFL++ 容器内执行。

用法:
  python -m pipeline /path/to/target_project
  python -m pipeline /path/to/target_project --resume   # 从断点继续
  python -m pipeline /path/to/target_project --phase 1  # 只跑指定阶段
"""

import anyio
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

DEFAULT_FUZZ_TIMEOUT = 86400  # 24 小时
STOP_SIGNAL = ".stop_signal"  # Web UI touch 此文件请求停止，在消息循环中被检测

# Windows GBK 终端兼容
if sys.stdout.encoding and sys.stdout.encoding.lower() in ("gbk", "gb2312", "gb18030"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

logger = logging.getLogger("pipeline")


def setup_logging(work_dir: str) -> str:
    """配置日志: 同时输出到终端和文件。返回日志文件路径。"""
    log_dir = Path(work_dir) / "log"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"pipeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(str(log_file), encoding="utf-8")
    fh.setFormatter(fmt)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)

    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.addHandler(fh)
    logger.addHandler(sh)

    return str(log_file)


def log_artifact(file_path: str) -> None:
    """记录生成的文件及其大小。"""
    p = Path(file_path)
    if p.exists():
        size_kb = p.stat().st_size / 1024
        logger.info("  [artifact] %s (%.1f KB)", file_path, size_kb)
    else:
        logger.warning("  [artifact] %s (NOT YET CREATED)", file_path)


from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    AssistantMessage,
    ResultMessage,
    SystemMessage,
    TextBlock,
)
from pipeline.container import ContainerManager, ContainerError
from pipeline.container_tools import create_container_server

BASE_DIR = Path(__file__).resolve().parent.parent
CONTAINER_NAME = "afl"

ARTIFACTS = {
    "program-analysis": [
        "command_combinations.json",
        "vulnerability_path_scores.md",
        "call_tree.md",
        "coverage_summary.md",
    ],
    "auto-fuzz": ["fuzz_manifest.json"],
    "auto-fuzz-exec": ["fuzz_started.signal"],
    "issue-generator": ["issues/SUMMARY.md"],
}

BASE_TOOLS = ["Read", "Write", "Edit", "Bash", "Glob", "Grep"]


# ──────────────────────────────────────────────
# Container Verification
# ──────────────────────────────────────────────

def verify_container() -> ContainerManager:
    """连接并验证 AFL++ 容器，必要时自动启动。"""
    mgr = ContainerManager(container_name=CONTAINER_NAME)

    try:
        logger.info("[container] connecting...")
        info = mgr.status()
        logger.info("[container] name=%s  exists=%s  running=%s  status=%s",
                     CONTAINER_NAME, info["exists"], info["running"], info["status"])

        if not info["exists"]:
            logger.error("[container] 容器不存在。请先运行: docker compose up -d")
            sys.exit(1)

        mgr.ensure_running(auto_start=True)
        logger.info("[container] 已就绪")

        if mgr.check_afl_available():
            logger.info("[container] afl-fuzz 可用")
        else:
            logger.warning("[container] 容器内未检测到 afl-fuzz")
    except ContainerError as e:
        logger.error("[container] 连接失败: %s", e)
        sys.exit(1)

    return mgr


def stop_existing_fuzz(mgr: ContainerManager, target: str) -> None:
    """停止容器中指定项目的 afl-fuzz 进程，防止冲突。"""
    project_name = Path(target).name
    logger.info("[container] checking for afl-fuzz processes for '%s'...", project_name)
    try:
        # afl-fuzz 命令行中会包含目标项目的二进制路径，用项目名匹配
        out = mgr.exec(
            f"ps aux | grep afl-fuzz | grep '{project_name}' | grep -v grep || true"
        )
        if out.strip():
            count = out.strip().count('\n') + 1 if '\n' in out.strip() else 1
            logger.info("[container] found %d afl-fuzz process(es) for '%s', stopping...",
                        count, project_name)
            mgr.exec(
                f"ps aux | grep afl-fuzz | grep '{project_name}' | grep -v grep "
                f"| awk '{{print $2}}' | xargs -r kill -9 2>/dev/null || true"
            )
            # 确认停止
            remained = mgr.exec(
                f"ps aux | grep afl-fuzz | grep '{project_name}' | grep -v grep || true"
            )
            if remained.strip():
                mgr.exec(
                    f"ps aux | grep afl-fuzz | grep '{project_name}' | grep -v grep "
                    f"| awk '{{print $2}}' | xargs -r kill -9 2>/dev/null || true"
                )
            logger.info("[container] afl-fuzz processes for '%s' stopped", project_name)
        else:
            logger.info("[container] no existing afl-fuzz processes for '%s'", project_name)
    except ContainerError:
        logger.info("[container] no existing afl-fuzz processes for '%s'", project_name)


# ──────────────────────────────────────────────
# State Detection
# ──────────────────────────────────────────────

def check_phase(work_dir: Path, phase: str) -> bool:
    return all((work_dir / a).exists() for a in ARTIFACTS[phase])


def detect_state(work_dir: Path) -> int:
    if check_phase(work_dir, "issue-generator"):
        return 5
    if check_phase(work_dir, "auto-fuzz-exec"):
        return 4
    if check_phase(work_dir, "auto-fuzz"):
        return 3
    if check_phase(work_dir, "program-analysis"):
        return 2
    return 1


def print_state(work_dir: Path) -> None:
    logger.info("=" * 60)
    logger.info("  Pipeline State Check")
    logger.info("=" * 60)
    phases = [
        ("Phase 1: Program Analysis", ["command_combinations.json", "vulnerability_path_scores.md", "call_tree.md", "coverage_summary.md"]),
        ("Phase 2: Preprocess", ["fuzz_manifest.json"]),
        ("Phase 3: Execute Fuzz", ["fuzz_started.signal"]),
        ("Phase 4: Issue Generator", ["issues/SUMMARY.md"]),
    ]
    for label, artifacts in phases:
        done = all((work_dir / a).exists() for a in artifacts)
        status = "[OK] COMPLETE" if done else "[..] PENDING"
        logger.info("  %s %s", status, label)
    logger.info("=" * 60)


# ──────────────────────────────────────────────
# Phase Prompts — 直接调技能，不嵌入 skill 全文
# ──────────────────────────────────────────────



# ──────────────────────────────────────────────
# Pipeline Execution
# ──────────────────────────────────────────────

async def run_phase(phase: int, prompt: str, work_dir: str, mcp_servers: dict | None = None, skills: list[str] | None = None) -> None:
    t0 = time.time()
    logger.info("")
    logger.info("=" * 60)
    logger.info("  Phase %s — Running...", phase)
    logger.info("=" * 60)

    perm_mode = "bypassPermissions" if mcp_servers else "acceptEdits"
    options = ClaudeAgentOptions(
        cwd=work_dir,
        allowed_tools=BASE_TOOLS,
        permission_mode=perm_mode,
        mcp_servers=mcp_servers or {},
        skills=skills,
    )

    msg_count = 0
    _stop_requested = False
    stop_file = Path(work_dir) / STOP_SIGNAL
    stop_file.unlink(missing_ok=True)  # 清理上一次的停止信号

    async def _run_agent() -> None:
        nonlocal msg_count, _stop_requested
        if mcp_servers:
            async with ClaudeSDKClient(options=options) as client:
                await client.query(prompt)
                async for message in client.receive_response():
                    msg_count += 1
                    if isinstance(message, AssistantMessage):
                        for block in message.content:
                            if isinstance(block, TextBlock):
                                logger.info("[Phase %s] %s", phase, block.text[:500])
                    elif isinstance(message, ResultMessage):
                        logger.info("[Phase %s] %s", phase, message.result[:500])
                        if message.subtype == "success" and message.stop_reason == "end_turn":
                            logger.info("[Phase %s] agent completed", phase)
                            break
                    elif isinstance(message, SystemMessage):
                        if message.subtype == "init":
                            logger.info("[Phase %s] session started", phase)
                    # 检查停止信号（Web UI 通过 touch .stop_signal 触发）
                    if stop_file.exists():
                        logger.info("[Phase %s] stop signal received, disconnecting agent...", phase)
                        client.disconnect()
                        _stop_requested = True
                        break
        else:
            logger.info("[Phase %s] waiting for agent response...", phase)
            async for message in query(prompt=prompt, options=options):
                msg_count += 1
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            logger.info("[Phase %s] %s", phase, block.text[:500])
                elif isinstance(message, ResultMessage):
                    logger.info("[Phase %s] %s", phase, message.result[:500])
                    if message.subtype == "success" and message.stop_reason == "end_turn":
                        logger.info("[Phase %s] agent completed", phase)
                        break
                elif isinstance(message, SystemMessage):
                    if message.subtype == "init":
                        logger.info("[Phase %s] session started", phase)
                # 检查停止信号
                if stop_file.exists():
                    logger.info("[Phase %s] stop signal received", phase)
                    _stop_requested = True
                    break

    await _run_agent()

    if _stop_requested and phase == 3:
        # 清理容器内本项目的 afl-fuzz 进程
        project_name = Path(work_dir).name
        logger.info("[Phase %s] cleaning up afl-fuzz processes for '%s'...", phase, project_name)
        try:
            mgr = ContainerManager(container_name=CONTAINER_NAME)
            mgr.ensure_running()
            mgr.exec(
                f"ps aux | grep afl-fuzz | grep '{project_name}' | grep -v grep "
                f"| awk '{{print $2}}' | xargs -r kill -9 2>/dev/null || true"
            )
            logger.info("[Phase %s] afl-fuzz processes cleaned up", phase)
        except Exception as e:
            logger.warning("[Phase %s] failed to clean up afl-fuzz: %s", phase, e)
    elif _stop_requested:
        logger.info("[Phase %s] stop requested (no container cleanup needed)", phase)

    elapsed = time.time() - t0
    logger.info("")
    logger.info("=" * 60)
    logger.info("  Phase %s — Complete (%d messages, %.1fs)", phase, msg_count, elapsed)
    logger.info("=" * 60)
    phase_artifacts = {
        1: ["command_combinations.json", "vulnerability_path_scores.md", "call_tree.md", "coverage_summary.md"],
        2: ["fuzz_manifest.json"],
        3: ["fuzz_started.signal"],
        4: ["issues/SUMMARY.md"],
    }.get(phase, [])
    for art in phase_artifacts:
        log_artifact(str(Path(work_dir) / art))


async def run_pipeline(target: str, work_dir: str, start_phase: int = 1, end_phase: int = 4, fuzz_timeout: int = DEFAULT_FUZZ_TIMEOUT) -> None:
    project_name = Path(target).name
    container: ContainerManager | None = None
    FUZZ_CONT = f"/workspace/fuzz_{project_name}"  # 容器内路径（在 volume mount 内，宿主机可访问）

    t_start = time.time()
    for num in range(start_phase, end_phase + 1):
        label = ["", "Program Analysis", "Preprocess", "Execute Fuzz", "Issue Generator"][num]

        if num == 1:
            prompt = (
                f"Run the program-analysis skill on the project at {target}.\n"
                f"Save all output files to {work_dir}."
            )
            mcp = None
            skills_list = None

        elif num == 2:
            logger.info(">>> Phase 2: Connecting to AFL++ container...")
            container = verify_container()
            stop_existing_fuzz(container, target)

            # 把 Phase 1 的 4 个分析文件复制到容器内
            logger.info("[transfer] copying analysis files to container: %s", FUZZ_CONT)
            container.exec(f"mkdir -p {FUZZ_CONT}")
            for f in ["command_combinations.json", "call_tree.md",
                       "coverage_summary.md", "vulnerability_path_scores.md"]:
                src = str(Path(work_dir) / f)
                if Path(src).exists():
                    container.copy_to_container(src, FUZZ_CONT)
                    logger.info("  => %s", f)
                else:
                    logger.warning("  => %s (NOT FOUND)", f)

            container_target = f"/workspace/{project_name}"
            prompt = (
                f"Run the auto-fuzz skill on the project in the AFL++ container.\n"
                f"Project source (container): {container_target}\n"
                f"Fuzz output directory (container): {FUZZ_CONT}\n"
                f"Phase 1 analysis files are at {FUZZ_CONT}/.\n"
                f"IMPORTANT: Do builds (cmake, make) inside the project source dir {container_target}/.\n"
                f"Only fuzz output dirs (out_*), seeds, dictionaries, and fuzz_manifest.json go under {FUZZ_CONT}/.\n"
                f"Use container_exec for all compilation.\n"
                f"Do NOT create build scripts on the host.\n"
                f"After building and generating seeds + manifest:\n"
                f"  1. SAVE fuzz_manifest.json to both {FUZZ_CONT}/fuzz_manifest.json (container) AND to the current directory (host workdir)\n"
                f"  2. SAVE target_metadata.sh to both {FUZZ_CONT}/target_metadata.sh (container) AND to the current directory (host workdir)\n"
                f"Do NOT launch afl-fuzz — this phase only prepares the manifest.\n"
                f"ABSOLUTE RULE: Every afl-fuzz command in the manifest MUST use -m at most 4096 (never higher, never 'none'). "
                f"If fork server crashes with ASAN, add AFL_NO_FORKSRV=1 "
                f"and keep -m at 4096 or below."
            )
            mcp = {"container": create_container_server()}

        elif num == 3:
            logger.info(">>> Phase 3: Connecting to AFL++ container...")
            if container is None:
                container = verify_container()

            # Copy filtered manifest if it exists
            sel_path = Path(work_dir) / "fuzz_manifest_selected.json"
            if sel_path.exists():
                logger.info("[transfer] copying filtered manifest to container")
                container.exec(f"mkdir -p {FUZZ_CONT}")
                container.copy_to_container(str(sel_path), FUZZ_CONT)
                manifest_file = "fuzz_manifest_selected.json"
            else:
                manifest_file = "fuzz_manifest.json"

            prompt = (
                f"Run the auto-fuzz-exec skill.\n"
                f"Fuzz workspace (container): {FUZZ_CONT}\n"
                f"Use container_exec / container_exec_detached for all operations.\n"
                f"Source target_metadata.sh, read {manifest_file} (this is the user-selected manifest).\n"
                f"If it has strategies, launch ALL of them (batch_size = total count), "
                f"verify processes are stably running.\n"
                f"If it is empty (no strategies selected), do NOT launch anything from it.\n"
                f"If you later add new strategies to the manifest mid-execution, launch ONLY the newly added ones — "
                f"do not re-launch strategies that are already running.\n"
                f"Then:\n"
                f"  1. Touch {FUZZ_CONT}/fuzz_started.signal (in container)\n"
                f"  2. Also create fuzz_started.signal in the current directory (host workdir)\n"
                f"  3. Output [FUZZ_STARTED]"
            )

            # 追加用户提供的参考上下文（需 enabled 标志为 1）
            ctx_path = Path(work_dir) / "phase3_context.txt"
            flag_path = Path(work_dir) / "phase3_context_enabled"
            enabled = flag_path.exists() and flag_path.read_text(encoding="utf-8").strip() == "1"
            if ctx_path.exists() and enabled:
                ctx_text = ctx_path.read_text(encoding="utf-8").strip()
                if ctx_text:
                    prompt += (
                        f"\n\n=== User Reference Context ===\n"
                        f"The user provided the following reference. "
                        f"It may contain hints about what to prioritize, known vulnerability patterns, "
                        f"or previous crash analysis. Please consider it during fuzzing:\n"
                        f"{ctx_text}\n"
                        f"=== End of Reference Context ===\n"
                        f"Note: If you decide (based on your own analysis) to fuzz a command that "
                        f"is NOT in the manifest (fuzz_manifest.json), add it there, then also update "
                        f"the select file (fuzz_manifest_select.json) to include the new strategy's id."
                    )
                    logger.info("[phase3] loaded reference context (%d chars)", len(ctx_text))
            mcp = {"container": create_container_server()}

        else:  # num == 4
            logger.info(">>> Phase 4: Connecting to AFL++ container...")
            if container is None:
                container = verify_container()

            prompt = (
                f"Run the crash-reporter skill, then the issue-generator skill.\n"
                f"Fuzz workspace (container): {FUZZ_CONT}\n"
                f"Project source (container): /workspace/{project_name}\n"
                f"Host workdir: {work_dir}\n"
                f"Use container_exec for crash reproduction in the container.\n"
                f"Use Write/Read for all operations on the host.\n"
                f"Save SUMMARY.md to {work_dir}/reports/ on the host.\n"
                f"Save each unique crash's PoC and reproduce.sh to {work_dir}/crashes/<crash_type>/ on the host.\n"
                f"Save issue files to {work_dir}/issues/ on the host.\n"
                f"IMPORTANT: SUMMARY.md must be written in Chinese (中文). "
                f"Individual issue files must be in English."
            )
            mcp = {"container": create_container_server()}
            skills_list = ["crash-reporter", "issue-generator"]

        logger.info(">>> Starting Phase %s: %s", num, label)
        await run_phase(num, prompt, work_dir, mcp_servers=mcp, skills=skills_list)

        # Phase 1 结束后：确保项目源码在容器内
        if num == 1:
            logger.info("[transfer] ensuring project source in container...")
            try:
                c = verify_container()
                container_target = f"/workspace/{project_name}"
                # 检查源码是否已存在
                exists = c.exec(f"test -d {container_target} && ls {container_target}/CMakeLists.txt 2>/dev/null || true")
                if exists.strip():
                    logger.info("[transfer] project source already in container: %s", container_target)
                else:
                    logger.info("[transfer] copying project source to container: %s", container_target)
                    c.exec(f"mkdir -p {container_target}")
                    c.copy_to_container(str(Path(target)), str(Path(container_target).parent))
                    logger.info("[transfer] project source copied")
            except Exception as e:
                logger.warning("[transfer] failed to ensure project source in container: %s", e)

        # Phase 3 结束后：把 signal 和 crash 结果从容器复制回宿主机
        if num == 3:
            logger.info("[transfer] retrieving fuzz results from container...")
            try:
                c = verify_container()
                try:
                    c.copy_from_container(f"{FUZZ_CONT}/fuzz_started.signal", str(work_dir))
                    logger.info("[transfer] fuzz_started.signal retrieved")
                except Exception:
                    logger.warning("[transfer] fuzz_started.signal not found in container")
            except Exception as e:
                logger.warning("[transfer] failed to retrieve fuzz results: %s", e)

    total_elapsed = time.time() - t_start
    logger.info("")
    logger.info("=" * 60)
    logger.info("  Pipeline Complete! (total %.1fs)", total_elapsed)
    logger.info("=" * 60)
    logger.info("")
    logger.info("Artifacts:")
    logger.info("  %s/", work_dir)
    for art_name in ["command_combinations.json", "call_tree.md", "coverage_summary.md",
                      "vulnerability_path_scores.md", "fuzz_manifest.json", "issues/SUMMARY.md"]:
        log_artifact(str(Path(work_dir) / art_name))


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Vulnerability Discovery Pipeline (Claude Agent SDK)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", nargs="?", help="目标项目路径")
    parser.add_argument("--resume", action="store_true", help="从断点继续（自动检测已完成阶段）")
    parser.add_argument("--phase", type=int, choices=[1, 2, 3, 4], default=None, help="只运行指定阶段")
    parser.add_argument("--stop-fuzz", action="store_true", help="停止容器中所有 afl-fuzz 进程")
    parser.add_argument("--fuzz-timeout", type=int, default=DEFAULT_FUZZ_TIMEOUT,
                        help=f"Fuzz 超时秒数（默认 {DEFAULT_FUZZ_TIMEOUT}s = 24h，仅用于上下文）")

    args = parser.parse_args()

    # --stop-fuzz 不需要 target
    if args.stop_fuzz:
        setup_logging(str(BASE_DIR / "outputs"))
        logger.info("Stopping all afl-fuzz processes in container...")
        try:
            mgr = ContainerManager(container_name=CONTAINER_NAME)
            mgr.ensure_running()
            out = mgr.exec("ps aux | grep afl-fuzz | grep -v grep | awk '{print $2}' || true")
            if out.strip():
                pids = out.strip().split("\n")
                logger.info("Found %d afl-fuzz process(es): %s", len(pids), " ".join(p.strip() for p in pids))
                mgr.exec("kill -9 $(ps aux | grep afl-fuzz | grep -v grep | awk '{print $2}') 2>/dev/null || true")
                logger.info("All afl-fuzz processes stopped")
            else:
                logger.info("No afl-fuzz processes found")
        except ContainerError as e:
            logger.error("Failed: %s", e)
            sys.exit(1)
        return

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"[ERROR] 目标不存在: {args.target}")
        sys.exit(1)

    # 输出目录: BASE_DIR/outputs/<project_name>/  (宿主机仅存最终交付物)
    project_name = target_path.name
    work_dir = BASE_DIR / "outputs" / project_name

    # 初始化日志文件
    log_file = setup_logging(str(work_dir))
    print(f"\n  Target:   {args.target}")
    print(f"  Output:   {work_dir}")
    print(f"  Log:      {log_file}")
    print()

    logger.info("Pipeline started")
    logger.info("  target:   %s", args.target)
    logger.info("  output:   %s", work_dir)
    logger.info("  log:      %s", log_file)

    if args.resume:
        print_state(work_dir)
        start = detect_state(work_dir)
        if start == 5:
            logger.info("All phases complete! Nothing to do.")
            return
        logger.info("Resuming from Phase %s...", start)
    else:
        start = 1

    if args.phase is not None:
        anyio.run(run_pipeline, args.target, str(work_dir), args.phase, args.phase, args.fuzz_timeout)
        print_state(work_dir)
        logger.info("Pipeline finished")
        return

    anyio.run(run_pipeline, args.target, str(work_dir), 1, 4, args.fuzz_timeout)
    print_state(work_dir)
    logger.info("Pipeline finished")


if __name__ == "__main__":
    main()
