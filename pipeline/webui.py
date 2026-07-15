"""Auto-Fuzz Control Center — Web UI + Pipeline 启动/停止合为一体。"""

import json
import logging
import subprocess
import time
from pathlib import Path

import docker
from docker.errors import NotFound
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import uvicorn

STOP_SIGNAL = ".stop_signal"

logger = logging.getLogger(__name__)

app = FastAPI(title="Auto-Fuzz Control Center")

BASE_DIR = Path(__file__).resolve().parent.parent
CONTAINER_NAME = "afl"

_pipeline_proc: subprocess.Popen | None = None
_current_target: str | None = None
_docker_client: docker.DockerClient | None = None
_edge_history: dict[str, dict] = {}  # out_dir -> {"edges": int, "changed_at": float}
_STALE_THRESHOLD = 7200  # 2 hours in seconds
_killed_strategies: list[dict] = []
_easyfuzz_enabled: bool = False  # EasyFuzz toggle state  # 已终止的策略最终状态


def get_client() -> docker.DockerClient:
    global _docker_client
    if _docker_client is None:
        _docker_client = docker.from_env()
    return _docker_client


def get_container():
    try:
        return get_client().containers.get(CONTAINER_NAME)
    except NotFound:
        return None


def docker_exec(cmd: str | list[str]) -> str:
    c = get_container()
    if c is None:
        return ""
    if isinstance(cmd, str):
        cmd = ["sh", "-c", cmd]
    try:
        exit_code, output = c.exec_run(cmd)
        return output.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def get_afl_processes() -> list[dict]:
    raw = docker_exec("ps aux | grep afl-fuzz | grep -v grep || true")
    if not raw:
        return []
    procs = []
    for line in raw.split("\n"):
        if "<defunct>" in line:
            continue
        parts = line.split()
        if len(parts) < 11:
            continue
        procs.append({"pid": parts[1], "cpu": parts[2], "mem": parts[3], "cmd": " ".join(parts[10:])})
    return procs


def _afl_outdirs(procs: list[dict]) -> dict[str, dict]:
    """从 afl-fuzz 进程的 -o 参数提取输出目录（只解析 -- 之前的 afl-fuzz 参数）。"""
    out_map = {}
    for p in procs:
        cmd = p["cmd"]
        if not cmd.startswith("afl-fuzz"):
            continue
        # 只取 -- 之前的部分（-- 之后的是目标二进制参数）
        before_dd = cmd.split(" -- ", 1)[0]
        parts = before_dd.split()
        for i, part in enumerate(parts):
            if part == "-o" and i + 1 < len(parts):
                out = parts[i + 1].rstrip("/")
                if out.startswith("/"):
                    key = out
                else:
                    cwd = docker_exec(f"readlink -f /proc/{p['pid']}/cwd 2>/dev/null || true")
                    key = f"{cwd}/{out}" if cwd else out
                if key not in out_map:
                    out_map[key] = p
    return out_map


def _get_active_outdirs() -> set[str]:
    return set(_afl_outdirs(get_afl_processes()).keys())


def get_outdir_stats() -> list[dict]:
    """从 afl-fuzz 进程提取统计数据 + 进程信息。即使 fuzzer_stats 还未生成也返回基础信息。"""
    procs = get_afl_processes()
    if not procs:
        return []

    out_map = _afl_outdirs(procs)

    stats_list = []
    for out_dir, proc in sorted(out_map.items()):
        raw = docker_exec(f"cat $(find {out_dir} -name fuzzer_stats -type f 2>/dev/null | head -1) 2>/dev/null || true")
        info = {
            "name": Path(out_dir).name,
            "path": out_dir,
            "pid": proc["pid"],
            "full_cmd": proc["cmd"],
        }
        if raw:
            for line in raw.split("\n"):
                for key, alias in {"edge_found": "edges_found",
                                   "unique_crashes": "saved_crashes",
                                   "paths_total": "corpus_count",
                                   "exec_speed": "execs_per_sec",
                                   "run_time": "run_time",
                                   "cycles_done": "cycles_done",
                                   "stability": "stability",
                                   "bitmap_cvg": "bitmap_cvg"}.items():
                    if line.startswith(alias):
                        info[key] = line.split(":", 1)[-1].strip()
        stats_list.append(info)

    # 如果没有任何 -o 参数可解析，直接用进程信息兜底
    if not stats_list:
        for p in procs:
            stats_list.append({
                "name": f"pid_{p['pid']}",
                "path": "",
                "pid": p["pid"],
                "full_cmd": p["cmd"],
            })

    return stats_list


def list_projects() -> list[str]:
    """扫描工作目录下可用的目标项目。"""
    workspace = BASE_DIR.parent  # aflplusplus/
    projects = []
    for d in workspace.iterdir():
        if d.is_dir() and d.name not in ("auto_fuzz", "fuzz_pipeline", ".git", "__pycache__"):
            if (d / "CMakeLists.txt").exists() or (d / "configure").exists() or (d / "configure.ac").exists() or (d / "Makefile").exists() or (d / "Makefile.am").exists() or (d / "meson.build").exists():
                projects.append(d.name)
    return sorted(projects)


# ──────────────────────────────────────────────
# API
# ──────────────────────────────────────────────


@app.get("/api/status")
async def api_status(target: str = ""):
    global _edge_history, _killed_strategies
    procs = get_afl_processes()
    stats = get_outdir_stats()

    # 切换目标时重新加载已终止策略
    effective_target = target or _current_target
    if effective_target:
        _load_killed(effective_target)

    # 按唯一 out_dir 去重后的活跃策略数
    active_count = len(_afl_outdirs(procs))

    total_crashes = sum(int(s.get("unique_crashes", 0)) for s in stats)
    total_edges = sum(int(s.get("edge_found", 0)) for s in stats)

    # 检查每个策略的 edge 是否停滞
    now = time.time()
    stale_count = 0
    for s in stats:
        out_dir = s.get("path", "")
        cur_edges = int(s.get("edge_found", 0))
        prev = _edge_history.get(out_dir)
        if prev is None:
            _edge_history[out_dir] = {"edges": cur_edges, "changed_at": now}
            s["stale"] = False
        elif cur_edges != prev["edges"]:
            prev["edges"] = cur_edges
            prev["changed_at"] = now
            s["stale"] = False
        else:
            elapsed = now - prev["changed_at"]
            s["stale"] = elapsed > _STALE_THRESHOLD
        if s["stale"]:
            stale_count += 1

    # 清理已经不存在的 out_dir
    active_dirs = {s["path"] for s in stats}
    _edge_history = {k: v for k, v in _edge_history.items() if k in active_dirs}

    # 读取 manifest 中的策略总数（只读本地）
    total_strategies = 0
    effective_target = _current_target or target
    if effective_target:
        mp = BASE_DIR / "outputs" / effective_target / "fuzz_manifest.json"
        if mp.exists():
            try:
                md = json.loads(mp.read_text(encoding="utf-8"))
                total_strategies = len(md.get("strategies", []))
            except Exception:
                pass

    return {
        "running": len(procs) > 0,
        "process_count": active_count,
        "processes": procs,
        "strategies": stats,
        "killed": list(_killed_strategies),
        "total_strategies": total_strategies,
        "total_crashes": total_crashes,
        "total_edges": total_edges,
        "stale_count": stale_count,
        "pipeline_running": _pipeline_proc is not None and _pipeline_proc.poll() is None,
        "current_target": _current_target,
        "easyfuzz_enabled": _easyfuzz_enabled,
    }


# ──────────────────────────────────────────────
# EasyFuzz API
# ──────────────────────────────────────────────


@app.get("/api/easyfuzz/status")
async def api_easyfuzz_status():
    """返回 EasyFuzz toggle 状态。"""
    return {"enabled": _easyfuzz_enabled}


@app.post("/api/easyfuzz/toggle")
async def api_easyfuzz_toggle(enabled: bool = False):
    """设置 EasyFuzz toggle 状态。"""
    global _easyfuzz_enabled
    _easyfuzz_enabled = enabled
    logger.info("[easyfuzz] toggled to %s", enabled)
    return {"status": "ok", "enabled": enabled}


@app.get("/api/easyfuzz/commands")
async def api_easyfuzz_commands(target: str = ""):
    """读取项目的 easy_fuzz_commands.json。"""
    if not target:
        return {"commands": []}
    path = BASE_DIR / "outputs" / target / "easy_fuzz_commands.json"
    if not path.exists():
        return {"commands": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data
    except Exception as e:
        logger.warning("[easyfuzz] failed to read commands: %s", e)
        return {"commands": []}


@app.post("/api/easyfuzz/commands")
async def api_easyfuzz_save_commands(target: str = "", request: Request = None):
    """保存新的 easy_fuzz_commands.json。"""
    if not target:
        return {"error": "no target"}
    body = await request.json()
    path = BASE_DIR / "outputs" / target / "easy_fuzz_commands.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("[easyfuzz] commands saved for '%s' (%d commands)", target, len(body.get("commands", [])))
    return {"status": "saved", "target": target}


def clean_workspace(target: str) -> dict:
    """清空指定项目的工作目录（容器 + 本机）。"""
    project_name = Path(target).name
    host_dir = BASE_DIR / "outputs" / project_name
    cont_fuzz = f"/workspace/fuzz_{project_name}"
    cont_easy_fuzz = f"/workspace/easy_fuzz_{project_name}"
    cont_src = f"/workspace/{project_name}"

    # 1) 先干掉该项目所有的 afl-fuzz 进程
    logger.info("[clean] killing afl-fuzz for '%s'...", project_name)
    docker_exec(
        f"ps aux | grep afl-fuzz | grep '{project_name}' | grep -v grep "
        f"| awk '{{print $2}}' | xargs -r kill -9 2>/dev/null || true"
    )

    # 2) 清空容器内 fuzz workspace（正常模式 + EasyFuzz 模式）
    logger.info("[clean] removing container fuzz workspace: %s", cont_fuzz)
    docker_exec(f"rm -rf {cont_fuzz} 2>/dev/null || true")
    logger.info("[clean] removing container easy fuzz workspace: %s", cont_easy_fuzz)
    docker_exec(f"rm -rf {cont_easy_fuzz} 2>/dev/null || true")

    # 3) 清空容器内项目源码（Phase 1 复制过去的）
    logger.info("[clean] removing container project source: %s", cont_src)
    docker_exec(f"rm -rf {cont_src} 2>/dev/null || true")

    # 4) 清空本机 output 目录
    logger.info("[clean] removing host output dir: %s", host_dir)
    import shutil
    if host_dir.exists():
        shutil.rmtree(str(host_dir))
        logger.info("[clean] host output dir removed")
    else:
        logger.info("[clean] host output dir does not exist")

    return {"status": "cleaned", "target": project_name}



@app.post("/api/workspace/clean")
async def api_workspace_clean(target: str):
    """清空容器+本机的工作目录。"""
    if _pipeline_proc and _pipeline_proc.poll() is None:
        return {"error": "pipeline is running, stop it first"}
    result = clean_workspace(target)
    logger.info("[clean] workspace cleaned for '%s'", target)
    return result


@app.post("/api/phase/clean")
async def api_phase_clean(target: str, phase: int):
    """清空指定阶段的输出文件。"""
    if _pipeline_proc and _pipeline_proc.poll() is None:
        return {"error": "pipeline is running, stop it first"}
    project_name = Path(target).name
    host_dir = BASE_DIR / "outputs" / project_name
    import shutil

    if phase == 1:
        # Phase 1: 分析文件 + 种子 + 容器源码
        for f in ["analysis", "command_combinations.json", "call_tree.md", "coverage_summary.md", "vulnerability_path_scores.md"]:
            p = host_dir / f
            if p.is_dir(): shutil.rmtree(str(p))
            elif p.exists(): p.unlink()
        # 清理本地种子目录（在项目输出目录下 seeds_* 开头的目录）
        for p in list(host_dir.glob("seeds_*")):
            if p.is_dir():
                shutil.rmtree(str(p))
                logger.info("[clean] removed local seeds dir: %s", p.name)
        docker_exec(f"rm -rf /workspace/{project_name} 2>/dev/null || true")
        docker_exec(f"rm -rf /workspace/fuzz_{project_name}/seeds_prebuilt 2>/dev/null || true")
        return {"status": "cleaned", "phase": 1, "target": project_name}

    elif phase == 2:
        # Phase 2: 全部清理（manifest、种子、字典、metadata、构建产物）
        for pat in ["fuzz_manifest*", "target_metadata.sh", "seeds*", "*.dict", "fuzz_tool_list.md", "manifest_selfcheck.md"]:
            for p in host_dir.glob(pat):
                if p.is_dir(): shutil.rmtree(str(p))
                elif p.exists(): p.unlink()
        docker_exec(f"rm -rf /workspace/{project_name}/build* /workspace/fuzz_{project_name}/seeds* /workspace/fuzz_{project_name}/*.dict /workspace/fuzz_{project_name}/fuzz_manifest* /workspace/fuzz_{project_name}/target_metadata.sh /workspace/fuzz_{project_name}/fuzz_tool_list.md /workspace/fuzz_{project_name}/manifest_selfcheck.md /workspace/fuzz_{project_name}/command_combinations.json /workspace/fuzz_{project_name}/call_tree.md /workspace/fuzz_{project_name}/coverage_summary.md /workspace/fuzz_{project_name}/vulnerability_path_scores.md 2>/dev/null || true")
        return {"status": "cleaned", "phase": 2, "target": project_name}

    elif phase == 3:
        # Phase 3: 清理 fuzz 输出 + selected manifest，保留预处理产物
        docker_exec(
            f"ps aux | grep afl-fuzz | grep '{project_name}' | grep -v grep "
            f"| awk '{{print $2}}' | xargs -r kill -9 2>/dev/null || true"
        )
        docker_exec(f"rm -rf /workspace/fuzz_{project_name}/out_* 2>/dev/null || true")
        docker_exec(f"rm -f /workspace/fuzz_{project_name}/fuzz_started.signal 2>/dev/null || true")
        docker_exec(f"rm -f /workspace/fuzz_{project_name}/fuzz_manifest_selected.json 2>/dev/null || true")
        for f in ["killed_strategies.json", "fuzz_manifest_selected.json"]:
            p = host_dir / f
            if p.exists(): p.unlink()
        return {"status": "cleaned", "phase": 3, "target": project_name}

    elif phase == 4:
        # Phase 4: 崩溃报告 + issue 文件 + 容器内中间文件
        for f in ["crashes", "reports", "issues"]:
            p = host_dir / f
            if p.is_dir(): shutil.rmtree(str(p))
        docker_exec(f"rm -rf /workspace/fuzz_{project_name}/all_crashes /workspace/fuzz_{project_name}/crashes_dedup 2>/dev/null || true")
        return {"status": "cleaned", "phase": 4, "target": project_name}

    return {"error": f"invalid phase: {phase}"}


def _save_killed(target: str):
    """将当前 _killed_strategies 写入对应项目的文件。"""
    if not target:
        return
    path = BASE_DIR / "outputs" / target / "killed_strategies.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_killed_strategies, indent=2, ensure_ascii=False), encoding="utf-8")


def _load_killed(target: str):
    """从文件加载已终止的策略列表。"""
    global _killed_strategies
    path = BASE_DIR / "outputs" / target / "killed_strategies.json"
    if path.exists():
        try:
            _killed_strategies = json.loads(path.read_text(encoding="utf-8"))
            logger.info("[strategy] loaded %d killed strategies from %s", len(_killed_strategies), path)
        except Exception as e:
            logger.warning("[strategy] failed to load killed strategies: %s", e)
    else:
        _killed_strategies = []


@app.post("/api/strategy/kill")
async def api_strategy_kill(pid: int = 0, request: Request = None, target: str = ""):
    """终止指定的 afl-fuzz 进程，并保存最终状态。"""
    global _killed_strategies
    if pid <= 0:
        return {"error": "invalid pid"}
    # 先捕获当前状态
    body = await request.json() if request else {}
    entry = body.get("strategy", {})
    if entry:
        entry["killed_at"] = time.time()
        _killed_strategies.append(entry)
        _save_killed(target)
        logger.info("[strategy] saved final state for pid=%d name=%s", pid, entry.get("name", ""))
    # 再终止进程
    out = docker_exec(f"kill {pid} 2>/dev/null && echo ok || echo fail").strip()
    logger.info("[strategy] kill pid=%d -> %s", pid, out)
    if out == "ok":
        return {"status": "killed", "pid": pid}
    return {"error": f"kill failed: {out}"}


@app.get("/api/manifest")
async def api_manifest(target: str):
    """读取项目的 fuzz_manifest.json（策略列表）。优先本机，没有则从容器拉取。"""
    manifest_path = BASE_DIR / "outputs" / target / "fuzz_manifest.json"

    # 本机没有 → 从容器的 fuzz workspace 拉取
    if not manifest_path.exists():
        cont_path = f"/workspace/fuzz_{target}/fuzz_manifest.json"
        raw = docker_exec(f"cat {cont_path} 2>/dev/null || true")
        if raw:
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(raw, encoding="utf-8")
            logger.info("[manifest] pulled from container: %s", cont_path)

    if not manifest_path.exists():
        return {"strategies": []}
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        return data
    except Exception as e:
        logger.warning("[manifest] failed to read: %s", e)
        return {"strategies": []}


@app.post("/api/manifest/select")
async def api_manifest_select(target: str, strategy_ids: str = ""):
    """保存选中的策略 ID 列表到 fuzz_manifest_selected.json。"""
    manifest_path = BASE_DIR / "outputs" / target / "fuzz_manifest.json"
    if not manifest_path.exists():
        return {"error": "fuzz_manifest.json not found"}
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        ids = [i.strip() for i in strategy_ids.split(",") if i.strip()]
        selected = [s for s in data["strategies"] if s["id"] in ids]
        selected_data = {"batch_size": len(selected), "strategies": selected}
        sel_path = BASE_DIR / "outputs" / target / "fuzz_manifest_selected.json"
        sel_path.parent.mkdir(parents=True, exist_ok=True)
        sel_path.write_text(json.dumps(selected_data, indent=2), encoding="utf-8")
        logger.info("[manifest] selected %d/%d strategies -> %s", len(selected), len(data["strategies"]), sel_path)
        return {"status": "saved", "count": len(selected)}
    except Exception as e:
        logger.warning("[manifest] select failed: %s", e)
        return {"error": str(e)}


@app.post("/api/ref-context")
async def api_ref_context_save(target: str, request: Request):
    """保存 Phase 3 的参考上下文（用户输入的文本）。"""
    body = await request.json()
    text = body.get("text", "")
    enabled = body.get("enabled", True)
    ctx_dir = BASE_DIR / "outputs" / target
    ctx_dir.mkdir(parents=True, exist_ok=True)
    (ctx_dir / "phase3_context.txt").write_text(text, encoding="utf-8")
    (ctx_dir / "phase3_context_enabled").write_text("1" if enabled else "0", encoding="utf-8")
    logger.info("[ref-context] saved for '%s' (%d chars, enabled=%s)", target, len(text), enabled)
    return {"status": "saved", "chars": len(text), "enabled": enabled}


@app.get("/api/ref-context")
async def api_ref_context_get(target: str):
    """读取已保存的参考上下文。"""
    ctx_dir = BASE_DIR / "outputs" / target
    ctx_path = ctx_dir / "phase3_context.txt"
    flag_path = ctx_dir / "phase3_context_enabled"
    text = ctx_path.read_text(encoding="utf-8") if ctx_path.exists() else ""
    enabled = flag_path.read_text(encoding="utf-8").strip() == "1" if flag_path.exists() else True
    return {"text": text, "enabled": enabled}


@app.post("/api/pipeline/start")
async def api_pipeline_start(target: str, phase: int = 2, fuzz_timeout: int = 86400):
    """启动 pipeline（在后台子进程运行）。"""
    import sys
    global _pipeline_proc, _current_target
    if _pipeline_proc and _pipeline_proc.poll() is None:
        return {"error": "pipeline already running"}
    target_path = str(BASE_DIR.parent / target)
    cmd = [sys.executable or "python", "-m", "pipeline.orchestrator", target_path, "--phase", str(phase)]
    if _easyfuzz_enabled:
        cmd.append("--easyfuzz")
    if phase == 2:
        cmd.extend(["--fuzz-timeout", str(fuzz_timeout)])
    logger.info("[pipeline] starting: %s (cwd=%s)", " ".join(cmd), BASE_DIR)
    try:
        _pipeline_proc = subprocess.Popen(
            cmd,
            cwd=str(BASE_DIR),
        )
    except Exception as e:
        logger.error("[pipeline] failed to start: %s", e)
        return {"error": f"subprocess error: {e}"}
    _current_target = target
    return {"status": "started", "target": target, "phase": phase}


@app.post("/api/pipeline/stop")
async def api_pipeline_stop():
    """停止 pipeline 子进程 + 清理容器内 afl-fuzz。"""
    global _pipeline_proc, _current_target, _killed_strategies

    # 1) 收集所有 afl-fuzz 的最终状态，存入 killed_strategies
    stats = get_outdir_stats()
    for s in stats:
        entry = {
            "name": s.get("name", "?"),
            "pid": s.get("pid", "?"),
            "edges": s.get("edge_found", "0"),
            "crashes": s.get("unique_crashes", "0"),
            "paths": s.get("paths_total", "0"),
            "speed": s.get("exec_speed", "\u2014"),
            "cycles": s.get("cycles_done", "0"),
            "bitmap": s.get("bitmap_cvg", "\u2014"),
            "runtime": s.get("run_time", "\u2014"),
            "full_cmd": s.get("full_cmd", ""),
            "killed_at": time.time(),
            "killed_by": "stop_all",
        }
        _killed_strategies.append(entry)
    if stats and _current_target:
        _save_killed(_current_target)

    # 2) 发送停止信号（touch .stop_signal），让 orchestrator 优雅关闭
    if _current_target:
        stop_path = BASE_DIR / "outputs" / _current_target / STOP_SIGNAL
        stop_path.parent.mkdir(parents=True, exist_ok=True)
        stop_path.touch(exist_ok=True)
        logger.info("[stop] signal sent -> %s", stop_path)

    proc = _pipeline_proc
    if proc is None or proc.poll() is not None:
        # 进程已不在运行，仅清理 afl-fuzz
        docker_exec("kill -9 $(ps aux | grep afl-fuzz | grep -v grep | awk '{print $2}') 2>/dev/null || true")
        return {"status": "stopped", "total_crashes": 0}

    # 3) 等待进程优雅退出（orchestrator 收到信号后调用 client.disconnect() + 清理 afl-fuzz）
    try:
        proc.wait(timeout=15)
        logger.info("[stop] pipeline exited gracefully")
    except subprocess.TimeoutExpired:
        logger.warning("[stop] pipeline did not exit within 15s, killing...")
        proc.kill()

    _pipeline_proc = None
    _current_target = None

    # 4) 保险：清理容器内残留的 afl-fuzz
    docker_exec("kill -9 $(ps aux | grep afl-fuzz | grep -v grep | awk '{print $2}') 2>/dev/null || true")

    total_crashes = sum(int(s.get("unique_crashes", 0)) for s in stats)
    logger.info("[stop] done, total crashes: %s", total_crashes)
    return {"status": "stopped", "total_crashes": total_crashes}


@app.get("/api/summary")
async def api_summary(target: str = ""):
    """返回 reports/SUMMARY.md 内容。"""
    if not target:
        return {"error": "no target", "content": ""}
    path = BASE_DIR / "outputs" / target / "reports" / "SUMMARY.md"
    if not path.exists():
        return {"error": "not found", "content": ""}
    content = path.read_text(encoding="utf-8")
    return {"content": content}


@app.get("/api/projects")
async def api_projects():
    return {"projects": list_projects()}


@app.get("/api/log")
async def api_log(target: str = ""):
    log_dir = BASE_DIR / "outputs"
    if not log_dir.exists():
        return {"log": ""}
    if target:
        log_path = log_dir / target / "log"
    else:
        projs = sorted(log_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
        if not projs:
            return {"log": ""}
        log_path = projs[0] / "log"
    log_files = sorted(log_path.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True) if log_path.exists() else []
    if not log_files:
        return {"log": ""}
    with open(log_files[0], "r", encoding="utf-8", errors="replace") as f:
        return {"log": "".join(f.readlines()[-80:])}


# ──────────────────────────────────────────────
# Pages
# ──────────────────────────────────────────────

WEBUI_DIR = Path(__file__).parent / "ui"

def _load_webui() -> str:
    html = (WEBUI_DIR / "index.html").read_text(encoding="utf-8")
    css = (WEBUI_DIR / "style.css").read_text(encoding="utf-8")
    js = (WEBUI_DIR / "app.js").read_text(encoding="utf-8")
    return html.replace("<!--STYLE-->", f"<style>{css}</style>").replace("<!--SCRIPT-->", f"<script>{js}</script>")

INDEX_HTML = _load_webui()


@app.get("/", response_class=HTMLResponse)
async def index():
    return INDEX_HTML


def main(port: int = 8765):
    import sys
    if sys.stdout.encoding and sys.stdout.encoding.lower() in ("gbk", "gb2312", "gb18030"):
        globe = "[globe]"
    else:
        globe = "\U0001f310"
    print(f"  {globe} Auto-Fuzz Control Center: http://localhost:{port}")
    print(f"  Select a target and press Start")
    print(f"  Ctrl+C to quit\n")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
