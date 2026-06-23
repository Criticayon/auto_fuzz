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
_killed_strategies: list[dict] = []  # 已终止的策略最终状态


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
        raw = docker_exec(f"cat {out_dir}/fuzzer_stats 2>/dev/null || cat {out_dir}/default/fuzzer_stats 2>/dev/null || true")
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
            if (d / "CMakeLists.txt").exists() or (d / "configure").exists() or (d / "Makefile").exists() or (d / "meson.build").exists():
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
    effective_target = _current_target or target
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
    }


def clean_workspace(target: str) -> dict:
    """清空指定项目的工作目录（容器 + 本机）。"""
    project_name = Path(target).name
    host_dir = BASE_DIR / "outputs" / project_name
    cont_fuzz = f"/workspace/fuzz_{project_name}"
    cont_src = f"/workspace/{project_name}"

    # 1) 先干掉该项目所有的 afl-fuzz 进程
    logger.info("[clean] killing afl-fuzz for '%s'...", project_name)
    docker_exec(
        f"ps aux | grep afl-fuzz | grep '{project_name}' | grep -v grep "
        f"| awk '{{print $2}}' | xargs -r kill -9 2>/dev/null || true"
    )

    # 2) 清空容器内 fuzz workspace
    logger.info("[clean] removing container fuzz workspace: %s", cont_fuzz)
    docker_exec(f"rm -rf {cont_fuzz} 2>/dev/null || true")

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
        ids = [int(i) for i in strategy_ids.split(",") if i.strip()]
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
    global _pipeline_proc, _current_target
    if _pipeline_proc and _pipeline_proc.poll() is None:
        return {"error": "pipeline already running"}
    target_path = str(BASE_DIR.parent / target)
    cmd = ["python", "-m", "pipeline.orchestrator", target_path, "--phase", str(phase)]
    if phase == 2:
        cmd.extend(["--fuzz-timeout", str(fuzz_timeout)])
    _pipeline_proc = subprocess.Popen(
        cmd,
        cwd=str(BASE_DIR),
    )
    _current_target = target
    return {"status": "started", "target": target, "phase": phase}


@app.post("/api/pipeline/stop")
async def api_pipeline_stop():
    """停止 pipeline 子进程 + 清理容器内 afl-fuzz。"""
    global _pipeline_proc, _current_target

    # 1) 发送停止信号（touch .stop_signal），让 orchestrator 优雅关闭
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

    # 2) 等待进程优雅退出（orchestrator 收到信号后调用 client.disconnect() + 清理 afl-fuzz）
    try:
        proc.wait(timeout=15)
        logger.info("[stop] pipeline exited gracefully")
    except subprocess.TimeoutExpired:
        logger.warning("[stop] pipeline did not exit within 15s, killing...")
        proc.kill()

    _pipeline_proc = None
    _current_target = None

    # 3) 保险：清理容器内残留的 afl-fuzz
    docker_exec("kill -9 $(ps aux | grep afl-fuzz | grep -v grep | awk '{print $2}') 2>/dev/null || true")

    stats = get_outdir_stats()
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
async def api_log():
    log_dir = BASE_DIR / "outputs"
    if not log_dir.exists():
        return {"log": ""}
    projs = sorted(log_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    if not projs:
        return {"log": ""}
    log_files = sorted((projs[0] / "log").glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True) if (projs[0] / "log").exists() else []
    if not log_files:
        return {"log": ""}
    with open(log_files[0], "r", encoding="utf-8", errors="replace") as f:
        return {"log": "".join(f.readlines()[-80:])}


# ──────────────────────────────────────────────
# Pages
# ──────────────────────────────────────────────

INDEX_HTML = """\
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Auto-Fuzz Control Center</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Rajdhani:wght@500;600;700&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; background: #fef7e8; color: #24292f; min-height: 100vh; }
  .header { background: linear-gradient(180deg, #d4a373 0%, #b88352 40%, #9c6b3e 100%); border-bottom: none; box-shadow: 0 3px 12px rgba(0,0,0,0.12); padding: 20px 32px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; position: relative; }
  .header-left { display: flex; flex-direction: column; gap: 2px; }
  .header-brand { display: flex; align-items: center; gap: 14px; }
  .header-icon { font-size: 30px; line-height: 1; filter: drop-shadow(0 2px 3px rgba(0,0,0,0.1)); }
  .header h1 { font-family: 'Orbitron', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 24px; font-weight: 700; letter-spacing: 1px; color: #fff; text-shadow: 0 1px 3px rgba(0,0,0,0.25); }
  .header h1 .highlight { font-weight: 900; }
  .header .subtitle { font-size: 12px; color: rgba(255,255,255,0.75); letter-spacing: 2.5px; text-transform: uppercase; margin-left: 44px; position: relative; }
  .header .subtitle::before, .header .subtitle::after { content: '✦'; margin: 0 6px; color: rgba(255,255,255,0.5); font-size: 9px; }
  .header #globalStatus .badge { border-color: rgba(255,255,255,0.3); }
  .paper-clip { position: absolute; bottom: -20px; left: 50%; transform: translateX(-50%); font-size: 34px; line-height: 1; z-index: 10; filter: drop-shadow(0 2px 4px rgba(0,0,0,0.25)); pointer-events: none; }
  .container { max-width: 1400px; margin: 28px auto; padding: 28px 32px; background: #ffffff; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05), 0 6px 24px rgba(0,0,0,0.06); position: relative; z-index: 1; }
  .controls { background: #ffffff; border: 1px solid #d0d7de; border-radius: 8px; padding: 20px; margin-bottom: 24px; display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }
  .controls select, .controls button { padding: 8px 16px; border-radius: 6px; font-size: 14px; border: 1px solid #d0d7de; background: #f6f8fa; color: #24292f; }
  .controls button { font-weight: 600; cursor: pointer; transition: all 0.2s; border: none; }
  .btn-primary { background: #0969da; color: #fff; }
  .btn-primary:hover { background: #0550ae; }
  .btn-danger { background: #cf222e; color: #fff; }
  .btn-danger:hover { background: #a40e26; }
  .btn-secondary { background: #f6f8fa; color: #24292f; border: 1px solid #d0d7de; }
  .btn-secondary:hover { background: #eaeef2; }
  button:disabled { opacity: .5; cursor: not-allowed; }
  .stale-icon { display: inline-block; margin-left: 6px; color: #d4940c; cursor: help; font-size: 14px; position: relative; }
  .stale-icon:hover .stale-tip { visibility: visible; opacity: 1; }
  .kill-btn { padding: 2px 10px; font-size: 11px; border-radius: 4px; border: 1px solid #d0d7de; cursor: pointer; background: #fff; color: #cf222e; transition: .15s; }
  .kill-btn:hover { background: #cf222e; color: #fff; border-color: #cf222e; }
  .kill-btn:disabled { opacity: .4; cursor: not-allowed; }
  .stale-tip { visibility: hidden; opacity: 0; position: absolute; bottom: calc(100% + 6px); left: 50%; transform: translateX(-50%); background: #24292f; color: #fff; font-size: 11px; padding: 5px 10px; border-radius: 6px; white-space: nowrap; transition: opacity .15s; z-index: 10; }
  .stale-tip::after { content: ''; position: absolute; top: 100%; left: 50%; transform: translateX(-50%); border: 5px solid transparent; border-top-color: #24292f; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: #ffffff; border: 1px solid #d0d7de; border-radius: 8px; padding: 20px; }
  .card .label { font-size: 12px; text-transform: uppercase; color: #656d76; letter-spacing: .5px; margin-bottom: 8px; }
  .card .value { font-size: 28px; font-weight: 700; color: #1f2328; }
  .card .value.green { color: #1a7f37; }
  .card .value.red { color: #cf222e; }
  .card .value.blue { color: #0969da; }
  .card .value.orange { color: #9a6700; }
  .section-title { font-family: 'Rajdhani', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 19px; font-weight: 700; margin: 24px 0 14px; color: #1f2328; letter-spacing: 0.3px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; background: #ffffff; border: 1px solid #d0d7de; border-radius: 8px; overflow: hidden; margin-bottom: 24px; }
  th { text-align: left; padding: 10px 14px; background: #f6f8fa; color: #656d76; font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; border-bottom: 1px solid #d0d7de; }
  td { padding: 10px 14px; border-bottom: 1px solid #eaeef2; color: #24292f; }
  tr:hover td { background: #f6f8fa; }
  .crashes { color: #cf222e; font-weight: 600; }
  .edges { color: #0969da; }
  .speed { color: #9a6700; }
  .log-box { background: #ffffff; border: 1px solid #d0d7de; border-radius: 8px; padding: 16px; font-size: 12px; line-height: 1.6; max-height: 400px; overflow-y: auto; font-family: 'Cascadia Code','JetBrains Mono',monospace; white-space: pre-wrap; color: #656d76; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-green { background: #dafbe1; color: #1a7f37; }
  .badge-red { background: #ffebe9; color: #cf222e; }
  .badge-yellow { background: #fff8c5; color: #9a6700; }
  .status-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
  .status-dot.green { background: #1a7f37; box-shadow: 0 0 8px #1a7f3788; }
  .status-dot.red { background: #cf222e; box-shadow: 0 0 8px #cf222e88; }
  .status-dot.gray { background: #656d76; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  .pulsing { animation: pulse 1.5s ease-in-out infinite; }
  .footer { text-align: center; padding: 24px; color: #8b949e; font-size: 12px; }
  .tag { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; background: #f6f8fa; color: #656d76; margin-left: 8px; }
  .tooltip-wrap { position: relative; display: inline-block; }
  .tooltip-wrap .tooltip-text { visibility: hidden; opacity: 0; position: absolute; bottom: calc(100% + 8px); left: 50%; transform: translateX(-50%); background: #1f2328; color: #fff; padding: 6px 12px; border-radius: 6px; font-size: 12px; white-space: nowrap; z-index: 100; transition: opacity 0.15s ease; pointer-events: none; }
  .tooltip-wrap .tooltip-text::after { content: ''; position: absolute; top: 100%; left: 50%; transform: translateX(-50%); border: 6px solid transparent; border-top-color: #1f2328; }
  .tooltip-wrap:hover .tooltip-text { visibility: visible; opacity: 1; }
  .ref-toggle { font-size: 15px; font-weight: 700; color: #0969da; cursor: pointer; user-select: none; padding: 4px 0; }
  .ref-toggle:hover { color: #0550ae; }
  .ref-btn { padding: 5px 14px; font-size: 12px; border-radius: 6px; border: 1px solid; cursor: pointer; font-weight: 500; line-height: 1.4; transition: .2s; }
  .ref-btn-upload { background: #f6f8fa; border-color: #d0d7de; color: #24292f; }
  .ref-btn-upload:hover { background: #eaeef2; }
  .ref-btn-primary { background: #0969da; border-color: #0969da; color: #fff; }
  .ref-btn-primary:hover { background: #0550ae; border-color: #0550ae; }
  .ref-btn-default { background: #f6f8fa; border-color: #d0d7de; color: #656d76; }
  .ref-btn-default:hover { background: #eaeef2; color: #24292f; }
  .ref-panel { background: #ffffff; border: 1px solid #d0d7de; border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; }
  .ref-panel textarea { width: 100%; min-height: 80px; border: 1px solid #d0d7de; border-radius: 6px; padding: 8px 10px; font-size: 13px; font-family: inherit; resize: vertical; }
  .ref-panel textarea:focus { outline: none; border-color: #0969da; box-shadow: 0 0 0 2px #0969da22; }
  .project-bar { background: #ffffff; border: 1px solid #d0d7de; border-radius: 8px; padding: 12px 20px; margin-bottom: 16px; display: flex; align-items: center; gap: 16px; }
  .project-bar .proj-name { font-size: 16px; font-weight: 600; color: #1f2328; }
  .project-bar .proj-label { font-size: 12px; color: #656d76; text-transform: uppercase; letter-spacing: .5px; }
  .project-bar .spacer { flex: 1; }
  .activity-bar { height: 3px; border-radius: 2px; background: #d0d7de; overflow: hidden; flex: 0 0 200px; }
  .activity-bar .fill { height: 100%; width: 0%; background: linear-gradient(90deg, #0969da, #1a7f37); border-radius: 2px; transition: width 1s ease; }
  .activity-bar .fill.active { animation: barPulse 2s ease-in-out infinite; }
  @keyframes barPulse { 0%,100%{ opacity: 1; width: 30%; } 50%{ opacity: .6; width: 100%; } }
  .strategy-row { cursor: pointer; }
  .strategy-row:hover td { background: #eaeef2; }
  .arrow { display: inline-block; transition: transform 0.2s ease; }
  .arrow.open { transform: rotate(90deg); }
  .cmd-detail { background: #f6f8fa; }
  .cmd-detail td { padding: 0 !important; }
  .cmd-detail pre { margin: 0; padding: 10px 14px; font-size: 12px; color: #24292f; white-space: pre-wrap; word-break: break-all; font-family: 'Cascadia Code','JetBrains Mono','Fira Code',Consolas,monospace; line-height: 1.5; max-height: 160px; overflow-y: auto; }
  .summary-box { background: #ffffff; border: 1px solid #d0d7de; border-radius: 8px; padding: 24px 32px; margin-bottom: 16px; font-size: 14px; line-height: 1.7; color: #24292f; overflow-y: auto; }
  .summary-box h1 { font-size: 22px; margin: 24px 0 12px; padding-bottom: 8px; border-bottom: 1px solid #d0d7de; font-weight: 600; }
  .summary-box h2 { font-size: 18px; margin: 20px 0 10px; padding-bottom: 6px; border-bottom: 1px solid #eaeef2; font-weight: 600; }
  .summary-box h3 { font-size: 15px; margin: 16px 0 8px; font-weight: 600; }
  .summary-box hr { border: none; border-top: 1px solid #d0d7de; margin: 20px 0; }
  .summary-box p { margin: 8px 0; }
  .summary-box table { border-collapse: collapse; margin: 12px 0; font-size: 13px; width: auto; min-width: 50%; }
  .summary-box table th { background: #f6f8fa; font-weight: 600; }
  .summary-box table td, .summary-box table th { border: 1px solid #d0d7de; padding: 6px 12px; text-align: left; }
  .summary-box tr:nth-child(even) { background: #fafbfc; }
  .summary-box pre { background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; padding: 12px 16px; font-size: 12px; overflow-x: auto; line-height: 1.5; font-family: 'Cascadia Code','JetBrains Mono','Fira Code',Consolas,monospace; }
  .summary-box code { background: #eaeef2; padding: 2px 5px; border-radius: 3px; font-size: 13px; font-family: 'Cascadia Code','JetBrains Mono','Fira Code',Consolas,monospace; }
  .summary-box pre code { background: none; padding: 0; border-radius: 0; font-size: 12px; }
  .summary-box ul, .summary-box ol { padding-left: 24px; margin: 8px 0; }
  .summary-box li { margin: 4px 0; }
  .summary-box strong { font-weight: 600; }
  .summary-box em { font-style: italic; }
  .summary-mode #strategyPanel,
  .summary-mode #projectBar,
  .summary-mode #statsGrid,
  .summary-mode .section-title:not(#summaryTitle),
  .summary-mode table:not(#summaryBox table),
  .summary-mode #killedTitle,
  .summary-mode #killedTable,
  .summary-mode #logBox,
  .summary-mode .log-box { display: none !important; }
  .summary-mode .summary-box { display: block !important; max-height: none; }
  .summary-mode #summaryWrapper { display: block !important; }
  @keyframes summaryFadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
  .summary-mode #summaryWrapper { animation: summaryFadeIn 0.35s ease-out; }
  #summaryWrapper { display: none; }
  .summary-header { display: flex; align-items: center; gap: 12px; padding: 20px 28px 16px; border-bottom: 2px solid #d0d7de; }
  .summary-header .icon { width: 36px; height: 36px; background: linear-gradient(135deg, #0969da, #1a7f37); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; color: #fff; flex-shrink: 0; }
  .summary-header .info { flex: 1; }
  .summary-header .info .title { font-size: 18px; font-weight: 700; color: #24292f; }
  .summary-header .info .sub { font-size: 13px; color: #656d76; margin-top: 2px; }
  .summary-header .badge { font-size: 12px; background: #ddf4ff; color: #0969da; padding: 4px 10px; border-radius: 20px; font-weight: 500; white-space: nowrap; }
  .loading-skeleton { padding: 20px 0; }
  .loading-skeleton .bar { background: linear-gradient(90deg, #eaeef2 25%, #f6f8fa 50%, #eaeef2 75%); background-size: 200% 100%; animation: shimmer 1.5s infinite; border-radius: 4px; }
  @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
  .summary-mode #btnPhase5 { background: #cf222e; color: #fff; border-color: #cf222e; }
  /* ── Code burst particles ── */
  .code-burst { position: fixed; pointer-events: none; z-index: 9999; font-family: 'Cascadia Code','JetBrains Mono','Fira Code',Consolas,monospace; font-weight: 700; user-select: none; will-change: transform, opacity; animation: codeFloat 1.2s ease-out forwards; }
  @keyframes codeFloat { 0% { opacity: 1; transform: translate(0,0) rotate(0deg) scale(1); } 100% { opacity: 0; transform: translate(var(--dx),var(--dy)) rotate(var(--r)) scale(0.3); } }
</style>
</head>
<body>
<div class="header">
  <div class="paper-clip">&#128206;</div>
  <div class="header-left">
    <div class="header-brand">
      <span class="header-icon">&#128027;</span>
      <h1>Auto-Fuzz <span class="highlight">Control Center</span></h1>
    </div>
    <div class="subtitle">Vulnerability Discovery Pipeline</div>
  </div>
  <div id="globalStatus"><span class="badge badge-yellow">Starting...</span></div>
</div>

<div class="container">

  <div class="section-title" style="margin-top:0;">Pipeline</div>
  <div class="controls">
    <select id="targetSelect" style="min-width:160px;">
      <option value="">-- Select target --</option>
    </select>
    <button class="btn-primary" id="btnPhase1" onclick="startPipeline(1)">Phase 1: Analyze</button>
    <button class="btn-primary" id="btnPhase2" onclick="startPipeline(2)">Phase 2: Prep</button>
    <div class="tooltip-wrap"><button class="btn-primary" id="btnPhase3" onclick="startPipeline(3)">Phase 3: Fuzz</button><span class="tooltip-text">追加新策略到当前正在跑的 fuzz 进程中</span></div>
    <button class="btn-primary" id="btnPhase4" onclick="startPipeline(4)">Phase 4: Issues</button>
    <button class="btn-secondary" id="btnPhase5" onclick="showSummary()">Phase 5: Summary</button>
    <button class="btn-secondary" id="btnClean" onclick="cleanWorkspace()" style="border-color:#cf222e;color:#cf222e;">Clean</button>
    <span id="pipelineStatus" style="font-size:13px;color:#656d76;margin-left:8px;"></span>
  </div>

  <div id="strategyPanel" style="display:none; background:#ffffff; border:1px solid #d0d7de; border-radius:8px; padding:16px 20px; margin-bottom:16px;">
    <div style="display:flex; align-items:center; gap:12px; margin-bottom:12px;">
      <span class="section-title" style="margin:0;">Strategies</span>
      <span style="font-size:12px;color:#656d76;" id="strategyCount"></span>
      <span class="spacer" style="flex:1;"></span>
      <button onclick="loadManifest()" style="font-size:12px;padding:4px 10px;border:1px solid #d0d7de;border-radius:4px;background:#f6f8fa;color:#656d76;cursor:pointer;">Refresh</button>
      <button class="kill-btn" id="btnStopAll" onclick="stopAllStrategies()" style="display:none;">Stop All</button>
      <label style="font-size:13px;color:#656d76;cursor:pointer;">
        <input type="checkbox" id="selectAllStrategies" checked onchange="toggleAllStrategies()"> Select All
      </label>
    </div>
    <div id="strategyList" style="display:flex; flex-direction:column; gap:6px;"></div>
    <div style="margin-top:12px; padding-top:12px; border-top:1px solid #d0d7de;">
      <div class="ref-toggle" onclick="toggleRefPanel()"><span class="arrow" id="refArrow">▶</span> Reference Context <label style="font-size:13px;font-weight:400;color:#656d76;cursor:pointer;margin-left:8px;user-select:none;" onclick="event.stopPropagation()"><input type="checkbox" id="refEnabled" checked> Enable</label></div>
      <div class="ref-panel" id="refPanel" style="display:none; margin-bottom:0;">
        <textarea id="refTextInput" placeholder="输入参考信息供 fuzz agent 参考（如已知漏洞模式、需要重点测试的路径等）" spellcheck="false"></textarea>
        <div style="display:flex; gap:6px; align-items:center; margin-top:8px; flex-wrap:wrap;">
          <label class="ref-btn ref-btn-upload">Upload .md<input type="file" id="refFileInput" accept=".md" style="display:none;" onchange="onRefFileSelect(event)"></label>
          <button class="ref-btn ref-btn-primary" onclick="saveRefContext()">Save</button>
          <button class="ref-btn ref-btn-default" onclick="clearRefContext()">Clear</button>
          <span id="refSaved" style="font-size:12px;color:#1a7f37;display:none;">✓ Saved</span>
          <span id="refFileName" style="font-size:12px;color:#656d76;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"></span>
        </div>
      </div>
    </div>
  </div>

  <div class="project-bar" id="projectBar" style="display:none;">
    <div><span class="proj-label">Testing</span><div class="proj-name" id="currentProject">—</div></div>
    <div class="activity-bar"><div class="fill" id="activityFill"></div></div>
    <span id="activityLabel" style="font-size:12px;color:#656d76;min-width:100px;">Idle</span>
    <div class="spacer"></div>
  </div>

  <div class="section-title" style="margin-bottom:12px;">Overview</div>
  <div class="grid" id="statsGrid">
    <div class="card"><div class="label">Total Strategies</div><div class="value blue" id="stratCount">—</div></div>
    <div class="card"><div class="label">Active Processes</div><div class="value blue" id="procCount">—</div></div>
    <div class="card"><div class="label">Edges Found</div><div class="value green" id="totalEdges">—</div></div>
    <div class="card"><div class="label">Crashes</div><div class="value red" id="totalCrashes">—</div></div>
    <div class="card"><div class="label">Stale (2h+)</div><div class="value" id="staleCount" style="color:#d4940c;">—</div></div>
  </div>

  <div class="section-title">Strategies</div>
  <table>
    <thead><tr><th></th><th>Name</th><th>PID</th><th>Edges</th><th>Crashes</th><th>Paths</th><th>Speed</th><th>Cycles</th><th>Bitmap</th><th>Runtime</th><th></th></tr></thead>
    <tbody id="strategiesBody"><tr><td colspan="11" style="text-align:center;color:#8b949e;">Waiting...</td></tr></tbody>
  </table>

  <div class="section-title" id="killedTitle" style="display:none;">Stopped Strategies</div>
  <table id="killedTable" style="display:none;">
    <thead><tr><th>Name</th><th>PID</th><th>Edges</th><th>Crashes</th><th>Paths</th><th>Speed</th><th>Cycles</th><th>Bitmap</th><th>Runtime</th></tr></thead>
    <tbody id="killedBody"></tbody>
  </table>

  <div id="summaryWrapper">
    <div class="card" style="padding:0;">
      <div class="summary-header">
        <div class="icon">&#128269;</div>
        <div class="info">
          <div class="title">Campaign Summary</div>
          <div class="sub" id="summaryTarget"></div>
        </div>
        <span class="badge">Phase 5</span>
      </div>
      <div class="summary-box" id="summaryBox"></div>
    </div>
  </div>

  <div class="section-title">Log</div>
  <div class="log-box" id="logBox">(waiting for data...)</div>
</div>

<div class="footer">Auto-Fuzz Control Center · auto-refresh 5s</div>

<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script>
let polling = true;
let logAtBottom = true;

async function api(url, opts) {
  try { return await (await fetch(url, opts || {})).json(); }
  catch { return null; }
}

function updateDashboard() {
  const target = document.getElementById('targetSelect').value;
  api('/api/status' + (target ? `?target=${encodeURIComponent(target)}` : '')).then(d => {
    if (!d) return;
    document.getElementById('stratCount').textContent = d.total_strategies || '\u2014';
    document.getElementById('procCount').textContent = d.process_count;
    document.getElementById('totalEdges').textContent = (d.total_edges||0).toLocaleString();
    document.getElementById('totalCrashes').textContent = (d.total_crashes||0).toLocaleString();
    document.getElementById('staleCount').textContent = d.stale_count || 0;

    const running = d.pipeline_running || d.running;
    const gs = document.getElementById('globalStatus');
    if (d.pipeline_running) {
      gs.innerHTML = '<span class="badge badge-green"><span class="status-dot green pulsing"></span>Pipeline Running</span>';
    } else if (d.running) {
      gs.innerHTML = '<span class="badge badge-green"><span class="status-dot green pulsing"></span>AFL++ Running</span>';
    } else {
      gs.innerHTML = '<span class="badge badge-red"><span class="status-dot gray"></span>Idle</span>';
    }

    // 按钮状态
    const noTarget = !document.getElementById('targetSelect').value;
    document.getElementById('btnPhase1').disabled = running || noTarget;
    document.getElementById('btnPhase2').disabled = running || noTarget;
    document.getElementById('btnPhase3').disabled = d.pipeline_running || noTarget;
    document.getElementById('btnPhase4').disabled = running || noTarget;
    document.getElementById('btnPhase5').disabled = noTarget;
    document.getElementById('btnClean').disabled = running || noTarget;
    // Stop All 按钮：有正在跑的进程才显示
    document.getElementById('btnStopAll').style.display = d.running ? 'inline-block' : 'none';
    // 没选项目或没有 afl-fuzz 在跑时隐藏追加提示
    const tt = document.querySelector('.tooltip-wrap .tooltip-text');
    if (tt) tt.style.display = (noTarget || !d.running) ? 'none' : '';

    // 项目显示 + 动画条
    const pBar = document.getElementById('projectBar');
    const pName = document.getElementById('currentProject');
    const aFill = document.getElementById('activityFill');
    const aLabel = document.getElementById('activityLabel');
    if (d.current_target) {
      pBar.style.display = 'flex';
      pName.textContent = d.current_target;
      if (running) {
        aFill.className = 'fill active';
        aLabel.textContent = d.pipeline_running ? 'Pipeline Running...' : 'Fuzzing...';
      } else {
        aFill.className = 'fill';
        aFill.style.width = d.running ? '60%' : '0%';
        aLabel.textContent = d.running ? 'Fuzzing' : 'Idle';
      }
    } else {
      pBar.style.display = 'none';
    }

    // 策略表格（含展开命令）
    const sBody = document.getElementById('strategiesBody');
    if (d.strategies && d.strategies.length) {
      sBody.innerHTML = d.strategies.map((s, idx) => {
        const rt = s.run_time ? (t=>{const h=Math.floor(t/3600),m=Math.floor((t%3600)/60);return h?h+'h '+m+'m':m?m+'m':t+'s'})(parseInt(s.run_time)) : '\u2014';
        const expanded = window._expandedRows || new Set();
        const showCmd = expanded.has(idx);
        const cmdRow = s.full_cmd ? `<tr class="cmd-detail" id="cmd_${idx}" style="${showCmd?'':'display:none;'}"><td colspan="11"><pre>${s.full_cmd}</pre></td></tr>` : '';
        const staleHtml = s.stale ? '<span class="stale-icon">\u26a0<span class="stale-tip">Edges unchanged for 2+ hours</span></span>' : '';
        return `<tr class="strategy-row" onclick="toggleCmd(${idx})"><td><span class="arrow ${showCmd?'open':''}" id="arrow_${idx}">\u25b6</span></td><td><strong>${s.name}</strong>${staleHtml}</td><td class="pid-cell">${s.pid||'\u2014'}</td><td class="edges">${s.edge_found||0}</td><td class="crashes">${s.unique_crashes||0}</td><td>${s.paths_total||0}</td><td class="speed">${s.exec_speed||'\u2014'}${s.exec_speed?'/s':''}</td><td>${s.cycles_done||0}</td><td>${s.bitmap_cvg||'\u2014'}</td><td>${rt}</td><td><button class="kill-btn" onclick="event.stopPropagation();killStrategy(${s.pid})" ${s.pid?'':'disabled'}>Stop</button></td></tr>${cmdRow}`;
      }).join('');
    } else {
      sBody.innerHTML = '<tr><td colspan="11" style="text-align:center;color:#8b949e;">No active strategies</td></tr>';
    }

    // 已终止策略表格（仅选了项目才显示）
    const killedTitle = document.getElementById('killedTitle');
    const killedTable = document.getElementById('killedTable');
    const killedBody = document.getElementById('killedBody');
    const hasTarget = !!document.getElementById('targetSelect').value;
    if (hasTarget && d.killed && d.killed.length) {
      killedTitle.style.display = 'block';
      killedTable.style.display = 'table';
      killedBody.innerHTML = d.killed.map(function(k) {
        return '<tr><td><strong>' + (k.name||'?') + '</strong></td><td>' + (k.pid||'\u2014') + '</td><td>' + (k.edges||'0') + '</td><td>' + (k.crashes||'0') + '</td><td>' + (k.paths||'0') + '</td><td>' + (k.speed||'\u2014') + '</td><td>' + (k.cycles||'0') + '</td><td>' + (k.bitmap||'\u2014') + '</td><td>' + (k.runtime||'\u2014') + '</td></tr>';
      }).join('');
    } else {
      killedTitle.style.display = 'none';
      killedTable.style.display = 'none';
    }
  });

  api('/api/log').then(d => {
    if (d && d.log) {
      const box = document.getElementById('logBox');
      const wasAtBottom = logAtBottom;
      box.textContent = d.log;
      if (wasAtBottom) {
        box.scrollTop = box.scrollHeight;
      }
    }
  });
}

function toggleCmd(idx) {
  const row = document.getElementById('cmd_' + idx);
  const arrow = document.getElementById('arrow_' + idx);
  if (row) {
    const show = row.style.display !== 'table-row';
    row.style.display = show ? 'table-row' : 'none';
    if (arrow) arrow.className = 'arrow' + (show ? ' open' : '');
    // 保存展开状态，刷新后恢复
    if (!window._expandedRows) window._expandedRows = new Set();
    if (show) window._expandedRows.add(idx);
    else window._expandedRows.delete(idx);
  }
}

async function showSummary() {
  const target = document.getElementById('targetSelect').value;
  if (!target) return;
  const isActive = document.body.classList.contains('summary-mode');
  if (isActive) {
    // 退出 summary 模式
    document.body.classList.remove('summary-mode');
    document.getElementById('btnPhase5').textContent = 'Phase 5: Summary';
    return;
  }
  // 进入 summary 模式
  document.body.classList.add('summary-mode');
  document.getElementById('btnPhase5').textContent = '\u2190 Back';
  document.getElementById('summaryTarget').textContent = target;
  const box = document.getElementById('summaryBox');
  box.innerHTML = '<div class="loading-skeleton"><div class="bar" style="width:60%;height:24px;margin-bottom:20px;"></div><div class="bar" style="width:40%;height:14px;margin-bottom:12px;"></div><div class="bar" style="width:100%;height:14px;margin-bottom:12px;"></div><div class="bar" style="width:80%;height:14px;margin-bottom:12px;"></div><div class="bar" style="width:55%;height:14px;margin-bottom:24px;"></div><div class="bar" style="width:45%;height:14px;margin-bottom:12px;"></div><div class="bar" style="width:90%;height:14px;margin-bottom:12px;"></div><div class="bar" style="width:70%;height:14px;"></div></div>';
  const d = await api('/api/summary?target=' + encodeURIComponent(target));
  if (d && d.content) {
    box.innerHTML = marked.parse(d.content);
  } else {
    box.innerHTML = '<div style="text-align:center;color:#656d76;padding:60px 20px;font-size:15px;">No SUMMARY.md found for <strong>' + target + '</strong>. Run fuzzing and Phase 4 first to generate reports.</div>';
  }
}

async function loadManifest() {
  const target = document.getElementById('targetSelect').value;
  const panel = document.getElementById('strategyPanel');
  const list = document.getElementById('strategyList');
  const count = document.getElementById('strategyCount');
  if (!target) { panel.style.display = 'none'; return; }
  // 保存当前勾选状态
  const prevChecked = new Set();
  document.querySelectorAll('.strategy-cb:checked').forEach(cb => prevChecked.add(cb.value));
  const d = await api(`/api/manifest?target=${encodeURIComponent(target)}`);
  if (d && d.strategies && d.strategies.length) {
    panel.style.display = 'block';
    count.textContent = `${d.strategies.length} available (batch_size=${d.batch_size||4})`;
    list.innerHTML = d.strategies.map(s => {
      const wasChecked = prevChecked.has(String(s.id));
      return `<div style="display:flex;align-items:flex-start;gap:10px;padding:10px 14px;background:#f6f8fa;border:1px solid #d0d7de;border-radius:6px;">
        <input type="checkbox" class="strategy-cb" value="${s.id}" ${wasChecked?'checked':''} onchange="updateSelectAll()" style="margin-top:3px;">
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
            <strong style="font-size:14px;">${s.name||'id_'+s.id}</strong>
            <span style="font-size:11px;padding:1px 6px;border-radius:4px;background:${s.priority==='critical'?'#ffebe9':'#fff8c5'};color:${s.priority==='critical'?'#cf222e':'#9a6700'};">${s.priority||'medium'}</span>
            <span style="font-size:11px;color:#656d76;">score: ${s.vuln_score||'?'}</span>
          </div>
          <div style="font-family:'Cascadia Code','JetBrains Mono','Fira Code',Consolas,monospace;font-size:12px;color:#24292f;background:#ffffff;padding:8px 12px;border-radius:4px;white-space:pre-wrap;word-break:break-all;line-height:1.5;">${s.command||'N/A'}</div>
        </div>
      </div>`;
    }).join('');
    updateSelectAll();
  } else {
    panel.style.display = 'none';
  }
}

function toggleAllStrategies() {
  const checked = document.getElementById('selectAllStrategies').checked;
  document.querySelectorAll('.strategy-cb').forEach(cb => cb.checked = checked);
}

function updateSelectAll() {
  const all = document.querySelectorAll('.strategy-cb');
  const checked = document.querySelectorAll('.strategy-cb:checked');
  document.getElementById('selectAllStrategies').checked = all.length === checked.length;
}

function getSelectedStrategyIds() {
  return Array.from(document.querySelectorAll('.strategy-cb:checked')).map(cb => cb.value).join(',');
}

// Log scroll listener
document.addEventListener('DOMContentLoaded', () => {
  const box = document.getElementById('logBox');
  box.addEventListener('scroll', () => {
    const threshold = 30;
    logAtBottom = (box.scrollTop + box.clientHeight >= box.scrollHeight - threshold);
  });
});

async function startPipeline(phase) {
  const target = document.getElementById('targetSelect').value;
  if (!target) { alert('Please select a target project first.'); return; }
  const btnId = {1:'btnPhase1', 2:'btnPhase2', 3:'btnPhase3', 4:'btnPhase4'}[phase] || 'btnPhase1';
  const btn = document.getElementById(btnId);
  const status = document.getElementById('pipelineStatus');
  btn.disabled = true;
  status.textContent = 'Starting...';
  status.style.color = '#9a6700';

  // Phase 3: save selected strategies first
  if (phase === 3) {
    const refEnabled = document.getElementById('refEnabled').checked;
    const ids = getSelectedStrategyIds();
    if (!ids && !refEnabled) { alert('Please select at least one strategy.'); btn.disabled = false; return; }
    const sel = await api(`/api/manifest/select?target=${encodeURIComponent(target)}&strategy_ids=${ids}`, {method:'POST'});
    if (!sel || sel.error) {
      status.textContent = sel && sel.error ? sel.error : 'Failed to save strategy selection';
      status.style.color = '#cf222e';
      btn.disabled = false;
      return;
    }
  }

  let url = `/api/pipeline/start?target=${encodeURIComponent(target)}&phase=${phase}`;
  const r = await api(url, {method:'POST'});
  btn.disabled = false;
  status.style.color = '#656d76';
  if (r && r.status === 'started') {
    status.textContent = `Phase ${phase} running on ${target}`;
    status.style.color = '#1a7f37';
  } else {
    const msg = r && r.error ? r.error : 'Failed to start';
    status.textContent = msg;
    status.style.color = '#cf222e';
    if (msg === 'pipeline already running') {
      alert('Pipeline is already running. Please stop it first or wait for it to complete.');
    }
  }
}

async function killStrategy(pid) {
  if (!pid) return;
  if (!confirm('Stop this afl-fuzz process (PID: ' + pid + ')?')) return;
  // 从当前策略数据中找到对应的行
  var allRows = document.querySelectorAll('#strategiesBody tr.strategy-row');
  var strategyData = {};
  for (var i = 0; i < allRows.length; i++) {
    var cells = allRows[i].cells;
    if (cells.length >= 2) {
      var rowPid = cells[2].textContent.trim();
      if (rowPid === String(pid)) {
        strategyData = {
          name: cells[1].textContent.replace(/[\u26a0\u26a1].*$/, '').trim(),
          pid: pid,
          edges: cells[3].textContent.trim(),
          crashes: cells[4].textContent.trim(),
          paths: cells[5].textContent.trim(),
          speed: cells[6].textContent.trim(),
          cycles: cells[7].textContent.trim(),
          bitmap: cells[8].textContent.trim(),
          runtime: cells[9].textContent.trim()
        };
        break;
      }
    }
  }
  var target = document.getElementById('targetSelect').value;
  var r = await api('/api/strategy/kill?pid=' + pid + '&target=' + encodeURIComponent(target), {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({strategy: strategyData})
  });
  if (r && r.status === 'killed') {
    updateDashboard();
  }
}

async function stopAllStrategies() {
  if (!confirm('Stop all running AFL++ strategies?')) return;
  await api('/api/pipeline/stop', {method:'POST'});
  updateDashboard();
}

async function cleanWorkspace() {
  const target = document.getElementById('targetSelect').value;
  if (!target) { alert('Please select a target project first.'); return; }
  if (!confirm(`Clean all fuzz workspace for "${target}"?\n\nThis will:\n- Kill all afl-fuzz processes for this project\n- Delete container fuzz workspace\n- Delete host output directory\n\nThis cannot be undone!`)) return;
  const status = document.getElementById('pipelineStatus');
  status.textContent = 'Cleaning...';
  status.style.color = '#9a6700';
  const r = await api(`/api/workspace/clean?target=${encodeURIComponent(target)}`, {method:'POST'});
  if (r && r.status === 'cleaned') {
    document.getElementById('strategyPanel').style.display = 'none';
    status.textContent = `Workspace cleaned for ${target}`;
    status.style.color = '#1a7f37';
  } else {
    status.textContent = r && r.error ? r.error : 'Failed to clean';
    status.style.color = '#cf222e';
  }
}

async function stopAll() {
  const status = document.getElementById('pipelineStatus');
  status.textContent = 'Stopping...';
  const r = await api('/api/pipeline/stop', {method:'POST'});
  if (r) {
    status.textContent = r.total_crashes ? `Stopped (${r.total_crashes} crashes collected)` : 'Stopped';
  }
}

function toggleRefPanel() {
  const panel = document.getElementById('refPanel');
  const arrow = document.getElementById('refArrow');
  if (!panel || !arrow) return;
  const show = panel.style.display !== 'block';
  panel.style.display = show ? 'block' : 'none';
  arrow.className = 'arrow' + (show ? ' open' : '');
}

function onRefFileSelect(event) {
  var file = event.target.files[0];
  if (!file) return;
  document.getElementById('refFileName').textContent = file.name;
  var reader = new FileReader();
  reader.onload = function(e) {
    var ta = document.getElementById('refTextInput');
    var prefix = ta.value ? ta.value + '\\n\\n' : '';
    ta.value = prefix + '> From ' + file.name + ':\\n' + e.target.result;
  };
  reader.readAsText(file);
}

async function clearRefContext() {
  document.getElementById('refTextInput').value = '';
  document.getElementById('refFileName').textContent = '';
  // 同步清空服务端文件
  var target = document.getElementById('targetSelect').value;
  if (target) {
    await api('/api/ref-context?target=' + encodeURIComponent(target), {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({text: ''})
    });
  }
  var saved = document.getElementById('refSaved');
  saved.style.display = 'inline';
  saved.textContent = 'Cleared';
  setTimeout(function() { saved.style.display = 'none'; saved.textContent = '\u2713 Saved'; }, 2000);
}

async function saveRefContext() {
  const target = document.getElementById('targetSelect').value;
  if (!target) return;
  const text = document.getElementById('refTextInput').value.trim();
  const enabled = document.getElementById('refEnabled').checked;
  const saved = document.getElementById('refSaved');
  const r = await api(`/api/ref-context?target=${encodeURIComponent(target)}`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text: text, enabled: enabled})
  });
  if (r && r.status === 'saved') {
    saved.style.display = 'inline';
    setTimeout(() => saved.style.display = 'none', 2000);
  }
}

async function loadRefContext() {
  const target = document.getElementById('targetSelect').value;
  if (!target) return;
  const r = await api(`/api/ref-context?target=${encodeURIComponent(target)}`);
  if (r) {
    document.getElementById('refTextInput').value = r.text || '';
    document.getElementById('refEnabled').checked = r.enabled !== false;
  }
}

// Target change → load strategies
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('targetSelect').addEventListener('change', () => {
    loadManifest();
    updateDashboard();
    loadRefContext();
    // 切换项目时退出 summary
    document.body.classList.remove('summary-mode');
  });
});

// Init
api('/api/projects').then(d => {
  if (d && d.projects) {
    const sel = document.getElementById('targetSelect');
    d.projects.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p; opt.textContent = p;
      sel.appendChild(opt);
    });
  }
});

setInterval(updateDashboard, 5000);
updateDashboard();

// ── Interactive code burst on background click ──
const CODE_TOKENS = ['</>','{ }','0x00','afl','fuzz','/*..*/','for(;;)','while','if()','ptr->','++','!=','&&','||','SIGSEGV','ASAN','#include','[ ]','malloc','free','0xFF','{;}','==','!','main()','--','=>','::'];
document.addEventListener('click', e => {
  if (e.target.closest('button,select,input,a,option')) return;
  const count = 6 + Math.floor(Math.random() * 6);
  for (let i = 0; i < count; i++) {
    const el = document.createElement('span');
    el.className = 'code-burst';
    el.textContent = CODE_TOKENS[Math.floor(Math.random() * CODE_TOKENS.length)];
    const angle = Math.random() * Math.PI * 2;
    const dist = 60 + Math.random() * 100;
    const size = 12 + Math.random() * 14;
    const hue = 200 + Math.random() * 60;
    el.style.left = (e.clientX + (Math.random() - 0.5) * 20) + 'px';
    el.style.top = (e.clientY + (Math.random() - 0.5) * 20) + 'px';
    el.style.fontSize = size + 'px';
    el.style.color = 'hsla(' + hue + ',70%,50%,0.9)';
    el.style.setProperty('--dx', Math.cos(angle) * dist + 'px');
    el.style.setProperty('--dy', Math.sin(angle) * dist + 'px');
    el.style.setProperty('--r', (Math.random() - 0.5) * 720 + 'deg');
    el.style.animationDuration = (0.6 + Math.random() * 0.8) + 's';
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 1500);
  }
});
</script>
</body>
</html>"""


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
