"""Agent SDK MCP 工具 — 在 AFL++ Docker 容器内执行命令。"""

from claude_agent_sdk import tool, create_sdk_mcp_server
from pipeline.container import ContainerManager, ContainerError

CONTAINER_NAME = "afl"


def _get_manager() -> ContainerManager:
    """获取共享的 ContainerManager 实例。"""
    mgr = ContainerManager(container_name=CONTAINER_NAME)
    mgr.ensure_running()
    return mgr


@tool(
    "container_exec",
    "Run a shell command inside the AFL++ Docker container and return its stdout. "
    "Use this for compilation, fuzzing, crash reproduction, and all container operations. "
    "The target project is mounted at /workspace/<project_name>.",
    {"command": str, "workdir": str},
)
async def container_exec(args: dict) -> dict:
    """在容器内执行命令并返回输出。"""
    mgr = _get_manager()
    try:
        stdout = mgr.exec(args["command"], workdir=args.get("workdir"))
        return {"content": [{"type": "text", "text": stdout}]}
    except ContainerError as e:
        return {"content": [{"type": "text", "text": f"[ERROR] {e}"}], "isError": True}


@tool(
    "container_exec_detached",
    "Start a long-running command in the background inside the AFL++ Docker container. "
    "Use this for afl-fuzz campaigns that need to run in the background.",
    {"command": str, "workdir": str},
)
async def container_exec_detached(args: dict) -> dict:
    """在容器内以后台模式执行命令（用于长时间运行的 fuzz 任务）。"""
    mgr = _get_manager()
    try:
        result = mgr.exec_detached(args["command"], workdir=args.get("workdir"))
        return {"content": [{"type": "text", "text": result}]}
    except ContainerError as e:
        return {"content": [{"type": "text", "text": f"[ERROR] {e}"}], "isError": True}


def create_container_server():
    """创建并返回 MCP server，包含容器执行工具。"""
    return create_sdk_mcp_server(
        "container",
        tools=[container_exec, container_exec_detached],
    )
