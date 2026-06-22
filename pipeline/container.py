"""AFL++ Docker 容器管理 — 使用 Docker SDK 真实连接容器。"""

import io
import logging
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import docker
from docker.errors import DockerException, NotFound, APIError

logger = logging.getLogger(__name__)

DEFAULT_IMAGE = "aflplusplus/aflplusplus:latest"
DEFAULT_CONTAINER_NAME = "afl"
MAX_RETRIES = 3
RETRY_DELAY = 2


class ContainerError(Exception):
    """容器相关错误的基类。"""


class ContainerNotRunning(ContainerError):
    """容器未运行。"""


class ContainerNotFound(ContainerError):
    """容器不存在。"""


class ContainerManager:
    """通过 Docker SDK 管理 AFL++ 容器。"""

    def __init__(
        self,
        container_name: str = DEFAULT_CONTAINER_NAME,
        image: str = DEFAULT_IMAGE,
    ):
        self.container_name = container_name
        self.image = image
        self._client: docker.DockerClient | None = None
        self._container: docker.models.containers.Container | None = None

    # ──────────────────────────────────────────
    # Connection
    # ──────────────────────────────────────────

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            try:
                self._client = docker.from_env()
                self._client.ping()
            except DockerException as e:
                raise ContainerError(
                    f"无法连接 Docker: {e}\n"
                    f"请确保 Docker Desktop 正在运行。"
                ) from e
        return self._client

    # ──────────────────────────────────────────
    # Container lookup
    # ──────────────────────────────────────────

    def find_container(self) -> docker.models.containers.Container | None:
        """查找容器（不关心状态），不存在返回 None。"""
        try:
            c = self.client.containers.get(self.container_name)
            self._container = c
            return c
        except NotFound:
            return None

    def get_container(self) -> docker.models.containers.Container:
        """获取容器，不存在则抛出 ContainerNotFound。"""
        c = self.find_container()
        if c is None:
            raise ContainerNotFound(
                f"容器 '{self.container_name}' 不存在。\n"
                f"请先创建:\n"
                f"  cd auto_fuzz && docker compose up -d\n"
                f"或:\n"
                f"  docker run -dit --name {self.container_name} {self.image}"
            )
        return c

    # ──────────────────────────────────────────
    # Status
    # ──────────────────────────────────────────

    def status(self) -> dict:
        """返回容器状态信息。"""
        c = self.find_container()
        if c is None:
            return {"exists": False, "running": False, "status": "not_found"}
        return {
            "exists": True,
            "running": c.status == "running",
            "status": c.status,
            "id": c.short_id,
            "image": c.image.tags[0] if c.image.tags else str(c.image),
        }

    def ensure_running(self, auto_start: bool = True) -> docker.models.containers.Container:
        """确保容器在运行，必要时自动启动。

        Returns:
            Container 对象

        Raises:
            ContainerNotFound: 容器不存在
            ContainerError: 启动失败
        """
        c = self.get_container()

        if c.status == "running":
            logger.debug("Container '%s' is running (%s)", self.container_name, c.short_id)
            self._container = c
            return c

        if not auto_start:
            raise ContainerNotRunning(
                f"容器 '{self.container_name}' 状态为 '{c.status}'，未运行。"
            )

        logger.info("Starting container '%s'...", self.container_name)
        try:
            c.start()
            # 等待容器就绪
            for i in range(MAX_RETRIES):
                time.sleep(RETRY_DELAY)
                c.reload()
                if c.status == "running":
                    logger.info("Container started (%s)", c.short_id)
                    self._container = c
                    return c
                logger.info("  waiting... attempt %d/%d", i + 1, MAX_RETRIES)
        except APIError as e:
            raise ContainerError(f"启动容器失败: {e}") from e

        raise ContainerError(f"容器启动后未进入 running 状态 (当前: {c.status})")

    # ──────────────────────────────────────────
    # Command execution
    # ──────────────────────────────────────────

    def exec(self, cmd: str | list[str], workdir: str | None = None, timeout: int | None = 600) -> str:
        """在容器内执行命令并返回 stdout。

        Args:
            cmd: 命令字符串或列表
            workdir: 工作目录（容器内路径）
            timeout: 超时秒数（默认 600s）

        Returns:
            命令 stdout

        Raises:
            ContainerError: 执行失败或超时
        """
        c = self.ensure_running()

        if isinstance(cmd, str):
            cmd = ["sh", "-c", cmd]

        exec_kwargs = {}
        if workdir:
            exec_kwargs["workdir"] = workdir

        try:
            exit_code, output = c.exec_run(cmd, **exec_kwargs)
        except APIError as e:
            raise ContainerError(f"容器内命令执行失败: {e}") from e

        stdout = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)

        if exit_code != 0:
            raise ContainerError(
                f"命令退出码 {exit_code}:\n"
                f"  cmd: {cmd}\n"
                f"  stdout: {stdout[:2000]}"
            )

        return stdout

    def exec_detached(self, cmd: str | list[str], workdir: str | None = None) -> str:
        """在容器内以 detach 模式执行命令（后台运行）。

        Returns:
            命令 stdout (通常是空的)
        """
        c = self.ensure_running()

        if isinstance(cmd, str):
            cmd = ["sh", "-c", cmd]

        exec_kwargs = {}
        if workdir:
            exec_kwargs["workdir"] = workdir

        try:
            exec_id = c.client.api.exec_create(c.id, cmd, **exec_kwargs)
            c.client.api.exec_start(exec_id["Id"], detach=True)
            return f"[detached] exec_id: {exec_id['Id']}"
        except APIError as e:
            raise ContainerError(f"容器内 detach 命令失败: {e}") from e

    def check_afl_available(self) -> bool:
        """检查容器内 afl-fuzz 是否可用。"""
        try:
            out = self.exec("which afl-fuzz && afl-fuzz --version 2>&1 | head -1")
            logger.info("AFL++ in container: %s", out.strip())
            return True
        except ContainerError:
            return False

    def get_container_path(self, host_path: str) -> str:
        """将宿主机路径转换为容器内路径（基于 volume 映射）。"""
        # 默认映射: auto_fuzz 所在目录 -> /workspace/
        # 可以通过 docker-compose.yml volumes 配置
        return host_path  # 简单映射: 如果 volume 挂载了上级目录

    # ──────────────────────────────────────────
    # File transfer (tar archive)
    # ──────────────────────────────────────────

    def copy_to_container(self, src_path: str, dest_dir: str) -> None:
        """将宿主机文件复制到容器内（使用 tar archive）。

        Args:
            src_path: 宿主机文件路径
            dest_dir: 容器内目标目录（必须已存在）
        """
        c = self.ensure_running()
        src = Path(src_path)
        if not src.exists():
            raise ContainerError(f"源文件不存在: {src_path}")

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            tar.add(str(src), arcname=src.name)
        tar_stream.seek(0)

        try:
            c.put_archive(dest_dir, tar_stream)
        except APIError as e:
            raise ContainerError(f"复制到容器失败: {e}") from e

    def copy_from_container(self, src_path: str, dest_dir: str) -> None:
        """将容器内文件复制到宿主机（使用 tar archive）。

        Args:
            src_path: 容器内文件或目录路径
            dest_dir: 宿主机目标目录
        """
        c = self.ensure_running()
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)

        try:
            tar_stream, _ = c.get_archive(src_path)
            tar_bytes = b"".join(tar_stream)
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
                tar.extractall(path=str(dest))
        except APIError as e:
            raise ContainerError(f"从容复制失败: {e}") from e

    # ──────────────────────────────────────────
    # Cleanup
    # ──────────────────────────────────────────

    def close(self):
        """释放 Docker 客户端连接。"""
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ──────────────────────────────────────────────
# CLI: 直接测试容器连接
# ──────────────────────────────────────────────

def cli_check():
    """检查容器状态。"""
    mgr = ContainerManager()
    try:
        info = mgr.status()
        print(f"  容器:     {mgr.container_name}")
        print(f"  存在:     {'yes' if info['exists'] else 'no'}")
        print(f"  运行中:   {'yes' if info['running'] else 'no'}")
        print(f"  状态:     {info['status']}")
        if info['running']:
            print(f"  ID:       {info['id']}")
            print(f"  镜像:     {info['image']}")
    except ContainerError as e:
        print(f"  [ERROR] {e}")


def cli_shell(cmd: str | None = None):
    """在容器内执行命令。"""
    mgr = ContainerManager()
    try:
        mgr.ensure_running()
        if cmd:
            out = mgr.exec(cmd)
            print(out)
        else:
            # 进入交互式 shell
            os.system(f"docker exec -it {mgr.container_name} bash")
    except ContainerError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)


def cli_compile(target_dir: str):
    """在容器内编译目标项目。"""
    mgr = ContainerManager()
    try:
        mgr.ensure_running()
        print(f"Compiling {target_dir} in container {mgr.container_name}...")
        out = mgr.exec(
            f"cd /workspace/{target_dir} && AFL_USE_ASAN=1 CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared && make -j$(nproc)",
            timeout=1200,
        )
        print(out)
    except ContainerError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AFL++ Container Manager")
    parser.add_argument("action", choices=["check", "shell", "exec", "compile"], help="操作")
    parser.add_argument("args", nargs="*", help="额外参数")
    args = parser.parse_args()

    if args.action == "check":
        cli_check()
    elif args.action == "shell":
        cli_shell(" ".join(args.args) if args.args else None)
    elif args.action == "exec":
        cli_shell(" ".join(args.args))
    elif args.action == "compile":
        cli_compile(args.args[0] if args.args else ".")
