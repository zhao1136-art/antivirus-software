"""
御天 实时守护 Python 接口
与 C++ file_guard.exe 通过命名管道通信
"""
import os
import sys
import threading
import subprocess
import json
from typing import Optional, Callable

GUARD_EXE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "native_guard", "file_guard.exe")

class FileGuardClient:
    """Python 端：连接 C++ 守护进程并接收文件事件"""

    def __init__(self, callback: Optional[Callable] = None):
        self._proc: Optional[subprocess.Popen] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callback = callback

    def start(self, watch_dirs: list[str] = None):
        """启动守护进程"""
        if self._running:
            return
        # 原生 native_guard 层默认禁用（同 native_guard_bridge）：其实时守护子进程
        # file_guard.exe 属于同一原生对抗层，在加载/运行阶段存在致命 0xC0000005
        # 访问违规风险，会拖垮主进程。除非显式 YUTIAN_NATIVE_GUARD=1 启用，
        # 否则不拉起，实时文件保护交由稳定运行的内置 file_guard 引擎承担。
        if os.environ.get("YUTIAN_NATIVE_GUARD", "").strip() != "1":
            print("[Guard] 原生 file_guard.exe 已禁用（未启用 YUTIAN_NATIVE_GUARD=1），使用内置实时防护")
            return
        if not os.path.isfile(GUARD_EXE):
            print(f"[Guard] 守护进程未找到: {GUARD_EXE}")
            return

        args = [GUARD_EXE]
        if watch_dirs:
            for d in watch_dirs:
                args.extend(["--watch", d])

        try:
            # CREATE_NO_WINDOW 仅 Windows 存在；Linux 下用 0
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            self._proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
            )
            self._running = True
            self._thread = threading.Thread(target=self._pipe_reader, daemon=True)
            self._thread.start()
            print(f"[Guard] 实时防护已启动 (PID={self._proc.pid})")
        except Exception as e:
            print(f"[Guard] 启动失败: {e}")

    def _pipe_reader(self):
        """读取命名管道消息"""
        import time
        time.sleep(1)  # 等待守护进程初始化管道

        try:
            # 使用 win32 API 或简单方式连接管道
            # 由于用标准库较复杂，这里简化为定期轮询守护进程输出
            while self._running and self._proc:
                line = self._proc.stdout.readline()
                if not line:
                    break
                try:
                    decoded = line.decode("utf-8", errors="replace").strip()
                    if decoded.startswith("{"):
                        msg = json.loads(decoded)
                        if self._callback:
                            self._callback(msg)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
        except Exception:
            pass

    def stop(self):
        """停止守护进程"""
        self._running = False
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        print("[Guard] 实时防护已停止")

    @property
    def is_running(self) -> bool:
        return self._running and self._proc is not None and self._proc.poll() is None


# 全局单例
_guard_client: Optional[FileGuardClient] = None


def get_guard() -> FileGuardClient:
    global _guard_client
    if _guard_client is None:
        _guard_client = FileGuardClient()
    return _guard_client


def scan_on_event(event: dict):
    """收到文件事件时的回调：触发扫描"""
    action = event.get("action", "")
    path = event.get("path", "")
    if action in ("created", "modified") and path:
        # 异步触发扫描
        def _do():
            try:
                from engine.scheduler import Scheduler
                s = Scheduler()
                task = s.create_task("custom", [path])
                s.run_task(task.task_id)
            except Exception:
                pass
        threading.Thread(target=_do, daemon=True).start()
