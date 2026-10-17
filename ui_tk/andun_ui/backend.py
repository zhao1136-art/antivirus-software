"""后端进程管理与界面偏好 —— 让 Tk UI 自己负责后端的生命周期。

为什么要单独一个模块
--------------------
本 UI 需要后端在 ``127.0.0.1:8899`` 提供 ``/api/v1/*``。此前要用户手动去起，
现在由 UI 代管：检测 → 拉起 → 等就绪 → 必要时停止。

启动命令为什么是 ``python -m uvicorn app:app`` 而不是 ``python app.py``
--------------------------------------------------------------------
``app.py`` 的 ``__main__`` 分支除了起 uvicorn，还会 `webview.start()` 弹一个
WebView2 窗口、并启动系统托盘。那是"主程序形态"，与 Tk UI 并存会多出一个
窗口 + 一个托盘图标。改用 ``-m uvicorn app:app`` 只导入并服务 ``app``
对象，**不执行 __main__**，因此得到的是纯 API 后端 —— 这正是 UI 想要的。

只管自己启动的进程
------------------
:meth:`BackendManager.stop` 只在"后端是本管理器拉起来的"时才动手。
若用户早已自己起了后端（或主程序在跑），我们只连接、不接管，绝不越权关掉
别人的进程 —— 对安全软件来说，误关后端等于关掉防护。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

__all__ = ["BackendManager", "load_prefs", "save_prefs", "PREFS_PATH"]

DEFAULT_PORT = 8899
DEFAULT_HOST = "127.0.0.1"

# 拉起后端后等待 /api/health 就绪的总预算（秒）。app.py 导入期要建特征库
# 索引、初始化各守护模块，冷启动偏慢，给足余量。
READY_TIMEOUT = 40.0
READY_INTERVAL = 0.6

_CREATE_NO_WINDOW = 0x08000000  # subprocess.CREATE_NO_WINDOW（Windows）


# ── 界面偏好落盘 ─────────────────────────────────────────────
#
# 放 %LOCALAPPDATA%\Andun\ 而不是仓库里：与主程序的数据位置约定一致
# （见 backend/config.py 的 _get_data_dir），也不污染源码目录。

def _prefs_dir() -> str:
    local = os.environ.get("LOCALAPPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Local")
    return os.path.join(local, "Andun")


PREFS_PATH = os.path.join(_prefs_dir(), "ui_prefs.json")

_DEFAULT_PREFS = {
    "auto_start_backend": True,     # 打开 UI 时若后端没在跑就自动拉起
    "stop_on_exit": False,          # 退出 UI 时是否关掉"我启动的"后端
    "backend_dir": "",              # 空=自动探测
    "python": "",                   # 空=用当前解释器
}


def load_prefs() -> dict:
    """读偏好；文件不存在或损坏都回落到默认值，绝不抛。"""
    prefs = dict(_DEFAULT_PREFS)
    try:
        with open(PREFS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            for key in _DEFAULT_PREFS:
                if key in data:
                    prefs[key] = data[key]
    except (OSError, json.JSONDecodeError):
        pass
    return prefs


def save_prefs(prefs: dict) -> bool:
    try:
        os.makedirs(os.path.dirname(PREFS_PATH), exist_ok=True)
        merged = dict(_DEFAULT_PREFS)
        merged.update({k: v for k, v in (prefs or {}).items() if k in _DEFAULT_PREFS})
        with open(PREFS_PATH, "w", encoding="utf-8") as fh:
            json.dump(merged, fh, ensure_ascii=False, indent=2)
        return True
    except OSError:
        return False


# ── 后端进程管理 ─────────────────────────────────────────────

class BackendManager:
    """探测 / 拉起 / 停止后端。所有方法都不抛异常，用返回值表达结果。"""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 backend_dir: str = "", python: str = ""):
        self.host = host
        self.port = int(port)
        self.prefs = load_prefs()
        self.backend_dir = backend_dir or str(self.prefs.get("backend_dir") or "")
        self.python = python or str(self.prefs.get("python") or "")
        self._proc: subprocess.Popen | None = None
        self._log_path = os.path.join(_prefs_dir(), "data", "logs", "ui_backend.log")

    # ── 基础信息 ──

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def started_by_us(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def log_path(self) -> str:
        return self._log_path

    # ── 路径探测 ──

    def python_exe(self) -> str:
        """优先用当前解释器 —— 它一定已能跑本 UI，也就最可能装好 uvicorn。"""
        if self.python and os.path.isfile(self.python):
            return self.python
        if sys.executable and os.path.isfile(sys.executable):
            return sys.executable
        for cand in (r"F:\Python314\python.exe", "python"):
            if cand == "python" or os.path.isfile(cand):
                return cand
        return "python"

    def detect_backend_dir(self) -> str:
        """定位含 ``app.py`` 的 backend 目录。

        顺序：显式配置 → ui_tk 的兄弟目录 → 当前工作目录及其子目录。
        """
        if self.backend_dir and os.path.isfile(os.path.join(self.backend_dir, "app.py")):
            return self.backend_dir
        here = os.path.dirname(os.path.abspath(__file__))          # ui_tk/andun_ui
        root = os.path.dirname(os.path.dirname(here))               # 仓库根
        candidates = [
            os.path.join(root, "backend"),
            os.path.join(os.getcwd(), "backend"),
            os.getcwd(),
        ]
        for cand in candidates:
            if os.path.isfile(os.path.join(cand, "app.py")):
                self.backend_dir = os.path.normpath(cand)
                return self.backend_dir
        return ""

    # ── 存活探测 ──

    def is_alive(self, timeout: float = 1.5) -> bool:
        """GET /api/health。任何异常都算"没在跑"。"""
        req = urllib.request.Request(self.base_url + "/api/health",
                                     headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return 200 <= getattr(resp, "status", 200) < 500
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
            return False

    # ── 启动 ──

    def start(self) -> tuple[bool, str]:
        """拉起后端（不阻塞等待就绪）。返回 (是否已发起, 说明)。"""
        if self.is_alive():
            return True, "后端已在运行，直接连接"

        backend_dir = self.detect_backend_dir()
        if not backend_dir:
            return False, ("找不到后端目录（需要包含 app.py）。"
                           "请在设置里指定 backend 目录路径。")

        python = self.python_exe()
        cmd = [python, "-m", "uvicorn", "app:app",
               "--host", self.host, "--port", str(self.port),
               "--log-level", "warning"]

        try:
            os.makedirs(os.path.dirname(self._log_path), exist_ok=True)
            log = open(self._log_path, "a", encoding="utf-8", errors="replace")
        except OSError:
            log = subprocess.DEVNULL

        try:
            self._proc = subprocess.Popen(
                cmd, cwd=backend_dir,
                stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                creationflags=_CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        except OSError as exc:
            try:
                if log is not subprocess.DEVNULL:
                    log.close()
            except Exception:
                pass
            return False, f"启动后端失败：{exc}"

        return True, f"已发起启动：{python} -m uvicorn app:app（cwd={backend_dir}）"

    def wait_ready(self, timeout: float = READY_TIMEOUT,
                   should_abort=None) -> tuple[bool, str]:
        """轮询 /api/health 直到就绪。

        ``should_abort()`` 返回 True 时提前退出（界面关掉了就别再等了）。
        """
        deadline = time.time() + max(1.0, float(timeout))
        while time.time() < deadline:
            if should_abort is not None and should_abort():
                return False, "已取消等待"
            if self.is_alive(timeout=1.0):
                return True, "后端已就绪"
            # 进程早死就立刻报错，不用等满超时
            if self._proc is not None and self._proc.poll() is not None:
                return False, (f"后端进程已退出（代码 {self._proc.returncode}）。"
                               f"详见日志：{self._log_path}")
            time.sleep(READY_INTERVAL)
        return False, f"等待后端就绪超时（{timeout:.0f}s）。详见日志：{self._log_path}"

    # ── 停止 ──

    def stop(self) -> tuple[bool, str]:
        """只停自己启动的进程。别人的后端一律不碰。"""
        if self._proc is None:
            return False, "后端不是本界面启动的，不予停止"
        if self._proc.poll() is not None:
            self._proc = None
            return True, "后端进程已结束"

        try:
            self._proc.terminate()
        except OSError:
            pass
        try:
            self._proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            try:
                self._proc.kill()
                self._proc.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                return False, "无法结束后端进程，请手动处理"
        self._proc = None
        return True, "已停止本界面启动的后端"
