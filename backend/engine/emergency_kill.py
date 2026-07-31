"""
F12 紧急处置模块 —— 连按 F12 五次关闭所有非系统进程

功能：
1. RegisterHotKey 注册 F12（MOD_NOREPEAT），线程内 GetMessage 循环等待 WM_HOTKEY
2. 2 秒窗口内连按 5 次 → 触发紧急杀进程
3. 系统进程白名单保护（~30 个系统关键进程 + 安盾自身不会被杀）
4. 先 WM_CLOSE 优雅关闭窗口 → 等待 3 秒 → TerminateProcess 强制终止
5. 日志记录 + 30 秒冷却防重入
"""
import os
import sys
import time
import json
import ctypes
import ctypes.wintypes as wt
import threading
from collections import deque
from datetime import datetime

from engine.system_guard import SYSTEM_CRITICAL_PROCESSES

IS_WINDOWS = sys.platform == 'win32'

# ── Win32 常量 ────────────────────────────────────────────
VK_F12 = 0x7B
MOD_NOREPEAT = 0x4000
WM_HOTKEY = 0x0312
WM_CLOSE = 0x0010
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000

# 触发参数
TRIGGER_WINDOW = 2.0      # 2 秒窗口
TRIGGER_COUNT = 5         # 连按 5 次触发
COOLDOWN_SECONDS = 30     # 触发后冷却 30 秒

# ── Win32 DLL ─────────────────────────────────────────────

user32 = None
kernel32 = None
WNDENUMPROC = None

if IS_WINDOWS:
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    user32.RegisterHotKey.argtypes = [wt.HANDLE, ctypes.c_int, wt.UINT, wt.UINT]
    user32.RegisterHotKey.restype = wt.BOOL
    user32.UnregisterHotKey.argtypes = [wt.HANDLE, ctypes.c_int]
    user32.UnregisterHotKey.restype = wt.BOOL

    user32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HANDLE, wt.UINT, wt.UINT]
    user32.GetMessageW.restype = wt.BOOL

    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
    kernel32.TerminateProcess.restype = wt.BOOL
    kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    kernel32.WaitForSingleObject.restype = wt.DWORD
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.CloseHandle.restype = wt.BOOL

    WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HANDLE, wt.LPARAM)
    user32.EnumWindows.argtypes = [WNDENUMPROC, wt.LPARAM]
    user32.EnumWindows.restype = wt.BOOL
    user32.PostMessageW.argtypes = [wt.HANDLE, wt.UINT, wt.WPARAM, wt.LPARAM]
    user32.PostMessageW.restype = wt.BOOL
    user32.GetWindowThreadProcessId.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
    user32.GetWindowThreadProcessId.restype = wt.DWORD


class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", wt.HANDLE),
        ("message", wt.UINT),
        ("wParam", wt.WPARAM),
        ("lParam", wt.LPARAM),
        ("time", wt.DWORD),
        ("pt", ctypes.wintypes.POINT),
    ]


# ── 系统进程白名单 ───────────────────────────────────────

SYSTEM_PROCESSES: set[str] = set(SYSTEM_CRITICAL_PROCESSES.keys()) | {
    # 系统核心（无进程名但有 PID）
    "system",
    "system idle process",
    "registry",
    "memory compression",
    # 系统服务与辅助
    "audiodg.exe",
    "sihost.exe",
    "taskhostw.exe",
    "backgroundtaskhost.exe",
    "runtimebroker.exe",
    "shellexperiencehost.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "wmiprvse.exe",
    "sppsvc.exe",
    "trustedinstaller.exe",
    "tiworker.exe",
    "mousocoreworker.exe",
    "musnotifyicon.exe",
    "ctfmon.exe",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
    "fontdrvhost.exe",
    "spoolsv.exe",
    "ntoskrnl.exe",
    "ntkrnlpa.exe",
}


class EmergencyKillManager:
    """F12 紧急处置管理器"""

    def __init__(self):
        self._enabled = True
        self._running = False
        self._hotkey_thread: threading.Thread | None = None
        self._cooldown_until: float = 0
        self._press_times: deque[float] = deque()
        self._last_trigger_time: str | None = None
        self._last_kill_count: int = 0
        self._events: deque[dict] = deque(maxlen=200)
        self._lock = threading.Lock()
        self._proc_name = self._get_self_name()

    @staticmethod
    def _get_self_name() -> str:
        try:
            return os.path.basename(sys.argv[0]).lower() if sys.argv else "安盾.exe"
        except Exception:
            return "安盾.exe"

    # ── 属性 ──

    @property
    def enabled(self) -> bool:
        return self._enabled

    # ── 启停 ──

    def enable(self):
        self._enabled = True
        self._add_event("info", "F12 紧急处置已启用")
        if not self._running:
            self.start()

    def disable(self):
        self._enabled = False
        self._add_event("info", "F12 紧急处置已禁用")

    def start(self):
        if not IS_WINDOWS:
            return
        if self._running:
            return
        self._running = True
        self._hotkey_thread = threading.Thread(
            target=self._hotkey_loop, daemon=True, name="EmergencyKill"
        )
        self._hotkey_thread.start()

    def stop(self):
        self._running = False

    # ── 状态与日志 ──

    def get_status(self) -> dict:
        now = time.time()
        cooling = max(0, int(self._cooldown_until - now))
        return {
            "enabled": self._enabled,
            "running": self._running,
            "cooling_seconds": cooling,
            "last_trigger": self._last_trigger_time,
            "last_kill_count": self._last_kill_count,
            "recent_events": list(self._events),
        }

    def get_log(self) -> list[dict]:
        path = self._get_log_path()
        if not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()[-50:]
            return [json.loads(l) for l in lines if l.strip()]
        except Exception:
            return []

    def _get_log_path(self) -> str:
        try:
            from config import LOGS_DIR
            return os.path.join(LOGS_DIR, "emergency_kill.log")
        except Exception:
            base = os.path.dirname(os.path.abspath(__file__))
            return os.path.join(base, "data", "logs", "emergency_kill.log")

    # ── 热键消息循环 ──

    def _hotkey_loop(self):
        hotkey_id = 0
        try:
            if not user32.RegisterHotKey(None, hotkey_id, MOD_NOREPEAT, VK_F12):
                self._add_event("error", "F12 热键注册失败（可能已被占用）")
                self._running = False
                return
            self._add_event("info", "F12 热键已注册，连按 5 次触发紧急处置")

            msg = MSG()
            while self._running:
                ret = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if ret <= 0:
                    break
                if msg.message == WM_HOTKEY and msg.wParam == hotkey_id:
                    self._on_f12_pressed()
        except Exception as e:
            self._add_event("error", f"热键线程异常: {e}")
        finally:
            try:
                user32.UnregisterHotKey(None, hotkey_id)
            except Exception:
                pass

    # ── 连按检测 ──

    def _on_f12_pressed(self):
        now = time.time()
        with self._lock:
            if self._cooldown_until > now:
                return
            self._press_times.append(now)
            # 滑出窗口外
            while self._press_times and self._press_times[0] < now - TRIGGER_WINDOW:
                self._press_times.popleft()
            if len(self._press_times) >= TRIGGER_COUNT:
                self._press_times.clear()
                self._cooldown_until = now + COOLDOWN_SECONDS
                threading.Thread(target=self._execute_kill, daemon=True).start()

    # ── 执行杀进程 ──

    def _execute_kill(self):
        self._add_event("info", "F12 紧急处置触发！开始关闭非系统进程...")

        from engine.system_guard import enumerate_processes
        procs = enumerate_processes()
        if not procs:
            self._add_event("error", "进程枚举失败")
            return

        self_name = self._proc_name
        killed: list[tuple[str, int]] = []
        skipped: list[tuple[str, int, str]] = []

        for p in procs:
            pid = p["pid"]
            name = (p.get("name") or "").lower()

            # PID 0/4 永不碰
            if pid <= 4:
                skipped.append((name, pid, "系统核心"))
                continue
            # 系统白名单
            if name in SYSTEM_PROCESSES:
                skipped.append((name, pid, "系统进程"))
                continue
            # 安盾自身
            if name == self_name:
                skipped.append((name, pid, "安盾自身"))
                continue

            ok = self._kill_process(pid, name)
            if ok:
                killed.append((name, pid))
            else:
                skipped.append((name, pid, "失败(权限/已退出)"))

        count = len(killed)
        self._last_kill_count = count
        self._last_trigger_time = datetime.now().isoformat()
        self._add_event("success", f"紧急处置完成：已终止 {count} 个非系统进程")
        self._write_log(killed, skipped)

    # ── 杀单个进程 ──

    def _kill_process(self, pid: int, name: str) -> bool:
        try:
            # 1. WM_CLOSE 优雅关闭（有窗口的进程）
            self._send_wm_close(pid)

            # 2. 等 3 秒
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid
            )
            if handle:
                kernel32.WaitForSingleObject(handle, 3000)
                kernel32.CloseHandle(handle)

            # 3. TerminateProcess 强制结束
            handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if not handle:
                return False  # 已退出或无权限
            kernel32.TerminateProcess(handle, 1)
            kernel32.CloseHandle(handle)
            return True
        except Exception:
            return False

    def _send_wm_close(self, pid: int) -> bool:
        sent = [False]
        pid_ref = ctypes.c_ulong(pid)

        @WNDENUMPROC
        def enum_proc(hwnd, _lparam):
            thread_pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(thread_pid))
            if thread_pid.value == pid_ref.value:
                user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
                sent[0] = True
            return True

        try:
            user32.EnumWindows(enum_proc, 0)
        except Exception:
            pass
        return sent[0]

    # ── 日志 ──

    def _write_log(self, killed: list, skipped: list):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "killed": [{"name": n, "pid": p} for n, p in killed],
            "killed_count": len(killed),
            "skipped": [
                {"name": n, "pid": p, "reason": r} for n, p, r in skipped
            ],
        }
        path = self._get_log_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _add_event(self, level: str, message: str):
        event = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        }
        with self._lock:
            self._events.append(event)
