"""
御天 进程启动拦截模块

程序运行前校验是否恶意，拦截恶意进程启动。
"""
import os
import sys
import time
import json
import threading
import subprocess
import hashlib
from datetime import datetime
from collections import defaultdict

IS_WINDOWS = sys.platform == 'win32'

DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data"
)
LOG_FILE = os.path.join(DATA_DIR, "logs", "process_guard.log")

# 默认进程黑名单
DEFAULT_BLACKLIST = [
    "malware.exe", "trojan.exe", "ransomware.exe", "keylogger.exe",
    "miner.exe", "backdoor.exe", "spy.exe",
]

# 高危进程路径特征
HIGH_RISK_PATHS = [
    r"\\temp",
    r"\\tmp",
    r"\\appdata\\local\\temp",
    r"\\users\\*\\appdata\\roaming",
]


class ProcessGuard:
    """进程启动拦截"""

    def __init__(self):
        self._enabled = False
        self._running = False
        self._stop_event = threading.Event()
        self._blacklist: set[str] = set(DEFAULT_BLACKLIST)
        self._whitelist: set[str] = set()
        self._blocked_count = 0
        self._allowed_count = 0
        self._recent_blocks: list[dict] = []
        self._lock = threading.Lock()
        os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)

    def _log(self, msg: str):
        t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{t}] {msg}\n")
        except Exception:
            pass

    def enable(self):
        if self._enabled:
            return
        self._enabled = True
        self._log("进程拦截已启用")
        if not self._running:
            self._start()

    def disable(self):
        self._enabled = False
        self._log("进程拦截已禁用")

    def _start(self):
        self._running = True
        self._stop_event.clear()
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()

    def stop(self):
        self._enabled = False
        self._stop_event.set()
        self._running = False

    def add_to_blacklist(self, name: str):
        with self._lock:
            self._blacklist.add(name.lower())
            if name.lower() in self._whitelist:
                self._whitelist.discard(name.lower())

    def remove_from_blacklist(self, name: str):
        with self._lock:
            self._blacklist.discard(name.lower())

    def add_to_whitelist(self, name: str):
        with self._lock:
            self._whitelist.add(name.lower())
            self._blacklist.discard(name.lower())

    def get_lists(self) -> dict:
        with self._lock:
            return {
                "blacklist": sorted(self._blacklist),
                "whitelist": sorted(self._whitelist)
            }

    def _monitor_loop(self):
        """轮询扫描运行中的进程，检测恶意进程"""
        if not IS_WINDOWS:
            return
        known_pids: set[int] = set()
        while not self._stop_event.is_set():
            if not self._enabled:
                self._stop_event.wait(3)
                continue
            try:
                # 使用 tasklist 获取当前进程列表
                r = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                current_pids: set[int] = set()
                for line in r.stdout.strip().split("\n"):
                    if not line.strip():
                        continue
                    parts = line.strip().strip('"').split('","')
                    if len(parts) >= 2:
                        try:
                            pid = int(parts[1].strip('"'))
                            name = parts[0].strip('"').lower()
                            current_pids.add(pid)
                            # 检查新进程
                            if pid not in known_pids:
                                self._check_process(pid, name)
                        except (ValueError, IndexError):
                            pass
                known_pids = current_pids
            except Exception:
                pass
            self._stop_event.wait(3)

    def _check_process(self, pid: int, name: str):
        """检查进程是否在黑名单中"""
        # 白名单检查
        if name in self._whitelist:
            return

        # 黑名单检查
        if name in self._blacklist:
            self._block_process(pid, name, "进程名匹配黑名单")
            return

        # 高危路径检查
        try:
            r = subprocess.run(
                ["wmic", "process", "where", f"ProcessId={pid}", "get", "ExecutablePath"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            path = r.stdout.strip().split("\n")[-1].strip() if r.stdout else ""
            if path:
                path_lower = path.lower()
                for hp in HIGH_RISK_PATHS:
                    if hp in path_lower:
                        self._block_process(pid, name, f"高危路径: {path}")
                        return
        except Exception:
            pass

    def _block_process(self, pid: int, name: str, reason: str):
        """终止恶意进程"""
        try:
            subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            with self._lock:
                self._blocked_count += 1
                self._recent_blocks.insert(0, {
                    "time": datetime.now().isoformat(),
                    "pid": pid,
                    "name": name,
                    "reason": reason
                })
                if len(self._recent_blocks) > 50:
                    self._recent_blocks = self._recent_blocks[:50]
            self._log(f"拦截进程: {name} (PID: {pid}) - {reason}")
        except Exception as e:
            self._log(f"拦截进程失败: {name} (PID: {pid}) - {e}")

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self._enabled,
                "blocked_count": self._blocked_count,
                "allowed_count": self._allowed_count,
                "recent_blocks": list(self._recent_blocks[:20]),
                "blacklist_count": len(self._blacklist),
                "whitelist_count": len(self._whitelist)
            }

    def get_status(self) -> dict:
        return {
            "enabled": self._enabled,
            "running": self._running,
            "blocked_total": self._blocked_count,
            "blacklist_size": len(self._blacklist),
            "whitelist_size": len(self._whitelist)
        }