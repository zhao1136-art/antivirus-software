"""
御天 注册表监控模块

阻止恶意程序篡改启动项、服务等注册表关键位置。
"""
import os
import sys
import time
import json
import threading
import subprocess
from datetime import datetime
from collections import defaultdict

IS_WINDOWS = sys.platform == 'win32'

DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data"
)
LOG_FILE = os.path.join(DATA_DIR, "logs", "registry_guard.log")

# 监控的注册表关键路径
MONITORED_KEYS = [
    # 启动项
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    # 服务
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    # Shell 扩展
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions",
    # 浏览器辅助对象
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    # 策略
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
    # App Paths
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
    # 映像劫持
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    # Winlogon
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
]

# 已知恶意注册表值特征
SUSPICIOUS_VALUE_PATTERNS = [
    "temp\\", "tmp\\", "appdata\\roaming\\",
    "malware", "trojan", "backdoor", "downloader",
    ".vbs", ".js", ".ps1", ".bat",
]


class RegistryGuard:
    """注册表监控"""

    def __init__(self):
        self._enabled = False
        self._running = False
        self._stop_event = threading.Event()
        self._snapshots: dict[str, str] = {}  # key -> value snapshot
        self._changes_detected: list[dict] = []
        self._blocked_count = 0
        self._lock = threading.Lock()
        self._auto_restore = True
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
        self._log("注册表监控已启用")
        if not self._running:
            self._start()

    def disable(self):
        self._enabled = False
        self._log("注册表监控已禁用")

    def _start(self):
        self._running = True
        self._stop_event.clear()
        # 初始化快照
        self._take_snapshot()
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()

    def stop(self):
        self._enabled = False
        self._stop_event.set()
        self._running = False

    def _reg_query(self, key_path: str) -> dict[str, str]:
        """查询注册表键下的所有值"""
        result: dict[str, str] = {}
        try:
            r = subprocess.run(
                ["reg", "query", key_path],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if r.returncode == 0:
                for line in r.stdout.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("HKEY") and not line.startswith(""):
                        parts = line.split("    ") if "    " in line else line.split("\t")
                        if len(parts) >= 2:
                            name = parts[0].strip()
                            value = parts[-1].strip()
                            result[name] = value
        except Exception:
            pass
        return result

    def _take_snapshot(self):
        """对所有监控键创建快照"""
        with self._lock:
            self._snapshots.clear()
            for key in MONITORED_KEYS:
                values = self._reg_query(key)
                if values:
                    self._snapshots[key] = json.dumps(values, sort_keys=True)

    def _monitor_loop(self):
        """轮询检测注册表变更"""
        while not self._stop_event.is_set():
            if not self._enabled:
                self._stop_event.wait(5)
                continue
            try:
                for key in MONITORED_KEYS:
                    current = self._reg_query(key)
                    current_str = json.dumps(current, sort_keys=True)
                    prev_str = self._snapshots.get(key, "{}")

                    if current_str != prev_str:
                        # 检测变更
                        try:
                            prev_dict = json.loads(prev_str) if prev_str != "{}" else {}
                        except json.JSONDecodeError:
                            prev_dict = {}

                        added = {k: v for k, v in current.items() if k not in prev_dict}
                        removed = {k: v for k, v in prev_dict.items() if k not in current}
                        modified = {k: v for k, v in current.items()
                                    if k in prev_dict and prev_dict[k] != v}

                        change = {
                            "time": datetime.now().isoformat(),
                            "key": key,
                            "added": added,
                            "removed": removed,
                            "modified": modified,
                            "suspicious": False
                        }

                        # 检查是否可疑
                        all_values = list(added.values()) + list(modified.values())
                        for val in all_values:
                            val_lower = val.lower()
                            for pattern in SUSPICIOUS_VALUE_PATTERNS:
                                if pattern in val_lower:
                                    change["suspicious"] = True
                                    break

                        with self._lock:
                            self._changes_detected.insert(0, change)
                            if len(self._changes_detected) > 100:
                                self._changes_detected = self._changes_detected[:100]

                        if change["suspicious"]:
                            self._blocked_count += 1
                            self._log(f"检测到可疑注册表变更: {key} - {added}")
                            # 自动恢复
                            if self._auto_restore:
                                self._restore_key(key, prev_dict)

                        # 更新快照
                        self._snapshots[key] = current_str

            except Exception:
                pass
            self._stop_event.wait(10)  # 每 10 秒检查一次

    def _restore_key(self, key: str, target: dict[str, str]):
        """恢复注册表键到目标状态"""
        try:
            # 删除多余的值
            current = self._reg_query(key)
            for name in current:
                if name not in target:
                    subprocess.run(
                        ["reg", "delete", key, "/v", name, "/f"],
                        capture_output=True, text=True, timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
            # 添加缺失的值
            for name, value in target.items():
                if name not in current:
                    subprocess.run(
                        ["reg", "add", key, "/v", name, "/t", "REG_SZ", "/d", value, "/f"],
                        capture_output=True, text=True, timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
            self._log(f"已自动恢复注册表: {key}")
        except Exception as e:
            self._log(f"恢复注册表失败: {key} - {e}")

    def set_auto_restore(self, enabled: bool):
        self._auto_restore = enabled

    def get_changes(self) -> list[dict]:
        with self._lock:
            return list(self._changes_detected[:30])

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self._enabled,
                "blocked_count": self._blocked_count,
                "monitored_keys": len(MONITORED_KEYS),
                "changes_count": len(self._changes_detected),
                "auto_restore": self._auto_restore
            }

    def get_status(self) -> dict:
        return {
            "enabled": self._enabled,
            "running": self._running,
            "blocked_total": self._blocked_count,
            "auto_restore": self._auto_restore,
            "monitored_keys_count": len(MONITORED_KEYS)
        }