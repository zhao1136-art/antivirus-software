"""
御天 高危行为阻断模块

阻止删除卷影副本、关闭系统恢复等勒索前置操作。
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
LOG_FILE = os.path.join(DATA_DIR, "logs", "behavior_block.log")

# 高危命令特征
HIGH_RISK_COMMANDS = [
    # 卷影副本相关
    "vssadmin delete shadows",
    "vssadmin resize shadowstorage",
    "wmic shadowcopy delete",
    "diskshadow",
    # 系统恢复相关
    "bcdedit /set {default} recoveryenabled no",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "reagentc /disable",
    # 安全模式相关
    "bcdedit /set {default} safeboot",
    # 防火墙相关
    "netsh advfirewall set allprofiles state off",
    "netsh firewall set opmode disable",
    # Windows Defender 禁用
    "powershell set-mppreference -disablerealtimeMonitoring",
    "reg add \"hklm\\software\\policies\\microsoft\\windows defender\"",
    # 计划任务清除
    "schtasks /delete /tn",
    # 事件日志清除
    "wevtutil cl",
    "wevtutil clear-log",
]

# 高危进程名
HIGH_RISK_PROCESSES = [
    "vssadmin.exe", "wmic.exe", "diskshadow.exe",
    "bcdedit.exe", "reagentc.exe", "wevtutil.exe",
]


class BehaviorBlock:
    """高危行为阻断"""

    def __init__(self):
        self._enabled = False
        self._running = False
        self._stop_event = threading.Event()
        self._blocked_count = 0
        self._detected_actions: list[dict] = []
        self._lock = threading.Lock()
        self._monitor_processes = False
        self._monitor_logs = False
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
        self._log("高危行为阻断已启用")
        if not self._running:
            self._start()

    def disable(self):
        self._enabled = False
        self._log("高危行为阻断已禁用")

    def _start(self):
        self._running = True
        self._stop_event.clear()
        t1 = threading.Thread(target=self._process_monitor_loop, daemon=True)
        t1.start()
        t2 = threading.Thread(target=self._log_monitor_loop, daemon=True)
        t2.start()

    def stop(self):
        self._enabled = False
        self._stop_event.set()
        self._running = False

    def _process_monitor_loop(self):
        """监控高危进程启动"""
        if not IS_WINDOWS:
            return
        high_risk_set = set(p.lower() for p in HIGH_RISK_PROCESSES)
        known_pids: set[int] = set()

        while not self._stop_event.is_set():
            if not self._enabled:
                self._stop_event.wait(3)
                continue
            try:
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
                            if pid not in known_pids and name in high_risk_set:
                                # 获取命令行参数
                                cmdline = ""
                                try:
                                    r2 = subprocess.run(
                                        ["wmic", "process", "where", f"ProcessId={pid}",
                                         "get", "CommandLine"],
                                        capture_output=True, text=True, timeout=5,
                                        creationflags=subprocess.CREATE_NO_WINDOW
                                    )
                                    cmdline = r2.stdout.strip().split("\n")[-1].strip() if r2.stdout else ""
                                except Exception:
                                    pass
                                self._detect_high_risk_action(name, pid, cmdline)
                        except (ValueError, IndexError):
                            pass
                known_pids = current_pids
            except Exception:
                pass
            self._stop_event.wait(2)

    def _log_monitor_loop(self):
        """监控系统日志中的高危行为"""
        if not IS_WINDOWS:
            return
        while not self._stop_event.is_set():
            if not self._enabled:
                self._stop_event.wait(10)
                continue
            try:
                # 检查 VSS 服务状态
                r = subprocess.run(
                    ["sc", "query", "VSS"],
                    capture_output=True, text=True, timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if "STOPPED" in r.stdout:
                    self._log("检测到卷影复制服务 (VSS) 已停止")

                # 检查系统保护状态
                r2 = subprocess.run(
                    ["powershell", "-Command",
                     "(Get-WmiObject -Class Win32_ShadowCopy).Count"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if r2.stdout.strip() == "0":
                    self._log("检测到卷影副本数量为 0，可能已被清除")

            except Exception:
                pass
            self._stop_event.wait(30)

    def _detect_high_risk_action(self, proc_name: str, pid: int, cmdline: str):
        """检测并记录高危行为"""
        matched_command = ""
        for cmd in HIGH_RISK_COMMANDS:
            if cmd.lower() in cmdline.lower():
                matched_command = cmd
                break

        action = {
            "time": datetime.now().isoformat(),
            "process": proc_name,
            "pid": pid,
            "command": cmdline[:200] if cmdline else "",
            "matched_pattern": matched_command,
            "blocked": False
        }

        # 尝试终止进程
        if matched_command:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    capture_output=True, text=True, timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                action["blocked"] = True
                with self._lock:
                    self._blocked_count += 1
                self._log(f"已阻断高危行为: {proc_name} (PID: {pid}) - {matched_command}")
            except Exception:
                pass

        with self._lock:
            self._detected_actions.insert(0, action)
            if len(self._detected_actions) > 100:
                self._detected_actions = self._detected_actions[:100]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self._enabled,
                "blocked_count": self._blocked_count,
                "detected_count": len(self._detected_actions),
                "recent_actions": list(self._detected_actions[:20])
            }

    def get_status(self) -> dict:
        return {
            "enabled": self._enabled,
            "running": self._running,
            "blocked_total": self._blocked_count,
            "monitored_commands": len(HIGH_RISK_COMMANDS),
            "monitored_processes": len(HIGH_RISK_PROCESSES)
        }