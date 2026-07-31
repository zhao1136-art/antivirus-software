"""
系统文件防篡改模块 - 监控关键系统文件的完整性

功能：
1. 关键系统文件基线建立（SHA256 哈希）
2. 文件完整性定期校验（检测内容修改、替换）
3. 文件存在性监控（检测删除/移动）
4. 新文件创建监控（在受保护目录中）
5. 文件保护事件记录与告警
6. 支持自定义受保护文件/目录列表
"""
import os
import sys
import time
import json
import hashlib
import threading
import shutil
from datetime import datetime
from collections import deque

# ---------- 日志路径 ----------

_file_guard_log = None

def _get_log_path():
    global _file_guard_log
    if _file_guard_log is None:
        try:
            from config import LOGS_DIR
            _file_guard_log = os.path.join(LOGS_DIR, "file_guard.log")
        except Exception:
            _file_guard_log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "logs", "file_guard.log")
    return _file_guard_log


def _log_event(event: dict):
    """写入文件保护日志"""
    entry = {"timestamp": datetime.now().isoformat(), **event}
    path = _get_log_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ---------- 哈希工具 ----------

def compute_file_hash(path: str) -> str | None:
    """计算文件的 SHA256 哈希"""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None
    except Exception:
        return None


def get_file_size(path: str) -> int:
    """获取文件大小"""
    try:
        return os.path.getsize(path)
    except Exception:
        return 0


def get_file_mtime(path: str) -> str:
    """获取文件最后修改时间"""
    try:
        return datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
    except Exception:
        return ""


# ---------- 默认受保护文件列表 ----------

def _get_default_protected_files() -> list[str]:
    """获取默认受保护的系统关键文件"""
    sys_dir = os.environ.get("SystemRoot", r"C:\Windows")
    sys32 = os.path.join(sys_dir, "System32")
    drivers = os.path.join(sys32, "drivers")

    files = [
        # 系统核心文件
        os.path.join(sys_dir, "explorer.exe"),
        os.path.join(sys_dir, "regedit.exe"),
        os.path.join(sys32, "kernel32.dll"),
        os.path.join(sys32, "ntdll.dll"),
        os.path.join(sys32, "user32.dll"),
        os.path.join(sys32, "advapi32.dll"),
        os.path.join(sys32, "gdi32.dll"),
        os.path.join(sys32, "ws2_32.dll"),
        os.path.join(sys32, "crypt32.dll"),
        os.path.join(sys32, "wintrust.dll"),
        os.path.join(sys32, "ole32.dll"),
        os.path.join(sys32, "shell32.dll"),
        os.path.join(sys32, "msvcrt.dll"),
        os.path.join(sys32, "rpcrt4.dll"),
        os.path.join(sys32, "secur32.dll"),
        os.path.join(sys32, "samlib.dll"),
        os.path.join(sys32, "netapi32.dll"),
        os.path.join(sys32, "iphlpapi.dll"),
        os.path.join(sys32, "dnsapi.dll"),
        os.path.join(sys32, "psapi.dll"),
        os.path.join(sys32, "dbghelp.dll"),
        os.path.join(sys32, "wininet.dll"),
        os.path.join(sys32, "urlmon.dll"),
        os.path.join(sys32, "msxml3.dll"),
        # 安全相关
        os.path.join(sys32, "lsass.exe"),
        os.path.join(sys32, "csrss.exe"),
        os.path.join(sys32, "svchost.exe"),
        os.path.join(sys32, "services.exe"),
        os.path.join(sys32, "winlogon.exe"),
        os.path.join(sys32, "smss.exe"),
        os.path.join(sys32, "wininit.exe"),
        os.path.join(sys32, "dwm.exe"),
        # 驱动目录
        os.path.join(drivers, "etc", "hosts"),
        os.path.join(drivers, "etc", "networks"),
        os.path.join(drivers, "etc", "services"),
        os.path.join(drivers, "etc", "protocol"),
    ]

    # 过滤掉不存在的文件
    return [f for f in files if os.path.isfile(f)]


def _get_default_protected_dirs() -> list[str]:
    """获取默认受保护的目录"""
    sys_dir = os.environ.get("SystemRoot", r"C:\Windows")
    sys32 = os.path.join(sys_dir, "System32")

    dirs = [
        os.path.join(sys32, "drivers"),
        os.path.join(sys_dir, "System32"),
    ]
    return [d for d in dirs if os.path.isdir(d)]


# ---------- 文件保护引擎 ----------

class FileGuard:
    """系统文件防篡改引擎"""

    def __init__(self):
        self._enabled = True
        self._monitor_thread = None
        self._running = False
        self._lock = threading.Lock()

        # 受保护文件列表
        self._protected_files: list[str] = _get_default_protected_files()
        # 受保护目录列表
        self._protected_dirs: list[str] = _get_default_protected_dirs()

        # 文件基线 {path: {"hash": str, "size": int, "mtime": str}}
        self._baseline: dict[str, dict] = {}

        # 事件队列
        self._events: deque = deque(maxlen=200)

        # 扫描间隔（秒）
        self._scan_interval = 10

    # ---------- 状态管理 ----------

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self):
        self._enabled = True
        self.start()
        self._add_event("info", "文件防篡改已启用")

    def disable(self):
        self._enabled = False
        self.stop()
        self._add_event("info", "文件防篡改已禁用")

    def get_status(self) -> dict:
        """获取保护状态"""
        return {
            "enabled": self._enabled,
            "running": self._running,
            "protected_files_count": len(self._protected_files),
            "protected_dirs_count": len(self._protected_dirs),
            "baseline_count": len(self._baseline),
            "scan_interval": self._scan_interval,
            "recent_events": list(self._events),
        }

    # ---------- 受保护文件管理 ----------

    def add_file(self, path: str) -> dict:
        """添加受保护文件"""
        path = os.path.normpath(path)
        if not os.path.isfile(path):
            return {"success": False, "error": "文件不存在"}
        if path in self._protected_files:
            return {"success": False, "error": "文件已在保护列表中"}
        self._protected_files.append(path)
        self._add_event("info", f"已添加受保护文件: {path}")
        return {"success": True, "file": path}

    def remove_file(self, path: str) -> dict:
        """移除受保护文件"""
        path = os.path.normpath(path)
        self._protected_files = [f for f in self._protected_files if f != path]
        self._baseline.pop(path, None)
        self._add_event("info", f"已移除受保护文件: {path}")
        return {"success": True, "removed": path}

    def add_dir(self, path: str) -> dict:
        """添加受保护目录"""
        path = os.path.normpath(path)
        if not os.path.isdir(path):
            return {"success": False, "error": "目录不存在"}
        if path in self._protected_dirs:
            return {"success": False, "error": "目录已在保护列表中"}
        self._protected_dirs.append(path)
        self._add_event("info", f"已添加受保护目录: {path}")
        return {"success": True, "dir": path}

    def remove_dir(self, path: str) -> dict:
        """移除受保护目录"""
        path = os.path.normpath(path)
        self._protected_dirs = [d for d in self._protected_dirs if d != path]
        self._add_event("info", f"已移除受保护目录: {path}")
        return {"success": True, "removed": path}

    def list_protected(self) -> dict:
        """列出所有受保护的文件和目录"""
        files = []
        for f in self._protected_files:
            info = self._baseline.get(f, {})
            files.append({
                "path": f,
                "hash": info.get("hash", "")[:16] + "..." if info.get("hash") else "",
                "size": info.get("size", 0),
                "baseline_set": f in self._baseline,
            })
        return {
            "files": files,
            "dirs": list(self._protected_dirs),
        }

    # ---------- 基线管理 ----------

    def build_baseline(self) -> dict:
        """建立文件完整性基线"""
        count = 0
        errors = 0

        for f in self._protected_files:
            if os.path.isfile(f):
                h = compute_file_hash(f)
                if h:
                    self._baseline[f] = {
                        "hash": h,
                        "size": get_file_size(f),
                        "mtime": get_file_mtime(f),
                    }
                    count += 1
                else:
                    errors += 1

        # 对受保护目录下的关键文件也建立基线
        for d in self._protected_dirs:
            try:
                for entry in os.listdir(d):
                    full_path = os.path.join(d, entry)
                    if os.path.isfile(full_path) and full_path not in self._baseline:
                        h = compute_file_hash(full_path)
                        if h:
                            self._baseline[full_path] = {
                                "hash": h,
                                "size": get_file_size(full_path),
                                "mtime": get_file_mtime(full_path),
                            }
                            count += 1
            except (PermissionError, OSError):
                pass

        self._add_event("info", f"文件基线已建立，共 {count} 个文件")
        return {"success": True, "baseline_count": count, "errors": errors}

    # ---------- 监控核心 ----------

    def start(self):
        """启动监控线程"""
        if self._running:
            return
        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop(self):
        """停止监控"""
        self._running = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=3)

    def _monitor_loop(self):
        """监控主循环"""
        # 初始建立基线
        if not self._baseline:
            self.build_baseline()

        while self._running:
            try:
                self._check_files()
            except Exception as e:
                self._add_event("error", f"文件监控异常: {e}")
            time.sleep(self._scan_interval)

    def _check_files(self):
        """检查所有受保护文件的完整性"""
        issues = []

        for path, baseline_info in list(self._baseline.items()):
            # 1. 检测文件被删除
            if not os.path.isfile(path):
                self._add_event("critical", f"受保护文件被删除: {path}")
                _log_event({
                    "type": "protected_file_deleted",
                    "file": path,
                    "level": "critical",
                    "message": f"受保护文件被删除: {path}"
                })
                issues.append({"path": path, "issue": "deleted"})
                continue

            # 2. 检测文件大小变化
            current_size = get_file_size(path)
            if current_size != baseline_info["size"]:
                self._add_event("warning", f"文件大小变化: {path} ({baseline_info['size']} → {current_size})")
                _log_event({
                    "type": "file_size_changed",
                    "file": path,
                    "old_size": baseline_info["size"],
                    "new_size": current_size,
                    "level": "warning",
                    "message": f"文件大小变化: {path}"
                })
                issues.append({"path": path, "issue": "size_changed"})

            # 3. 检测文件修改时间变化
            current_mtime = get_file_mtime(path)
            if current_mtime != baseline_info["mtime"]:
                # 修改时间变了，重新计算哈希
                current_hash = compute_file_hash(path)
                if current_hash and current_hash != baseline_info["hash"]:
                    self._add_event("critical", f"文件内容被篡改: {path}")
                    _log_event({
                        "type": "file_tampered",
                        "file": path,
                        "old_hash": baseline_info["hash"],
                        "new_hash": current_hash,
                        "old_size": baseline_info["size"],
                        "new_size": current_size,
                        "level": "critical",
                        "message": f"文件内容被篡改: {path}"
                    })
                    issues.append({"path": path, "issue": "tampered"})

                    # 更新基线（防止重复告警）
                    self._baseline[path] = {
                        "hash": current_hash,
                        "size": current_size,
                        "mtime": current_mtime,
                    }
                elif current_hash:
                    # 修改时间变了但哈希没变，更新基线
                    self._baseline[path]["mtime"] = current_mtime

        # 4. 检测受保护目录中的新文件
        for d in self._protected_dirs:
            try:
                for entry in os.listdir(d):
                    full_path = os.path.join(d, entry)
                    if os.path.isfile(full_path) and full_path not in self._baseline:
                        h = compute_file_hash(full_path)
                        if h:
                            self._add_event("warning", f"受保护目录新增文件: {full_path}")
                            _log_event({
                                "type": "new_file_in_protected_dir",
                                "file": full_path,
                                "level": "warning",
                                "message": f"受保护目录新增文件: {full_path}"
                            })
                            # 将新文件加入基线
                            self._baseline[full_path] = {
                                "hash": h,
                                "size": get_file_size(full_path),
                                "mtime": get_file_mtime(full_path),
                            }
            except (PermissionError, OSError):
                pass

        return issues

    # ---------- 事件管理 ----------

    def _add_event(self, level: str, message: str):
        """添加事件到队列"""
        event = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        }
        with self._lock:
            self._events.append(event)

    def get_events(self, limit: int = 50) -> list[dict]:
        """获取最近事件"""
        with self._lock:
            return list(self._events)[-limit:]

    # ---------- 手动扫描 ----------

    def verify_file(self, path: str) -> dict:
        """手动验证单个文件完整性"""
        path = os.path.normpath(path)
        if not os.path.isfile(path):
            return {"error": "文件不存在", "path": path}

        current_hash = compute_file_hash(path)
        baseline = self._baseline.get(path)

        result = {
            "path": path,
            "current_hash": current_hash,
            "current_size": get_file_size(path),
            "current_mtime": get_file_mtime(path),
            "has_baseline": baseline is not None,
            "is_tampered": False,
            "issues": [],
        }

        if baseline:
            result["baseline_hash"] = baseline["hash"]
            result["baseline_size"] = baseline["size"]
            result["baseline_mtime"] = baseline["mtime"]

            if current_hash != baseline["hash"]:
                result["is_tampered"] = True
                result["issues"].append("文件内容哈希不匹配 - 疑似篡改")
            if result["current_size"] != baseline["size"]:
                result["issues"].append(f"文件大小变化: {baseline['size']} → {result['current_size']}")
        else:
            result["issues"].append("文件未在保护列表中，无基线数据")

        return result

    def rebaseline_file(self, path: str) -> dict:
        """重新建立单个文件基线"""
        path = os.path.normpath(path)
        if not os.path.isfile(path):
            return {"success": False, "error": "文件不存在"}

        h = compute_file_hash(path)
        if not h:
            return {"success": False, "error": "无法读取文件"}

        self._baseline[path] = {
            "hash": h,
            "size": get_file_size(path),
            "mtime": get_file_mtime(path),
        }

        if path not in self._protected_files:
            self._protected_files.append(path)

        self._add_event("info", f"文件基线已重建: {path}")
        return {"success": True, "path": path, "hash": h}
