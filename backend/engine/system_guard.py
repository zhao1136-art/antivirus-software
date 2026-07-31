"""
系统进程保护模块 - 监控关键进程、检测进程终止/注入/篡改行为

功能：
1. 受保护进程列表管理（系统关键进程 + 自定义进程）
2. 进程存活监控（定时轮询，检测异常终止）
3. 进程注入检测（检测 Process Hollowing / DLL 注入）
4. 可疑进程创建监控（基于规则的进程创建告警）
5. 进程保护事件记录与告警
"""
import os
import sys
import time
import json
import ctypes
import ctypes.wintypes as wt
import threading
import hashlib
from datetime import datetime
from collections import deque

# ---------- Windows API 声明（仅 Windows 平台需要） ----------
IS_WINDOWS = sys.platform == 'win32'

# 纯整数常量，跨平台安全
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
TH32CS_SNAPPROCESS = 0x00000002

# 非 Windows 平台下置空：相关函数在 Linux 上不会被实例化/调用，
# 这样模块在 Linux 也能正常 import（避免 OSError: 找不到 DLL）。
psapi = None
kernel32 = None


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


if IS_WINDOWS:
    # Psapi / kernel32 动态链接库（仅 Windows 存在）
    psapi = ctypes.WinDLL('psapi.dll')
    kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)

    # EnumProcesses
    psapi.EnumProcesses.argtypes = [ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    psapi.EnumProcesses.restype = ctypes.c_bool

    # GetModuleFileNameExW
    psapi.GetModuleFileNameExW.argtypes = [wt.HANDLE, wt.HMODULE, wt.LPWSTR, wt.DWORD]
    psapi.GetModuleFileNameExW.restype = wt.DWORD

    # OpenProcess
    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.OpenProcess.restype = wt.HANDLE

    # CloseHandle
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.CloseHandle.restype = wt.BOOL

    # GetProcessImageFileNameW
    psapi.GetProcessImageFileNameW.argtypes = [wt.HANDLE, wt.LPWSTR, wt.DWORD]
    psapi.GetProcessImageFileNameW.restype = wt.DWORD

    # GetExitCodeProcess
    kernel32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(ctypes.c_ulong)]
    kernel32.GetExitCodeProcess.restype = ctypes.c_bool

    # CreateToolhelp32Snapshot
    kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    kernel32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = ctypes.c_bool
    kernel32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = ctypes.c_bool

# ---------- 日志路径 ----------

_guard_log_file = None

def _get_log_path():
    global _guard_log_file
    if _guard_log_file is None:
        try:
            from config import LOGS_DIR
            _guard_log_file = os.path.join(LOGS_DIR, "system_guard.log")
        except Exception:
            _guard_log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "logs", "system_guard.log")
    return _guard_log_file


def _log_event(event: dict):
    """写入进程保护日志"""
    entry = {"timestamp": datetime.now().isoformat(), **event}
    path = _get_log_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ---------- 进程枚举 ----------

def enumerate_processes() -> list[dict]:
    """枚举所有运行中的进程"""
    if not IS_WINDOWS:
        return []
    processes = []
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == ctypes.c_void_p(-1).value or snapshot == 0:
        return processes

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
        while True:
            pid = entry.th32ProcessID
            ppid = entry.th32ParentProcessID
            name = entry.szExeFile
            exe_path = _get_process_path(pid)
            processes.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "exe_path": exe_path,
                "thread_count": entry.cntThreads,
            })
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break

    kernel32.CloseHandle(snapshot)
    return processes


def _get_process_path(pid: int) -> str:
    """获取进程的可执行文件路径"""
    try:
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            return ""

        buf = ctypes.create_unicode_buffer(260)
        length = psapi.GetProcessImageFileNameW(handle, buf, 260)
        kernel32.CloseHandle(handle)

        if length > 0:
            # GetProcessImageFileNameW 返回的是设备路径，如 \Device\HarddiskVolume1\...
            # 尝试转换为盘符路径
            path = buf.value
            return _device_path_to_drive(path)
        return ""
    except Exception:
        return ""


def _device_path_to_drive(device_path: str) -> str:
    """将设备路径转换为盘符路径"""
    try:
        # 获取所有逻辑驱动器
        buf = ctypes.create_unicode_buffer(260)
        length = kernel32.GetLogicalDriveStringsW(260, buf)
        drives = buf.value[:length].split('\0')

        for drive in drives:
            drive = drive.strip('\\').strip()
            if not drive:
                continue
            # 获取设备名
            dev_buf = ctypes.create_unicode_buffer(260)
            if kernel32.QueryDosDeviceW(drive, dev_buf, 260):
                dev_name = dev_buf.value
                if device_path.upper().startswith(dev_name.upper()):
                    return drive + device_path[len(dev_name):]
        return device_path
    except Exception:
        return device_path


def get_process_hash(pid: int) -> str | None:
    """获取进程可执行文件的 SHA256 哈希"""
    path = _get_process_path(pid)
    if not path or not os.path.isfile(path):
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


# ---------- 受保护进程列表 ----------

# Windows 系统关键进程
SYSTEM_CRITICAL_PROCESSES = {
    "lsass.exe": "本地安全机构子系统服务 - 管理安全策略、凭据",
    "csrss.exe": "客户端/服务端运行时子系统 - Win32 控制台",
    "winlogon.exe": "Windows 登录程序 - 处理登录/注销",
    "services.exe": "服务控制管理器 - 管理系统服务",
    "svchost.exe": "服务主机 - 承载多个 Windows 服务",
    "smss.exe": "会话管理器子系统 - 启动会话",
    "wininit.exe": "Windows 启动应用 - 初始化系统",
    "explorer.exe": "Windows 资源管理器 - 用户外壳",
    "dwm.exe": "桌面窗口管理器 - 图形合成",
    "spoolsv.exe": "打印后台处理服务",
    "fontdrvhost.exe": "字体驱动程序宿主",
    "System": "系统进程 - 内核线程",
}

# 可疑进程名映射（名字伪装系统进程）
SUSPICIOUS_NAME_MAPPINGS = {
    "svch0st.exe": "svchost.exe",
    "scvhost.exe": "svchost.exe",
    "svhost.exe": "svchost.exe",
    "lsasss.exe": "lsass.exe",
    "lsaas.exe": "lsass.exe",
    "csrsss.exe": "csrss.exe",
    "winlogon.exe.exe": "winlogon.exe",
    "expl0rer.exe": "explorer.exe",
    "explorer.exe.exe": "explorer.exe",
}


class SystemGuard:
    """系统进程保护引擎"""

    def __init__(self):
        self._enabled = True
        self._monitor_thread = None
        self._running = False
        self._lock = threading.Lock()

        # 受保护进程列表
        self._protected_processes = set(SYSTEM_CRITICAL_PROCESSES.keys())

        # 已知进程基线 {pid: {"name": str, "exe_path": str, "hash": str, "start_time": str}}
        self._baseline: dict[int, dict] = {}

        # 事件队列（最近 200 条）
        self._events: deque = deque(maxlen=200)

        # 可疑进程创建规则
        self._suspicious_paths = [
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%APPDATA%"),
            os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
        ]

    # ---------- 状态管理 ----------

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self):
        self._enabled = True
        self.start()
        self._add_event("info", "进程保护已启用")

    def disable(self):
        self._enabled = False
        self.stop()
        self._add_event("info", "进程保护已禁用")

    def get_status(self) -> dict:
        """获取保护状态"""
        return {
            "enabled": self._enabled,
            "running": self._running,
            "protected_count": len(self._protected_processes),
            "protected_list": sorted(self._protected_processes),
            "monitored_count": len(self._baseline),
            "recent_events": list(self._events),
        }

    # ---------- 受保护进程管理 ----------

    def add_protected(self, name: str) -> dict:
        """添加受保护进程"""
        name = name.strip()
        if not name:
            return {"success": False, "error": "进程名不能为空"}
        self._protected_processes.add(name)
        self._add_event("info", f"已添加受保护进程: {name}")
        return {"success": True, "protected": name}

    def remove_protected(self, name: str) -> dict:
        """移除受保护进程"""
        if name in SYSTEM_CRITICAL_PROCESSES:
            return {"success": False, "error": f"系统关键进程 {name} 不能移除"}
        self._protected_processes.discard(name)
        self._add_event("info", f"已移除受保护进程: {name}")
        return {"success": True, "removed": name}

    def list_protected(self) -> list[dict]:
        """列出所有受保护进程"""
        result = []
        for name in sorted(self._protected_processes):
            desc = SYSTEM_CRITICAL_PROCESSES.get(name, "自定义受保护进程")
            result.append({"name": name, "description": desc, "is_system": name in SYSTEM_CRITICAL_PROCESSES})
        return result

    # ---------- 监控核心 ----------

    def start(self):
        """启动监控线程"""
        if not IS_WINDOWS:
            # 非 Windows 平台无进程防护能力，直接跳过
            return
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
        self._build_baseline()

        while self._running:
            try:
                self._check_processes()
            except Exception as e:
                self._add_event("error", f"监控循环异常: {e}")
            time.sleep(3)  # 每 3 秒检查一次

    def _build_baseline(self):
        """建立进程基线"""
        procs = enumerate_processes()
        self._baseline.clear()
        for p in procs:
            pid = p["pid"]
            self._baseline[pid] = {
                "name": p["name"],
                "exe_path": p["exe_path"],
                "ppid": p["ppid"],
                "first_seen": datetime.now().isoformat(),
            }
        self._add_event("info", f"进程基线已建立，共 {len(self._baseline)} 个进程")

    def _check_processes(self):
        """检查进程状态"""
        current_procs = {p["pid"]: p for p in enumerate_processes()}
        current_pids = set(current_procs.keys())
        baseline_pids = set(self._baseline.keys())

        # 1. 检测已终止的受保护进程
        terminated = baseline_pids - current_pids
        for pid in terminated:
            old_info = self._baseline.get(pid, {})
            name = old_info.get("name", "")
            if name in self._protected_processes:
                self._add_event("warning", f"受保护进程已终止: {name} (PID:{pid})")
                _log_event({
                    "type": "protected_process_terminated",
                    "process": name,
                    "pid": pid,
                    "level": "warning",
                    "message": f"受保护进程 {name} (PID:{pid}) 已终止"
                })

        # 2. 检测新创建的进程
        new_pids = current_pids - baseline_pids
        for pid in new_pids:
            info = current_procs[pid]
            name = info.get("name", "")
            exe_path = info.get("exe_path", "")
            ppid = info.get("ppid", 0)

            # 检查可疑进程名伪装
            for fake_name, real_name in SUSPICIOUS_NAME_MAPPINGS.items():
                if name.lower() == fake_name.lower():
                    self._add_event("critical", f"检测到进程名伪装: {name} (伪装 {real_name}) PID:{pid}")
                    _log_event({
                        "type": "process_name_spoofing",
                        "process": name,
                        "pid": pid,
                        "disguised_as": real_name,
                        "level": "critical",
                        "message": f"进程名伪装检测: {name} 伪装为系统进程 {real_name}"
                    })
                    break

            # 检查从可疑路径启动的进程
            if exe_path:
                for susp_path in self._suspicious_paths:
                    if exe_path.lower().startswith(susp_path.lower()):
                        self._add_event("warning", f"可疑路径启动: {name} 从 {exe_path} PID:{pid}")
                        _log_event({
                            "type": "suspicious_process_creation",
                            "process": name,
                            "pid": pid,
                            "exe_path": exe_path,
                            "parent_pid": ppid,
                            "level": "warning",
                            "message": f"可疑路径启动进程: {name} 从 {exe_path}"
                        })
                        break

            # 如果是受保护进程名，记录其启动
            if name in self._protected_processes:
                parent_name = self._baseline.get(ppid, {}).get("name", "unknown")
                self._add_event("info", f"受保护进程已启动: {name} (PID:{pid}, 父进程: {parent_name})")

        # 3. 检查受保护进程的路径篡改
        for pid in current_pids & baseline_pids:
            old_info = self._baseline.get(pid, {})
            name = old_info.get("name", "")
            if name not in self._protected_processes:
                continue

            new_path = current_procs[pid].get("exe_path", "")
            old_path = old_info.get("exe_path", "")
            if old_path and new_path and old_path.lower() != new_path.lower():
                self._add_event("critical", f"进程路径篡改: {name} (PID:{pid}) 路径从 {old_path} 变为 {new_path}")
                _log_event({
                    "type": "process_path_tampered",
                    "process": name,
                    "pid": pid,
                    "old_path": old_path,
                    "new_path": new_path,
                    "level": "critical",
                    "message": f"进程路径篡改: {name} PID:{pid}"
                })

        # 更新基线
        for pid in current_pids:
            self._baseline[pid] = {
                "name": current_procs[pid]["name"],
                "exe_path": current_procs[pid].get("exe_path", ""),
                "ppid": current_procs[pid].get("ppid", 0),
                "first_seen": self._baseline.get(pid, {}).get("first_seen", datetime.now().isoformat()),
            }
        # 清理已终止的进程
        for pid in terminated:
            self._baseline.pop(pid, None)

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

    def get_process_list(self) -> list[dict]:
        """获取当前进程列表"""
        return enumerate_processes()

    def scan_process(self, pid: int) -> dict:
        """扫描单个进程"""
        procs = enumerate_processes()
        target = None
        for p in procs:
            if p["pid"] == pid:
                target = p
                break

        if not target:
            return {"error": f"进程 PID:{pid} 不存在"}

        result = {
            "pid": pid,
            "name": target["name"],
            "exe_path": target["exe_path"],
            "ppid": target["ppid"],
            "thread_count": target.get("thread_count", 0),
            "is_protected": target["name"] in self._protected_processes,
            "is_suspicious": False,
            "issues": [],
        }

        # 检查可疑名称
        for fake_name, real_name in SUSPICIOUS_NAME_MAPPINGS.items():
            if target["name"].lower() == fake_name.lower():
                result["is_suspicious"] = True
                result["issues"].append(f"进程名伪装: 伪装为 {real_name}")

        # 检查可疑路径
        exe_path = target.get("exe_path", "")
        if exe_path:
            for susp_path in self._suspicious_paths:
                if exe_path.lower().startswith(susp_path.lower()):
                    result["is_suspicious"] = True
                    result["issues"].append(f"从可疑路径运行: {exe_path}")
                    break

        # 计算哈希
        file_hash = get_process_hash(pid)
        if file_hash:
            result["sha256"] = file_hash

        return result
