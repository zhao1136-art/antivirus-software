"""
御天内核驱动通信桥接模块

通过 ctypes 调用 Windows API 与内核驱动 andun.sys 通信：
  - CreateFileW 打开驱动设备句柄
  - DeviceIoControl 发送 IOCTL
  - 事件轮询线程每秒读取驱动事件队列

所有 IOCTL 码、数据结构、事件类型均与 backend/driver/andun_driver/andun.h 中的定义保持一致。
驱动未安装时 connect() 返回 False，模块进入降级模式，不影响其他模块运行。
"""

import ctypes
import ctypes.wintypes as wt
import threading
import time
import datetime
from typing import Callable, Optional


# ============================================================
# Windows API 常量
# ============================================================

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
FILE_ATTRIBUTE_NORMAL = 0x80
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0


# ============================================================
# IOCTL 码计算（与 andun.h 中 CTL_CODE 宏一致）
# ============================================================

def _ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    """模拟 Windows 的 CTL_CODE 宏：
       CTL_CODE(DeviceType, Function, Method, Access) =
           (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
    """
    return (device_type << 16) | (access << 14) | (function << 2) | method


ANDUN_IOCTL_BASE = 0x8000

# IOCTL 控制码（与 andun.h 完全一致）
IOCTL_ANDUN_GET_EVENTS = _ctl_code(ANDUN_IOCTL_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_ADD_RULE = _ctl_code(ANDUN_IOCTL_BASE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_DEL_RULE = _ctl_code(ANDUN_IOCTL_BASE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_CLEAR_RULES = _ctl_code(ANDUN_IOCTL_BASE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_SET_CONFIG = _ctl_code(ANDUN_IOCTL_BASE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_GET_CONFIG = _ctl_code(ANDUN_IOCTL_BASE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_PROTECT_PID = _ctl_code(ANDUN_IOCTL_BASE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_UNPROTECT_PID = _ctl_code(ANDUN_IOCTL_BASE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_ROOTKIT_SCAN = _ctl_code(ANDUN_IOCTL_BASE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_GET_STATS = _ctl_code(ANDUN_IOCTL_BASE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

# 自保护 IOCTL（0x80A-0x80D）
IOCTL_ANDUN_SELFPROTECT_PROCESS = _ctl_code(ANDUN_IOCTL_BASE, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_SELFPROTECT_FILE = _ctl_code(ANDUN_IOCTL_BASE, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_SELFPROTECT_REGISTRY = _ctl_code(ANDUN_IOCTL_BASE, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_SELFPROTECT_SERVICE = _ctl_code(ANDUN_IOCTL_BASE, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)

# 处置响应 IOCTL（0x80E-0x810）
IOCTL_ANDUN_RESPONSE_KILL_PROCESS = _ctl_code(ANDUN_IOCTL_BASE, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_RESPONSE_QUARANTINE_FILE = _ctl_code(ANDUN_IOCTL_BASE, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_RESPONSE_BLOCK_RULE = _ctl_code(ANDUN_IOCTL_BASE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ANDUN_GET_VERSION = _ctl_code(ANDUN_IOCTL_BASE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)


# ============================================================
# 事件类型枚举（对应 andun.h 中 ANDUN_EVENT_TYPE）
# ============================================================

class AndunEventType:
    EventFileCreate = 1
    EventFileWrite = 2
    EventFileDelete = 3
    EventProcessCreate = 4
    EventProcessTerminate = 5
    EventRegistrySet = 6
    EventRegistryDelete = 7
    EventNetworkConnect = 8
    EventHandleOpen = 9
    EventDriverLoad = 10
    EventRootkitDetected = 11


# 动作枚举（对应 andun.h 中 ANDUN_ACTION）
class AndunAction:
    ActionAllow = 0
    ActionBlock = 1
    ActionAsk = 2


# 规则类型枚举（对应 andun.h 中 ANDUN_RULE_TYPE）
class AndunRuleType:
    RuleTypeFile = 0
    RuleTypeProcess = 1
    RuleTypeRegistry = 2
    RuleTypeNetwork = 3
    RuleTypeHandle = 4


# ============================================================
# ctypes 结构体定义（与 andun.h 中的 C 结构体一一对应）
# ============================================================

# andun.h 使用 #pragma pack(push, 1)，这里也要按 1 字节对齐
class ANDUN_EVENT(ctypes.Structure):
    """驱动事件结构（推送给用户态）

    对应 andun.h 中的 _ANDUN_EVENT：
        ULONG       eventType;          // ANDUN_EVENT_TYPE
        ULONG       pid;
        ULONG       ppid;
        WCHAR       processName[260];
        WCHAR       processPath[520];
        WCHAR       targetPath[520];
        WCHAR       remoteAddr[46];
        USHORT      remotePort;
        ULONG       action;
        LARGE_INTEGER timestamp;
    """
    _pack_ = 1
    _fields_ = [
        ("eventType", ctypes.c_ulong),
        ("pid", ctypes.c_ulong),
        ("ppid", ctypes.c_ulong),
        ("processName", ctypes.c_wchar * 260),
        ("processPath", ctypes.c_wchar * 520),
        ("targetPath", ctypes.c_wchar * 520),
        ("remoteAddr", ctypes.c_wchar * 46),
        ("remotePort", ctypes.c_ushort),
        ("action", ctypes.c_ulong),
        ("timestamp", ctypes.c_longlong),  # LARGE_INTEGER 用 c_longlong 表示
    ]


class ANDUN_RULE(ctypes.Structure):
    """拦截规则结构（用户态下发）

    对应 andun.h 中的 _ANDUN_RULE：
        ULONG       ruleId;
        ULONG       ruleType;
        ULONG       action;
        WCHAR       pattern[ANDUN_MAX_PATTERN_LEN];  // 520
        ULONG       enabled;
    """
    _pack_ = 1
    _fields_ = [
        ("ruleId", ctypes.c_ulong),
        ("ruleType", ctypes.c_ulong),
        ("action", ctypes.c_ulong),
        ("pattern", ctypes.c_wchar * 520),
        ("enabled", ctypes.c_ulong),
    ]


class ANDUN_CONFIG(ctypes.Structure):
    """配置结构（6 个 ULONG 字段）

    对应 andun.h 中的 _ANDUN_CONFIG。
    """
    _pack_ = 1
    _fields_ = [
        ("fileFilterEnabled", ctypes.c_ulong),
        ("networkFilterEnabled", ctypes.c_ulong),
        ("processCallbackEnabled", ctypes.c_ulong),
        ("registryCallbackEnabled", ctypes.c_ulong),
        ("objectCallbackEnabled", ctypes.c_ulong),
        ("rootkitScanEnabled", ctypes.c_ulong),
    ]


class ANDUN_STATS(ctypes.Structure):
    """统计信息结构

    对应 andun.h 中的 _ANDUN_STATS：
        8 个 ULONG64 + 2 个 ULONG。
    """
    _pack_ = 1
    _fields_ = [
        ("totalEvents", ctypes.c_ulonglong),
        ("blockedEvents", ctypes.c_ulonglong),
        ("fileOperations", ctypes.c_ulonglong),
        ("processOperations", ctypes.c_ulonglong),
        ("registryOperations", ctypes.c_ulonglong),
        ("networkOperations", ctypes.c_ulonglong),
        ("handleOperations", ctypes.c_ulonglong),
        ("droppedEvents", ctypes.c_ulonglong),
        ("activeRules", ctypes.c_ulong),
        ("protectedPids", ctypes.c_ulong),
    ]


class ANDUN_PID_REQUEST(ctypes.Structure):
    """PID 保护请求结构

    对应 andun.h 中的 _ANDUN_PID_REQUEST。
    """
    _pack_ = 1
    _fields_ = [
        ("pid", ctypes.c_ulong),
    ]


# ============================================================
# Rootkit 扫描结果结构（对应 andun.h 中的 _ANDUN_ROOTKIT_*）
# ============================================================

class ANDUN_ROOTKIT_PROC_ENTRY(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("pid", ctypes.c_ulong),
        ("ppid", ctypes.c_ulong),
        ("name", ctypes.c_wchar * 260),
        ("image_path", ctypes.c_wchar * 520),
    ]


class ANDUN_ROOTKIT_DRIVER_ENTRY(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("name", ctypes.c_wchar * 260),
        ("base_address", ctypes.c_ulonglong),
        ("size", ctypes.c_ulonglong),
        ("section_unloaded", ctypes.c_ulong),
    ]


class ANDUN_ROOTKIT_HOOK_ENTRY(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("hook_type", ctypes.c_ulong),
        ("function_name", ctypes.c_wchar * 128),
        ("hook_address", ctypes.c_ulonglong),
        ("original_bytes", ctypes.c_ubyte * 16),
        ("current_bytes", ctypes.c_ubyte * 16),
        ("driver_name", ctypes.c_wchar * 260),
        ("severity", ctypes.c_ulong),
    ]


class ANDUN_ROOTKIT_CALLBACK_ENTRY(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("callback_type", ctypes.c_ulong),
        ("callback_address", ctypes.c_ulonglong),
        ("driver_name", ctypes.c_wchar * 260),
        ("is_trusted", ctypes.c_ulong),
        ("severity", ctypes.c_ulong),
    ]


class ANDUN_ROOTKIT_SCAN_RESULT(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("proc_count", ctypes.c_ulong),
        ("driver_count", ctypes.c_ulong),
        ("hook_count", ctypes.c_ulong),
        ("callback_count", ctypes.c_ulong),
        ("procs", ANDUN_ROOTKIT_PROC_ENTRY * 256),
        ("drivers", ANDUN_ROOTKIT_DRIVER_ENTRY * 64),
        ("hooks", ANDUN_ROOTKIT_HOOK_ENTRY * 32),
        ("callbacks", ANDUN_ROOTKIT_CALLBACK_ENTRY * 32),
    ]


# ============================================================
# 自保护配置结构（对应 andun.h 中的 _ANDUN_SELFPROTECT_*）
# ============================================================

class ANDUN_SELFPROTECT_PROCESS_CFG(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("agent_pid", ctypes.c_ulong),
        ("protect_enabled", ctypes.c_ulong),
    ]


class ANDUN_SELFPROTECT_FILE_CFG(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("install_dir", ctypes.c_wchar * 520),
        ("protect_enabled", ctypes.c_ulong),
    ]


class ANDUN_SELFPROTECT_REGISTRY_CFG(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("key_path", ctypes.c_wchar * 520),
        ("protect_enabled", ctypes.c_ulong),
    ]


class ANDUN_SELFPROTECT_SERVICE_CFG(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("service_name", ctypes.c_wchar * 260),
        ("protect_enabled", ctypes.c_ulong),
    ]


# ============================================================
# 处置响应结构（对应 andun.h 中的 _ANDUN_RESPONSE_*）
# ============================================================

class ANDUN_RESPONSE_KILL_PROCESS(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("target_pid", ctypes.c_ulong),
        ("force", ctypes.c_ulong),
    ]


class ANDUN_RESPONSE_QUARANTINE_FILE(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("file_path", ctypes.c_wchar * 520),
        ("quarantine_dir", ctypes.c_wchar * 520),
    ]


class ANDUN_RESPONSE_BLOCK_RULE(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("rule", ANDUN_RULE),
        ("auto_remove_sec", ctypes.c_ulong),
    ]


# 一次从驱动读取的最大事件数量（与 EventQueuePop 的 MaxCount 对应）
MAX_EVENTS_PER_READ = 32


# ============================================================
# Windows API 函数原型
# ============================================================

# CreateFileW
ctypes.windll.kernel32.CreateFileW.argtypes = [
    ctypes.c_wchar_p, wt.DWORD, wt.DWORD, ctypes.c_void_p,
    wt.DWORD, wt.DWORD, wt.HANDLE
]
ctypes.windll.kernel32.CreateFileW.restype = wt.HANDLE

# CloseHandle
ctypes.windll.kernel32.CloseHandle.argtypes = [wt.HANDLE]
ctypes.windll.kernel32.CloseHandle.restype = wt.BOOL

# DeviceIoControl
ctypes.windll.kernel32.DeviceIoControl.argtypes = [
    wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD,
    ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p
]
ctypes.windll.kernel32.DeviceIoControl.restype = wt.BOOL


# ============================================================
# KernelBridge 主类
# ============================================================

class KernelBridge:
    """御天内核驱动通信桥接

    通过 ctypes 调用 Windows API 与内核驱动 andun.sys 通信：
      - CreateFileW 打开驱动设备句柄
      - DeviceIoControl 发送 IOCTL
      - 事件轮询线程每秒读取驱动事件队列
    """

    DEVICE_PATH = r"\\.\AndunDriver"

    # 暴露 IOCTL 码，方便外部引用
    IOCTL_GET_EVENTS = IOCTL_ANDUN_GET_EVENTS
    IOCTL_ADD_RULE = IOCTL_ANDUN_ADD_RULE
    IOCTL_DEL_RULE = IOCTL_ANDUN_DEL_RULE
    IOCTL_CLEAR_RULES = IOCTL_ANDUN_CLEAR_RULES
    IOCTL_SET_CONFIG = IOCTL_ANDUN_SET_CONFIG
    IOCTL_GET_CONFIG = IOCTL_ANDUN_GET_CONFIG
    IOCTL_PROTECT_PID = IOCTL_ANDUN_PROTECT_PID
    IOCTL_UNPROTECT_PID = IOCTL_ANDUN_UNPROTECT_PID
    IOCTL_ROOTKIT_SCAN = IOCTL_ANDUN_ROOTKIT_SCAN
    IOCTL_GET_STATS = IOCTL_ANDUN_GET_STATS
    IOCTL_SELFPROTECT_PROCESS = IOCTL_ANDUN_SELFPROTECT_PROCESS
    IOCTL_SELFPROTECT_FILE = IOCTL_ANDUN_SELFPROTECT_FILE
    IOCTL_SELFPROTECT_REGISTRY = IOCTL_ANDUN_SELFPROTECT_REGISTRY
    IOCTL_SELFPROTECT_SERVICE = IOCTL_ANDUN_SELFPROTECT_SERVICE
    IOCTL_RESPONSE_KILL_PROCESS = IOCTL_ANDUN_RESPONSE_KILL_PROCESS
    IOCTL_RESPONSE_QUARANTINE_FILE = IOCTL_ANDUN_RESPONSE_QUARANTINE_FILE
    IOCTL_RESPONSE_BLOCK_RULE = IOCTL_ANDUN_RESPONSE_BLOCK_RULE
    IOCTL_GET_VERSION = IOCTL_ANDUN_GET_VERSION

    def __init__(self):
        self._handle = None
        self._lock = threading.Lock()
        # 事件处理器表：event_type -> list[callable]
        self._handlers: dict[int, list[Callable[[dict], None]]] = {}
        self._handlers_lock = threading.Lock()
        # 事件轮询线程控制
        self._stop_event = threading.Event()
        self._poll_thread: Optional[threading.Thread] = None
        self._poll_interval = 1.0  # 轮询间隔（秒）

    # ---------------------- 连接管理 ----------------------

    def connect(self) -> bool:
        """打开驱动设备句柄。

        成功返回 True；失败（驱动未安装/设备不可访问）返回 False，
        不抛出异常，便于上层进入降级模式。
        """
        with self._lock:
            if self._handle is not None and self._handle != INVALID_HANDLE_VALUE:
                return True
            try:
                handle = ctypes.windll.kernel32.CreateFileW(
                    self.DEVICE_PATH,
                    GENERIC_READ | GENERIC_WRITE,
                    0,                       # 不共享
                    None,                    # 默认安全属性
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,                    # 无模板文件
                )
            except (FileNotFoundError, OSError):
                self._handle = None
                return False
            except Exception:
                self._handle = None
                return False

            if handle == INVALID_HANDLE_VALUE or handle is None:
                self._handle = None
                return False

            self._handle = handle
            return True

    def disconnect(self) -> None:
        """关闭驱动设备句柄。"""
        # 先停止事件轮询
        self.stop_event_loop()
        with self._lock:
            if self._handle is not None and self._handle != INVALID_HANDLE_VALUE:
                try:
                    ctypes.windll.kernel32.CloseHandle(self._handle)
                except Exception:
                    pass
            self._handle = None

    def is_connected(self) -> bool:
        """返回当前是否已连接到驱动。"""
        return self._handle is not None and self._handle != INVALID_HANDLE_VALUE

    def is_driver_ready(self) -> dict:
        """
        完整的驱动就绪检查（供上层模块调用前判断，避免静默失效）。
        
        检查项：
        1. 驱动句柄是否有效
        2. 驱动是否响应（IOCTL 版本查询）
        3. 返回就绪状态 + 版本号 + 诊断信息
        
        :returns: {ready: bool, version: str|None, reason: str, connected: bool}
        """
        if not self.is_connected():
            return {"ready": False, "version": None, "reason": "驱动未连接（句柄无效）", "connected": False}

        # 尝试获取驱动版本号（通过 IOCTL 版本查询验证驱动是否响应）
        try:
            version_buf = (ctypes.c_ubyte * 64)()
            ok, ret = self._ioctl(
                self.IOCTL_ANDUN_GET_VERSION,
                out_buffer=ctypes.byref(version_buf),
                out_size=ctypes.sizeof(version_buf),
            )
            if ok and ret > 0:
                version = ctypes.string_at(version_buf, ret).decode("utf-8", errors="replace").strip("\x00")
                return {"ready": True, "version": version, "reason": "驱动正常响应", "connected": True}
            else:
                return {"ready": False, "version": None,
                        "reason": f"驱动无响应（IOCTL 返回 ok={ok}, ret={ret}）", "connected": True}
        except Exception as e:
            return {"ready": False, "version": None,
                    "reason": f"驱动通信异常: {e}", "connected": True}

    # ---------------------- 内部 IOCTL 封装 ----------------------

    def _ioctl(self, ioctl_code: int, in_buffer=None, in_size: int = 0,
               out_buffer=None, out_size: int = 0) -> tuple[bool, int]:
        """统一的 DeviceIoControl 调用。

        返回 (是否成功, 实际返回字节数)。
        若驱动未连接，直接返回 (False, 0)。
        """
        if not self.is_connected():
            return False, 0

        returned = wt.DWORD(0)
        in_ptr = ctypes.cast(in_buffer, ctypes.c_void_p) if in_buffer is not None else None
        out_ptr = ctypes.cast(out_buffer, ctypes.c_void_p) if out_buffer is not None else None

        try:
            ok = ctypes.windll.kernel32.DeviceIoControl(
                self._handle,
                ioctl_code,
                in_ptr, in_size,
                out_ptr, out_size,
                ctypes.byref(returned),
                None,  # 同步调用，无 overlapped
            )
        except Exception:
            return False, 0

        return bool(ok), returned.value

    # ---------------------- 事件读取 ----------------------

    @staticmethod
    def _filetime_to_unix(filetime: int) -> float:
        """将 Windows FILETIME（1601-01-01 起的 100ns 计数）转换为 Unix 时间戳（秒）。"""
        if filetime <= 0:
            return 0.0
        # 116444736000000000 = 1601-01-01 到 1970-01-01 的 100ns 计数
        unix_100ns = filetime - 116444736000000000
        if unix_100ns < 0:
            return 0.0
        return unix_100ns / 10000000.0

    @staticmethod
    def _filetime_to_datetime(filetime: int) -> Optional[datetime.datetime]:
        """将 Windows FILETIME 转换为本地时间 datetime。"""
        ts = KernelBridge._filetime_to_unix(filetime)
        if ts <= 0:
            return None
        try:
            return datetime.datetime.fromtimestamp(ts)
        except (OSError, ValueError, OverflowError):
            return None

    @staticmethod
    def _event_to_dict(event: ANDUN_EVENT) -> dict:
        """将 ANDUN_EVENT 结构体转换为字典，便于上层使用。"""
        ts_raw = event.timestamp
        return {
            "eventType": int(event.eventType),
            "pid": int(event.pid),
            "ppid": int(event.ppid),
            "processName": event.processName.rstrip("\x00"),
            "processPath": event.processPath.rstrip("\x00"),
            "targetPath": event.targetPath.rstrip("\x00"),
            "remoteAddr": event.remoteAddr.rstrip("\x00"),
            "remotePort": int(event.remotePort),
            "action": int(event.action),
            "timestampRaw": int(ts_raw),
            "timestampUnix": KernelBridge._filetime_to_unix(ts_raw),
            "timestamp": KernelBridge._filetime_to_datetime(ts_raw),
        }

    def get_events(self) -> list:
        """从驱动事件队列中读取事件，返回 dict 列表。

        一次最多读取 MAX_EVENTS_PER_READ 个事件。
        驱动未连接或读取失败时返回空列表。
        """
        if not self.is_connected():
            return []

        # 输出缓冲区：ANDUN_EVENT * MAX_EVENTS_PER_READ
        EventArray = ANDUN_EVENT * MAX_EVENTS_PER_READ
        out_buf = EventArray()
        out_size = ctypes.sizeof(out_buf)

        ok, returned = self._ioctl(
            self.IOCTL_GET_EVENTS,
            in_buffer=None, in_size=0,
            out_buffer=out_buf, out_size=out_size,
        )

        if not ok:
            return []

        # 实际返回的事件数
        count = returned // ctypes.sizeof(ANDUN_EVENT)
        if count > MAX_EVENTS_PER_READ:
            count = MAX_EVENTS_PER_READ

        events = []
        for i in range(count):
            try:
                events.append(self._event_to_dict(out_buf[i]))
            except Exception:
                continue
        return events

    # ---------------------- 规则管理 ----------------------

    def add_rule(self, rule: dict) -> bool:
        """下发一条拦截规则。

        rule 字段：ruleId, ruleType, action, pattern, enabled。
        """
        if not self.is_connected():
            return False

        try:
            r = ANDUN_RULE()
            r.ruleId = int(rule.get("ruleId", 0))
            r.ruleType = int(rule.get("ruleType", 0))
            r.action = int(rule.get("action", 0))
            pattern = str(rule.get("pattern", ""))
            # 截断到 519 字符，留 1 个结尾 \0
            if len(pattern) >= 520:
                pattern = pattern[:519]
            r.pattern = pattern
            r.enabled = 1 if rule.get("enabled", True) else 0
        except Exception:
            return False

        ok, _ = self._ioctl(
            self.IOCTL_ADD_RULE,
            in_buffer=ctypes.byref(r), in_size=ctypes.sizeof(r),
            out_buffer=None, out_size=0,
        )
        return ok

    def del_rule(self, rule_id: int) -> bool:
        """删除一条规则（按 ruleId）。"""
        if not self.is_connected():
            return False

        # IOCTL_DEL_RULE 通常需要 ruleId 作为输入，这里使用 ULONG 作为输入缓冲
        rule_id_val = ctypes.c_ulong(int(rule_id))
        ok, _ = self._ioctl(
            self.IOCTL_DEL_RULE,
            in_buffer=ctypes.byref(rule_id_val), in_size=ctypes.sizeof(rule_id_val),
            out_buffer=None, out_size=0,
        )
        return ok

    def clear_rules(self) -> bool:
        """清空所有规则。"""
        if not self.is_connected():
            return False
        ok, _ = self._ioctl(
            self.IOCTL_CLEAR_RULES,
            in_buffer=None, in_size=0,
            out_buffer=None, out_size=0,
        )
        return ok

    # ---------------------- 配置管理 ----------------------

    def set_config(self, config: dict) -> bool:
        """下发驱动配置。

        config 字段对应 ANDUN_CONFIG 的 6 个布尔开关。
        """
        if not self.is_connected():
            return False

        try:
            cfg = ANDUN_CONFIG()
            cfg.fileFilterEnabled = 1 if config.get("fileFilterEnabled", False) else 0
            cfg.networkFilterEnabled = 1 if config.get("networkFilterEnabled", False) else 0
            cfg.processCallbackEnabled = 1 if config.get("processCallbackEnabled", False) else 0
            cfg.registryCallbackEnabled = 1 if config.get("registryCallbackEnabled", False) else 0
            cfg.objectCallbackEnabled = 1 if config.get("objectCallbackEnabled", False) else 0
            cfg.rootkitScanEnabled = 1 if config.get("rootkitScanEnabled", False) else 0
        except Exception:
            return False

        ok, _ = self._ioctl(
            self.IOCTL_SET_CONFIG,
            in_buffer=ctypes.byref(cfg), in_size=ctypes.sizeof(cfg),
            out_buffer=None, out_size=0,
        )
        return ok

    def get_config(self) -> dict:
        """读取驱动当前配置。"""
        if not self.is_connected():
            return {}

        cfg = ANDUN_CONFIG()
        ok, _ = self._ioctl(
            self.IOCTL_GET_CONFIG,
            in_buffer=None, in_size=0,
            out_buffer=ctypes.byref(cfg), out_size=ctypes.sizeof(cfg),
        )
        if not ok:
            return {}

        return {
            "fileFilterEnabled": bool(cfg.fileFilterEnabled),
            "networkFilterEnabled": bool(cfg.networkFilterEnabled),
            "processCallbackEnabled": bool(cfg.processCallbackEnabled),
            "registryCallbackEnabled": bool(cfg.registryCallbackEnabled),
            "objectCallbackEnabled": bool(cfg.objectCallbackEnabled),
            "rootkitScanEnabled": bool(cfg.rootkitScanEnabled),
        }

    # ---------------------- PID 保护 ----------------------

    def protect_pid(self, pid: int) -> bool:
        """将指定 PID 加入受保护列表（防止被句柄操作）。"""
        if not self.is_connected():
            return False

        req = ANDUN_PID_REQUEST()
        req.pid = int(pid)
        ok, _ = self._ioctl(
            self.IOCTL_PROTECT_PID,
            in_buffer=ctypes.byref(req), in_size=ctypes.sizeof(req),
            out_buffer=None, out_size=0,
        )
        return ok

    def unprotect_pid(self, pid: int) -> bool:
        """将指定 PID 从受保护列表移除。"""
        if not self.is_connected():
            return False

        req = ANDUN_PID_REQUEST()
        req.pid = int(pid)
        ok, _ = self._ioctl(
            self.IOCTL_UNPROTECT_PID,
            in_buffer=ctypes.byref(req), in_size=ctypes.sizeof(req),
            out_buffer=None, out_size=0,
        )
        return ok

    # ---------------------- 统计 & Rootkit 扫描 ----------------------

    def get_stats(self) -> dict:
        """读取驱动统计信息。"""
        if not self.is_connected():
            return {}

        stats = ANDUN_STATS()
        ok, _ = self._ioctl(
            self.IOCTL_GET_STATS,
            in_buffer=None, in_size=0,
            out_buffer=ctypes.byref(stats), out_size=ctypes.sizeof(stats),
        )
        if not ok:
            return {}

        return {
            "totalEvents": int(stats.totalEvents),
            "blockedEvents": int(stats.blockedEvents),
            "fileOperations": int(stats.fileOperations),
            "processOperations": int(stats.processOperations),
            "registryOperations": int(stats.registryOperations),
            "networkOperations": int(stats.networkOperations),
            "handleOperations": int(stats.handleOperations),
            "droppedEvents": int(stats.droppedEvents),
            "activeRules": int(stats.activeRules),
            "protectedPids": int(stats.protectedPids),
        }

    def rootkit_scan(self) -> bool:
        """触发一次 Rootkit 扫描（触发型，结果需通过 rootkit_scan_full 获取）。"""
        if not self.is_connected():
            return False
        ok, _ = self._ioctl(
            self.IOCTL_ROOTKIT_SCAN,
            in_buffer=None, in_size=0,
            out_buffer=None, out_size=0,
        )
        return ok

    def rootkit_scan_full(self) -> dict:
        """执行完整 Rootkit 扫描并获取四维结果。

        返回:
            {
                "ok": bool,
                "procs": [{pid, ppid, name}],
                "drivers": [{name, base_address, size, section_unloaded}],
                "hooks": [{hook_type, function_name, hook_address, driver_name,
                           original_bytes, current_bytes, severity}],
                "callbacks": [{callback_type, callback_address, driver_name,
                               is_trusted, severity}],
            }
        """
        if not self.is_connected():
            return {"ok": False, "error": "driver not connected"}

        result = ANDUN_ROOTKIT_SCAN_RESULT()
        ok, _ = self._ioctl(
            self.IOCTL_ROOTKIT_SCAN,
            in_buffer=None, in_size=0,
            out_buffer=ctypes.byref(result), out_size=ctypes.sizeof(result),
        )
        if not ok:
            return {"ok": False, "error": "IOCTL failed"}

        # 进程
        procs = []
        for i in range(min(result.proc_count, 256)):
            p = result.procs[i]
            if p.pid == 0:
                continue
            procs.append({
                "pid": int(p.pid),
                "ppid": int(p.ppid),
                "name": p.name.rstrip("\x00"),
                "image_path": p.image_path.rstrip("\x00"),
            })

        # 驱动
        drivers = []
        for i in range(min(result.driver_count, 64)):
            d = result.drivers[i]
            if d.name[0] == "\x00":
                continue
            drivers.append({
                "name": d.name.rstrip("\x00"),
                "base_address": int(d.base_address),
                "base_address_hex": hex(d.base_address),
                "size": int(d.size),
                "section_unloaded": bool(d.section_unloaded),
            })

        # 钩子
        hooks = []
        for i in range(min(result.hook_count, 32)):
            h = result.hooks[i]
            if h.function_name[0] == "\x00":
                continue
            hook_type_name = {0: "SSDT", 1: "IRP", 2: "Inline"}.get(h.hook_type, "Unknown")
            hooks.append({
                "hook_type": hook_type_name,
                "function_name": h.function_name.rstrip("\x00"),
                "hook_address": int(h.hook_address),
                "hook_address_hex": hex(h.hook_address),
                "driver_name": h.driver_name.rstrip("\x00"),
                "original_bytes": " ".join(f"{b:02x}" for b in h.original_bytes[:8]),
                "current_bytes": " ".join(f"{b:02x}" for b in h.current_bytes[:8]),
                "severity": int(h.severity),
            })

        # 回调
        callbacks = []
        for i in range(min(result.callback_count, 32)):
            c = result.callbacks[i]
            if c.callback_address == 0:
                continue
            cb_type_name = {0: "Process", 1: "Thread", 2: "Image",
                            3: "Registry", 4: "Object"}.get(c.callback_type, "Unknown")
            callbacks.append({
                "callback_type": cb_type_name,
                "callback_address": int(c.callback_address),
                "callback_address_hex": hex(c.callback_address),
                "driver_name": c.driver_name.rstrip("\x00"),
                "is_trusted": bool(c.is_trusted),
                "severity": int(c.severity),
            })

        return {
            "ok": True,
            "proc_count": int(result.proc_count),
            "driver_count": int(result.driver_count),
            "hook_count": int(result.hook_count),
            "callback_count": int(result.callback_count),
            "procs": procs,
            "drivers": drivers,
            "hooks": hooks,
            "callbacks": callbacks,
        }

    # ---------------------- 自保护配置 ----------------------

    def set_selfprotect_process(self, agent_pid: int, enabled: bool = True) -> bool:
        """配置进程自保护：保护 agent 进程 PID。"""
        if not self.is_connected():
            return False
        cfg = ANDUN_SELFPROTECT_PROCESS_CFG()
        cfg.agent_pid = int(agent_pid)
        cfg.protect_enabled = 1 if enabled else 0
        ok, _ = self._ioctl(
            self.IOCTL_SELFPROTECT_PROCESS,
            in_buffer=ctypes.byref(cfg), in_size=ctypes.sizeof(cfg),
            out_buffer=None, out_size=0,
        )
        return ok

    def set_selfprotect_file(self, install_dir: str, enabled: bool = True) -> bool:
        """配置文件自保护：保护安装目录。"""
        if not self.is_connected():
            return False
        cfg = ANDUN_SELFPROTECT_FILE_CFG()
        if len(install_dir) >= 520:
            install_dir = install_dir[:519]
        cfg.install_dir = install_dir
        cfg.protect_enabled = 1 if enabled else 0
        ok, _ = self._ioctl(
            self.IOCTL_SELFPROTECT_FILE,
            in_buffer=ctypes.byref(cfg), in_size=ctypes.sizeof(cfg),
            out_buffer=None, out_size=0,
        )
        return ok

    def set_selfprotect_registry(self, key_path: str, enabled: bool = True) -> bool:
        """配置注册表自保护。"""
        if not self.is_connected():
            return False
        cfg = ANDUN_SELFPROTECT_REGISTRY_CFG()
        if len(key_path) >= 520:
            key_path = key_path[:519]
        cfg.key_path = key_path
        cfg.protect_enabled = 1 if enabled else 0
        ok, _ = self._ioctl(
            self.IOCTL_SELFPROTECT_REGISTRY,
            in_buffer=ctypes.byref(cfg), in_size=ctypes.sizeof(cfg),
            out_buffer=None, out_size=0,
        )
        return ok

    def set_selfprotect_service(self, service_name: str, enabled: bool = True) -> bool:
        """配置服务自保护。"""
        if not self.is_connected():
            return False
        cfg = ANDUN_SELFPROTECT_SERVICE_CFG()
        if len(service_name) >= 260:
            service_name = service_name[:259]
        cfg.service_name = service_name
        cfg.protect_enabled = 1 if enabled else 0
        ok, _ = self._ioctl(
            self.IOCTL_SELFPROTECT_SERVICE,
            in_buffer=ctypes.byref(cfg), in_size=ctypes.sizeof(cfg),
            out_buffer=None, out_size=0,
        )
        return ok

    # ---------------------- 处置响应 ----------------------

    def response_kill_process(self, target_pid: int, force: bool = False) -> bool:
        """处置：终止进程。"""
        if not self.is_connected():
            return False
        req = ANDUN_RESPONSE_KILL_PROCESS()
        req.target_pid = int(target_pid)
        req.force = 1 if force else 0
        ok, _ = self._ioctl(
            self.IOCTL_RESPONSE_KILL_PROCESS,
            in_buffer=ctypes.byref(req), in_size=ctypes.sizeof(req),
            out_buffer=None, out_size=0,
        )
        return ok

    def response_quarantine_file(self, file_path: str, quarantine_dir: str = "") -> bool:
        """处置：隔离文件。"""
        if not self.is_connected():
            return False
        req = ANDUN_RESPONSE_QUARANTINE_FILE()
        if len(file_path) >= 520:
            file_path = file_path[:519]
        if len(quarantine_dir) >= 520:
            quarantine_dir = quarantine_dir[:519]
        req.file_path = file_path
        req.quarantine_dir = quarantine_dir
        ok, _ = self._ioctl(
            self.IOCTL_RESPONSE_QUARANTINE_FILE,
            in_buffer=ctypes.byref(req), in_size=ctypes.sizeof(req),
            out_buffer=None, out_size=0,
        )
        return ok

    def response_block_rule(self, rule: dict, auto_remove_sec: int = 0) -> bool:
        """处置：下发即时拦截规则。

        rule 字段与 add_rule 相同（ruleId/ruleType/action/pattern/enabled）。
        """
        if not self.is_connected():
            return False

        req = ANDUN_RESPONSE_BLOCK_RULE()
        req.rule.ruleId = int(rule.get("ruleId", 0))
        req.rule.ruleType = int(rule.get("ruleType", 0))
        req.rule.action = int(rule.get("action", 0))
        pattern = str(rule.get("pattern", ""))
        if len(pattern) >= 520:
            pattern = pattern[:519]
        req.rule.pattern = pattern
        req.rule.enabled = 1 if rule.get("enabled", True) else 0
        req.auto_remove_sec = int(auto_remove_sec)

        ok, _ = self._ioctl(
            self.IOCTL_RESPONSE_BLOCK_RULE,
            in_buffer=ctypes.byref(req), in_size=ctypes.sizeof(req),
            out_buffer=None, out_size=0,
        )
        return ok

    # ---------------------- 事件轮询线程 ----------------------

    def register_handler(self, event_type: int, handler: Callable[[dict], None]) -> None:
        """注册事件处理器。

        event_type 对应 ANDUN_EVENT_TYPE 枚举值；
        handler 接收一个 dict 参数（事件字典）。
        同一 event_type 可注册多个处理器，按注册顺序调用。
        """
        if not callable(handler):
            return
        with self._handlers_lock:
            self._handlers.setdefault(event_type, []).append(handler)

    def unregister_handler(self, event_type: int, handler: Callable[[dict], None]) -> bool:
        """取消注册事件处理器，成功返回 True。"""
        with self._handlers_lock:
            lst = self._handlers.get(event_type)
            if not lst:
                return False
            try:
                lst.remove(handler)
                return True
            except ValueError:
                return False

    def _dispatch_event(self, event: dict) -> None:
        """将单个事件分发给已注册的处理器。"""
        etype = event.get("eventType", 0)
        with self._handlers_lock:
            handlers = list(self._handlers.get(etype, []))
        for h in handlers:
            try:
                h(event)
            except Exception:
                # 处理器异常不影响其他处理器和轮询线程
                pass

    def _poll_loop(self) -> None:
        """事件轮询线程主循环：每秒读取一次事件并分发。"""
        while not self._stop_event.is_set():
            try:
                events = self.get_events()
                for ev in events:
                    self._dispatch_event(ev)
            except Exception:
                # 任何异常都不应让轮询线程退出
                pass

            # 用 wait 替代 sleep，便于及时响应停止信号
            self._stop_event.wait(self._poll_interval)

    def start_event_loop(self) -> bool:
        """启动事件轮询守护线程。

        返回 True 表示已启动或正在运行；False 表示驱动未连接无法启动。
        """
        if not self.is_connected():
            return False
        if self._poll_thread is not None and self._poll_thread.is_alive():
            return True

        self._stop_event.clear()
        t = threading.Thread(target=self._poll_loop, name="AndunEventPoller", daemon=True)
        t.start()
        self._poll_thread = t
        return True

    def stop_event_loop(self) -> None:
        """停止事件轮询线程。"""
        self._stop_event.set()
        t = self._poll_thread
        if t is not None and t.is_alive():
            t.join(timeout=2.0)
        self._poll_thread = None

    # ---------------------- 上下文管理器支持 ----------------------

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False


# ============================================================
# 单例模式
# ============================================================

_kernel_bridge: Optional[KernelBridge] = None
_bridge_lock = threading.Lock()


def get_kernel_bridge() -> KernelBridge:
    """获取全局唯一的 KernelBridge 实例（双重检查锁定单例）。"""
    global _kernel_bridge
    if _kernel_bridge is None:
        with _bridge_lock:
            if _kernel_bridge is None:
                _kernel_bridge = KernelBridge()
    return _kernel_bridge


# ============================================================
# 模块自检（直接运行时执行）
# ============================================================

if __name__ == "__main__":
    bridge = get_kernel_bridge()
    if bridge.connect():
        print("[kernel_bridge] 已连接到 andun.sys 驱动")
        print("[kernel_bridge] 当前配置:", bridge.get_config())
        print("[kernel_bridge] 统计信息:", bridge.get_stats())
        bridge.disconnect()
    else:
        print("[kernel_bridge] 未能连接到 andun.sys 驱动（可能未安装），进入降级模式")
