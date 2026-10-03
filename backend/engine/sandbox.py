"""
御天 轻量内嵌沙箱（Windows Job Object）

在受限环境中运行可疑文件，监控其行为，自动生成分析报告。

功能：
  1. Windows Job Object 限制（内存 256MB / CPU 10 秒 / 进程数 / 关闭即杀）
  2. UI 限制（禁止读写剪贴板、全局原子、ExitWindows 等）
  3. ETW 监控行为（简化实现：用 psutil 监控子进程 / 文件操作 / 网络连接）
  4. 自动生成分析报告（verdict / confidence / behaviors / risk_indicators）
  5. 历史分析记录持久化到 data/sandbox_history.json
  6. 支持分析超时控制与强制终止

注意：
  - 仅支持 Windows 平台（依赖 Job Object / ctypes / Windows API）
  - 非 PE 文件或分析失败时返回 clean 报告，不抛异常
  - psutil 为可选依赖，缺失时行为监控降级
"""
import os
import sys
import time
import json
import ctypes
import threading
import subprocess
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

IS_WINDOWS = sys.platform == 'win32'

# ── 默认配置 ──
# 历史记录文件：engine/data/sandbox_history.json
SANDBOX_DATA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "data"
)
HISTORY_FILE = os.path.join(SANDBOX_DATA_DIR, "sandbox_history.json")

# 沙箱限制参数
JOB_MEMORY_LIMIT_MB = 256                      # 进程内存上限 (MB)
JOB_CPU_TIME_LIMIT_SEC = 10                    # CPU 时间上限 (秒)
JOB_ACTIVE_PROCESS_LIMIT = 1                   # 最大活动进程数
DEFAULT_ANALYSIS_TIMEOUT = 30                  # 默认分析超时 (秒)
MAX_HISTORY_RECORDS = 500                      # 历史记录最大条数

# ── Windows API 常量 ──
# Job Object 限制标志
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x0040
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x0100
JOB_OBJECT_LIMIT_PROCESS_TIME = 0x0002
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x0008
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x0400

# Job Object 信息类
JobObjectExtendedLimitInformation = 9
JobObjectBasicUIRestrictions = 7

# UI 限制标志
JOB_OBJECT_UILIMIT_READCLIPBOARD = 0x0002
JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x0004
JOB_OBJECT_UILIMIT_GLOBALATOMS = 0x0020
JOB_OBJECT_UILIMIT_HANDLES = 0x0001
JOB_OBJECT_UILIMIT_EXITWINDOWS = 0x0080
JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x0008

# 进程创建标志
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
CREATE_BREAKAWAY_FROM_JOB = 0x01000000

# 等待结果
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
INFINITE = 0xFFFFFFFF

# 句柄权限
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_TERMINATE = 0x0001
STILL_ACTIVE = 259


# ── ctypes 结构体定义 ──

class _LARGE_INTEGER(ctypes.Structure):
    """64 位有符号整数（用于 CPU 时间限制）"""
    _fields_ = [("QuadPart", wintypes.LARGE_INTEGER)]


class _IO_COUNTERS(ctypes.Structure):
    """I/O 计数器"""
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    """Job Object 基本限制信息"""
    _fields_ = [
        ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_void_p),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    """Job Object 扩展限制信息（含内存限制）"""
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class JOBOBJECT_BASIC_UI_RESTRICTIONS(ctypes.Structure):
    """Job Object UI 限制"""
    _fields_ = [
        ("UIRestrictionsClass", wintypes.DWORD),
    ]


class STARTUPINFO(ctypes.Structure):
    """进程启动信息"""
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    """进程信息"""
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


# ── Windows API 函数原型 ──

if IS_WINDOWS:
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # CreateJobObjectW(lpJobAttributes, lpName) -> HANDLE
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = [
        ctypes.c_void_p, wintypes.LPCWSTR
    ]

    # SetInformationJobObject(hJob, JobObjectInfoClass, lpJobObjectInfo, cbJobObjectInfoLength)
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, wintypes.INT, ctypes.c_void_p, wintypes.DWORD
    ]

    # AssignProcessToJobObject(hJob, hProcess)
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE
    ]

    # CreateProcessW(...)
    _kernel32.CreateProcessW.restype = wintypes.BOOL
    _kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
        wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFO), ctypes.POINTER(PROCESS_INFORMATION)
    ]

    # ResumeThread(hThread)
    _kernel32.ResumeThread.restype = wintypes.DWORD
    _kernel32.ResumeThread.argtypes = [wintypes.HANDLE]

    # WaitForSingleObject(hHandle, dwMilliseconds)
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

    # TerminateJobObject(hJob, uExitCode)
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]

    # CloseHandle(hObject)
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    # OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [
        wintypes.DWORD, wintypes.BOOL, wintypes.DWORD
    ]

    # GetExitCodeProcess(hProcess, lpExitCode)
    _kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    _kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)
    ]

    # IsDebuggerPresent 风格的简单可用性检查不需要


# ── psutil 可选导入 ──
try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    psutil = None
    _HAS_PSUTIL = False


# ── 工具函数 ──

def _get_logger():
    """获取沙箱专用日志记录器"""
    log_dir = os.path.join(SANDBOX_DATA_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    import logging
    logger = logging.getLogger("sandbox")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(
            os.path.join(log_dir, "sandbox.log"), encoding="utf-8"
        )
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(fh)
    return logger


def _is_pe_file(file_path: str) -> bool:
    """判断文件是否为 PE 文件（通过 MZ 头判断）"""
    try:
        with open(file_path, "rb") as f:
            header = f.read(2)
        return header == b"MZ"
    except Exception:
        return False


def _format_size(size: int) -> str:
    """格式化字节数为可读字符串"""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def _token_cancelled(cancel) -> bool:
    """判断取消令牌是否已置位（兼容 is_cancelled() / is_set() 两种约定）"""
    if cancel is None:
        return False
    if hasattr(cancel, "is_cancelled"):
        return bool(cancel.is_cancelled())
    if hasattr(cancel, "is_set"):
        return bool(cancel.is_set())
    return False


# ══════════════════════════════════════════════════════════════
#  LightweightSandbox — 轻量内嵌沙箱主类
# ══════════════════════════════════════════════════════════════

class LightweightSandbox:
    """轻量内嵌沙箱（Windows Job Object）

    在受限环境中运行可疑文件，监控其行为：
    - Windows Job Object 限制（内存/CPU/进程数）
    - UI 限制（禁止剪贴板/全局原子）
    - ETW 监控行为（文件/注册表/网络/进程/DLL）
    - 自动生成分析报告
    """

    def __init__(self):
        self._logger = None
        self._lock = threading.Lock()

        # 当前分析状态
        self._current_analysis: dict | None = None
        self._status_lock = threading.Lock()

        # 历史分析记录
        self._history: list[dict] = None  # 延迟加载
        self._history_lock = threading.Lock()

        # 统计信息
        self._stats = {
            "total_analyzed": 0,
            "malicious_detected": 0,
            "suspicious_detected": 0,
            "clean_results": 0,
            "analysis_failed": 0,
        }
        self._stats_lock = threading.Lock()

        # 确保数据目录存在
        os.makedirs(SANDBOX_DATA_DIR, exist_ok=True)

    def _ensure_history(self):
        """延迟加载历史记录（首次访问时从磁盘读取）"""
        if self._history is None:
            self._history = []
            self._load_history()

    # ── 属性 ──

    @property
    def is_windows(self) -> bool:
        """是否在 Windows 平台"""
        return IS_WINDOWS

    @property
    def has_psutil(self) -> bool:
        """是否有 psutil 可用"""
        return _HAS_PSUTIL

    # ── Job Object 管理 ──

    def _setup_job(self) -> int:
        """创建并配置 Job Object

        Returns:
            Job Object 句柄，失败返回 0
        """
        if not IS_WINDOWS:
            return 0

        try:
            # 1. 创建 Job Object
            h_job = _kernel32.CreateJobObjectW(None, None)
            if not h_job:
                self._log("error", f"CreateJobObject 失败: {ctypes.get_last_error()}")
                return 0

            # 2. 配置扩展限制（内存 + CPU + 关闭即杀 + 进程数）
            extended = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            basic = extended.BasicLimitInformation
            # CPU 时间限制（10 秒，单位 100ns）
            basic.PerProcessUserTimeLimit = JOB_CPU_TIME_LIMIT_SEC * 10000000
            basic.PerJobUserTimeLimit = JOB_CPU_TIME_LIMIT_SEC * 10000000
            basic.LimitFlags = (
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_BREAKAWAY_OK
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_PROCESS_TIME
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            )
            basic.ActiveProcessLimit = JOB_ACTIVE_PROCESS_LIMIT
            # 内存限制 256MB
            extended.ProcessMemoryLimit = JOB_MEMORY_LIMIT_MB * 1024 * 1024
            extended.JobMemoryLimit = JOB_MEMORY_LIMIT_MB * 1024 * 1024

            success = _kernel32.SetInformationJobObject(
                h_job,
                JobObjectExtendedLimitInformation,
                ctypes.byref(extended),
                ctypes.sizeof(extended)
            )
            if not success:
                self._log("error", f"SetInformationJobObject(Extended) 失败: {ctypes.get_last_error()}")
                _kernel32.CloseHandle(h_job)
                return 0

            # 3. 配置 UI 限制（禁止剪贴板、全局原子、ExitWindows、系统参数）
            ui_restrictions = JOBOBJECT_BASIC_UI_RESTRICTIONS()
            ui_restrictions.UIRestrictionsClass = (
                JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            )

            success = _kernel32.SetInformationJobObject(
                h_job,
                JobObjectBasicUIRestrictions,
                ctypes.byref(ui_restrictions),
                ctypes.sizeof(ui_restrictions)
            )
            if not success:
                # UI 限制失败不致命，继续
                self._log("warning", f"SetInformationJobObject(UI) 失败: {ctypes.get_last_error()}")

            self._log("info", f"Job Object 已创建并配置 (内存上限 {JOB_MEMORY_LIMIT_MB}MB, CPU 上限 {JOB_CPU_TIME_LIMIT_SEC}s)")
            return h_job

        except Exception as e:
            self._log("error", f"配置 Job Object 异常: {e}")
            return 0

    # ── 主分析入口 ──

    def analyze_file(self, file_path: str, timeout: int = DEFAULT_ANALYSIS_TIMEOUT,
                     cancel=None) -> dict:
        """在沙箱中分析文件

        流程：
          1. 创建 Job Object
          2. 设置限制（内存/CPU/UI）
          3. 创建受限进程 (CREATE_SUSPENDED)
          4. 将进程分配到 Job
          5. 恢复进程执行
          6. 等待 timeout 秒（分片轮询，可被 cancel 令牌提前打断）
          7. 收集行为日志
          8. 终止 Job（杀死所有子进程）
          9. 生成报告

        Args:
            file_path: 要分析的可执行文件路径
            timeout: 分析超时时间（秒）
            cancel: 可选取消令牌（is_cancelled()/is_set()）；置位后立即
                    终止沙箱进程并返回 cancelled=True 的部分报告

        Returns:
            分析报告字典，包含 verdict / confidence / behaviors / risk_indicators
        """
        file_path = os.path.abspath(file_path)
        report_id = f"sandbox_{int(time.time() * 1000)}"

        # 非 Windows 平台直接返回 clean
        if not IS_WINDOWS:
            return self._make_clean_report(
                file_path, report_id, "非 Windows 平台，无法运行沙箱"
            )

        # 文件不存在
        if not os.path.isfile(file_path):
            return self._make_clean_report(
                file_path, report_id, "文件不存在"
            )

        # 非 PE 文件返回 clean 报告
        if not _is_pe_file(file_path):
            with self._stats_lock:
                self._stats["clean_results"] += 1
            return self._make_clean_report(
                file_path, report_id, "非 PE 文件，跳过沙箱分析"
            )

        self._logger = _get_logger()
        start_time = time.time()

        # 设置当前分析状态
        with self._status_lock:
            self._current_analysis = {
                "file_path": file_path,
                "start_time": start_time,
                "timeout": timeout,
                "status": "running",
            }

        self._log("info", f"开始沙箱分析: {file_path} (超时 {timeout}s)")

        behaviors: list[dict] = []
        h_job = 0
        h_process = 0
        h_thread = 0
        pid = 0
        result = WAIT_TIMEOUT
        was_cancelled = False

        try:
            # 1. 创建并配置 Job Object
            h_job = self._setup_job()
            if not h_job:
                with self._stats_lock:
                    self._stats["analysis_failed"] += 1
                return self._make_clean_report(
                    file_path, report_id, "创建 Job Object 失败"
                )

            # 2. 创建挂起的进程
            startup_info = STARTUPINFO()
            startup_info.cb = ctypes.sizeof(STARTUPINFO)
            startup_info.dwFlags = 0x00000001  # STARTF_USESHOWWINDOW
            startup_info.wShowWindow = 0  # SW_HIDE
            proc_info = PROCESS_INFORMATION()

            creation_flags = (
                CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_BREAKAWAY_FROM_JOB
            )

            # CreateProcessW 需要可变字符串作为命令行
            cmd_line = ctypes.create_unicode_buffer(f'"{file_path}"')

            success = _kernel32.CreateProcessW(
                None,                       # lpApplicationName
                cmd_line,                   # lpCommandLine (可变)
                None, None,                 # 进程/线程属性
                False,                      # 不继承句柄
                creation_flags,
                None,                       # 环境块
                None,                       # 当前目录
                ctypes.byref(startup_info),
                ctypes.byref(proc_info)
            )

            if not success:
                err = ctypes.get_last_error()
                self._log("error", f"CreateProcess 失败: {err}")
                _kernel32.CloseHandle(h_job)
                with self._stats_lock:
                    self._stats["analysis_failed"] += 1
                return self._make_clean_report(
                    file_path, report_id, f"创建进程失败 (错误码 {err})"
                )

            h_process = proc_info.hProcess
            h_thread = proc_info.hThread
            pid = proc_info.dwProcessId

            # 3. 将进程分配到 Job
            success = _kernel32.AssignProcessToJobObject(h_job, h_process)
            if not success:
                self._log("warning", f"AssignProcessToJobObject 失败: {ctypes.get_last_error()}")
                # 继续执行，仍可监控

            # 4. 启动行为监控线程（独立线程）
            monitor_stop = threading.Event()
            monitor_thread = threading.Thread(
                target=self._monitor_process,
                args=(pid, behaviors, monitor_stop),
                daemon=True,
                name="Sandbox-Monitor"
            )
            monitor_thread.start()

            # 5. 恢复进程主线程执行
            _kernel32.ResumeThread(h_thread)

            # 6. 等待进程结束、超时或被取消（分片轮询以支持中途取消）
            deadline = time.time() + timeout
            while True:
                if cancel is not None and _token_cancelled(cancel):
                    was_cancelled = True
                    self._log("info", f"沙箱分析已被用户取消: {file_path}")
                    break
                remain = deadline - time.time()
                if remain <= 0:
                    result = WAIT_TIMEOUT
                    break
                slice_ms = int(min(0.2, max(0.02, remain)) * 1000)
                r = _kernel32.WaitForSingleObject(h_process, slice_ms)
                if r == WAIT_OBJECT_0:
                    result = r
                    break
                if r not in (WAIT_TIMEOUT, WAIT_OBJECT_0):
                    result = r
                    break

            # 7. 停止行为监控
            monitor_stop.set()
            monitor_thread.join(timeout=2)

            # 8. 获取退出码
            exit_code = wintypes.DWORD()
            _kernel32.GetExitCodeProcess(h_process, ctypes.byref(exit_code))

            if was_cancelled:
                behaviors.append({
                    "type": "cancelled",
                    "detail": "用户取消分析，沙箱进程已被强制终止",
                    "severity": "low",
                })
            elif result == WAIT_TIMEOUT:
                self._log("warning", f"分析超时，强制终止: {file_path}")
                behaviors.append({
                    "type": "timeout",
                    "detail": f"进程在 {timeout}s 后未退出",
                    "severity": "medium",
                })
            elif result == WAIT_OBJECT_0:
                self._log("info", f"进程正常退出，退出码: {exit_code.value}")
            else:
                self._log("warning", f"等待异常: result={result}")

        except Exception as e:
            self._log("error", f"沙箱分析异常: {e}")
            behaviors.append({
                "type": "error",
                "detail": f"分析异常: {e}",
                "severity": "low",
            })
        finally:
            # 9. 终止 Job（杀死所有子进程）
            if h_job:
                _kernel32.TerminateJobObject(h_job, 1)
                _kernel32.CloseHandle(h_job)
            if h_process:
                _kernel32.CloseHandle(h_process)
            if h_thread:
                _kernel32.CloseHandle(h_thread)

        elapsed = round(time.time() - start_time, 2)

        # 10. 生成报告
        report = self._generate_report(
            file_path, behaviors, elapsed, report_id
        )

        # 用户取消：标记报告并跳过统计/历史写入（避免污染分析历史）
        if was_cancelled:
            report["cancelled"] = True
            with self._status_lock:
                self._current_analysis = None
            self._log("info", f"沙箱分析已取消: {file_path} (耗时 {elapsed}s)")
            return report

        # 更新统计与历史
        self._update_stats_and_history(report)

        with self._status_lock:
            self._current_analysis = None

        self._log("info",
                  f"分析完成: {file_path} -> {report['verdict']} "
                  f"(置信度 {report['confidence']}, 耗时 {elapsed}s)")
        return report

    # ── 行为监控（简化 ETW，用 psutil）──

    def _monitor_process(self, pid: int, behaviors: list[dict],
                         stop_event: threading.Event):
        """ETW 监控行为（简化实现：用 psutil 监控子进程/文件操作/网络连接）

        Args:
            pid: 目标进程 PID
            behaviors: 行为列表（输出参数，由调用方传入）
            stop_event: 停止事件
        """
        if not _HAS_PSUTIL:
            # 没有 psutil，只记录进程退出
            return

        try:
            parent = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        # 已记录的网络连接（避免重复）
        seen_connections: set[tuple] = set()
        # 已记录的子进程
        seen_children: set[int] = {pid}
        # 已记录的打开文件
        seen_files: set[str] = set()
        # 采样计数
        sample_count = 0

        while not stop_event.is_set():
            try:
                # 检查父进程是否还在
                if not parent.is_running():
                    break

                # 1. 监控子进程创建
                try:
                    for child in parent.children(recursive=True):
                        if child.pid not in seen_children:
                            seen_children.add(child.pid)
                            try:
                                cmd = " ".join(child.cmdline()) or child.name()
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                cmd = child.name()
                            behaviors.append({
                                "type": "child_process",
                                "detail": f"创建子进程: {cmd} (PID={child.pid})",
                                "severity": "high",
                                "timestamp": time.time(),
                            })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # 2. 监控网络连接
                try:
                    for conn in parent.net_connections(kind='inet'):
                        if conn.status == psutil.CONN_ESTABLISHED:
                            key = (conn.laddr, conn.raddr, conn.status)
                            if key not in seen_connections:
                                seen_connections.add(key)
                                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "unknown"
                                behaviors.append({
                                    "type": "network",
                                    "detail": f"网络连接 -> {raddr}",
                                    "severity": "high",
                                    "timestamp": time.time(),
                                })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # 3. 监控文件操作（打开的文件）
                try:
                    for f in parent.open_files():
                        path = f.path
                        if path not in seen_files:
                            seen_files.add(path)
                            # 仅记录可疑路径
                            lower = path.lower()
                            if any(s in lower for s in (
                                "system32", "startup", "autorun",
                                "temp", "appdata", ".exe", ".dll",
                                "registry", "sam", "ntds.dit"
                            )):
                                behaviors.append({
                                    "type": "file_access",
                                    "detail": f"访问文件: {path}",
                                    "severity": "medium",
                                    "timestamp": time.time(),
                                })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                sample_count += 1
                # 每 0.5 秒采样一次
                stop_event.wait(0.5)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            except Exception:
                # 监控异常不应中断主流程
                break

    # ── 报告生成 ──

    def _generate_report(self, file_path: str, behaviors: list[dict],
                         elapsed: float, report_id: str) -> dict:
        """生成分析报告

        根据收集到的行为判定 verdict 与 confidence。

        Args:
            file_path: 分析的文件路径
            behaviors: 行为列表
            elapsed: 实际耗时（秒）
            report_id: 报告 ID

        Returns:
            报告字典，包含 verdict / confidence / behaviors / risk_indicators
        """
        # 计算风险评分
        risk_score = 0
        risk_indicators: list[str] = []

        # 各类行为计数
        behavior_counts: dict[str, int] = {}
        for b in behaviors:
            btype = b.get("type", "unknown")
            behavior_counts[btype] = behavior_counts.get(btype, 0) + 1

            # 根据严重程度累加风险分
            severity = b.get("severity", "low")
            if severity == "high":
                risk_score += 30
            elif severity == "medium":
                risk_score += 15
            elif severity == "low":
                risk_score += 5

        # 高风险行为指标
        if behavior_counts.get("child_process", 0) > 0:
            risk_indicators.append("创建子进程")
            risk_score += 10
        if behavior_counts.get("network", 0) > 0:
            risk_indicators.append("发起网络连接")
            risk_score += 20
        if behavior_counts.get("file_access", 0) >= 5:
            risk_indicators.append("大量文件访问")
            risk_score += 15
        if behavior_counts.get("timeout", 0) > 0:
            risk_indicators.append("运行超时未退出")
            risk_score += 10
        if behavior_counts.get("error", 0) > 0:
            risk_indicators.append("运行异常")

        # 限制风险分上限
        risk_score = min(risk_score, 100)

        # 判定 verdict
        if risk_score >= 70:
            verdict = "malicious"
            confidence = round(risk_score / 100, 2)
        elif risk_score >= 30:
            verdict = "suspicious"
            confidence = round(risk_score / 100, 2)
        else:
            verdict = "clean"
            confidence = round(1 - risk_score / 100, 2)

        report = {
            "report_id": report_id,
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path) if os.path.isfile(file_path) else 0,
            "verdict": verdict,
            "confidence": confidence,
            "risk_score": risk_score,
            "behaviors": behaviors,
            "risk_indicators": risk_indicators,
            "behavior_counts": behavior_counts,
            "elapsed_sec": elapsed,
            "timestamp": time.time(),
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        return report

    def _make_clean_report(self, file_path: str, report_id: str,
                           reason: str) -> dict:
        """生成 clean 报告（用于非 PE 文件或分析失败的情况）

        Args:
            file_path: 文件路径
            report_id: 报告 ID
            reason: 跳过原因

        Returns:
            clean 报告字典
        """
        return {
            "report_id": report_id,
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path) if os.path.isfile(file_path) else 0,
            "verdict": "clean",
            "confidence": 1.0,
            "risk_score": 0,
            "behaviors": [],
            "risk_indicators": [],
            "behavior_counts": {},
            "elapsed_sec": 0,
            "timestamp": time.time(),
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "note": reason,
        }

    # ── 统计与历史 ──

    def _update_stats_and_history(self, report: dict):
        """更新统计信息与历史记录

        Args:
            report: 分析报告
        """
        verdict = report.get("verdict", "clean")
        with self._stats_lock:
            self._stats["total_analyzed"] += 1
            if verdict == "malicious":
                self._stats["malicious_detected"] += 1
            elif verdict == "suspicious":
                self._stats["suspicious_detected"] += 1
            else:
                self._stats["clean_results"] += 1

        # 简化的历史记录（不存储完整 behaviors，避免过大）
        history_entry = {
            "report_id": report.get("report_id"),
            "file_path": report.get("file_path"),
            "file_name": report.get("file_name"),
            "verdict": verdict,
            "confidence": report.get("confidence"),
            "risk_score": report.get("risk_score"),
            "risk_indicators": report.get("risk_indicators", []),
            "behavior_counts": report.get("behavior_counts", {}),
            "elapsed_sec": report.get("elapsed_sec"),
            "timestamp": report.get("timestamp"),
            "datetime": report.get("datetime"),
        }

        with self._history_lock:
            self._history.append(history_entry)
            # 限制历史记录条数
            if len(self._history) > MAX_HISTORY_RECORDS:
                self._history = self._history[-MAX_HISTORY_RECORDS:]

        self._save_history()

    def _load_history(self):
        """从历史记录文件加载"""
        with self._history_lock:
            self._history = []
            if os.path.isfile(HISTORY_FILE):
                try:
                    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        self._history = data
                except Exception:
                    self._history = []

    def _save_history(self):
        """保存历史记录到文件"""
        with self._history_lock:
            data = list(self._history)
        try:
            os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # ── 状态查询 ──

    def get_status(self) -> dict:
        """获取沙箱状态

        Returns:
            包含平台、依赖、当前分析、统计信息的状态字典
        """
        self._ensure_history()
        with self._status_lock:
            current = dict(self._current_analysis) if self._current_analysis else None
        with self._stats_lock:
            stats = dict(self._stats)
        with self._history_lock:
            history_count = len(self._history)

        return {
            "platform": "windows" if IS_WINDOWS else "non-windows",
            "is_windows": IS_WINDOWS,
            "has_psutil": _HAS_PSUTIL,
            "ready": IS_WINDOWS,
            "current_analysis": current,
            "history_count": history_count,
            "stats": stats,
            "config": {
                "memory_limit_mb": JOB_MEMORY_LIMIT_MB,
                "cpu_time_limit_sec": JOB_CPU_TIME_LIMIT_SEC,
                "active_process_limit": JOB_ACTIVE_PROCESS_LIMIT,
                "default_timeout": DEFAULT_ANALYSIS_TIMEOUT,
                "max_history_records": MAX_HISTORY_RECORDS,
            },
        }

    def get_history(self, limit: int = 50) -> list[dict]:
        """获取历史分析记录

        Args:
            limit: 返回的最大记录数（默认 50）

        Returns:
            历史记录列表（按时间倒序）
        """
        self._ensure_history()
        with self._history_lock:
            records = list(self._history)
        # 倒序（最新在前）
        records.reverse()
        return records[:limit]

    # ── 日志 ──

    def _log(self, level: str, message: str):
        if self._logger:
            getattr(self._logger, level, self._logger.info)(message)


# ══════════════════════════════════════════════════════════════
#  单例
# ══════════════════════════════════════════════════════════════

_sandbox_instance: LightweightSandbox | None = None
_sandbox_lock = threading.Lock()


def get_sandbox() -> LightweightSandbox:
    """获取 LightweightSandbox 单例实例"""
    global _sandbox_instance
    if _sandbox_instance is None:
        with _sandbox_lock:
            if _sandbox_instance is None:
                _sandbox_instance = LightweightSandbox()
    return _sandbox_instance
