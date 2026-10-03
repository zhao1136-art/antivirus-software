"""
御天 内嵌沙箱（Windows Job Object + Low Integrity + 防火墙阻断）

在受限环境中运行可疑文件，监控其行为，自动生成分析报告。

功能：
  1. Windows Job Object 限制（内存 256MB / CPU 10 秒 / 进程数 / 关闭即杀）
  2. UI 限制（禁止读写剪贴板、全局原子、ExitWindows 等）
  3. 低完整性级别（Low IL, S-1-16-4096）受限令牌启动
     —— CreateRestrictedToken + SetTokenInformation(TokenIntegrityLevel)
        + CreateProcessAsUserW / CreateProcessWithTokenW
     —— 样本默认写不进用户目录 / Program Files / HKLM，也改不了 HKCU Run
  4. 独立低完整性工作目录 %TEMP%\\yutian_sandbox\\<task_id>\\（ACL 打 Low 标签）
  5. 出网阻断：netsh advfirewall 按 program + dir=out + action=block 加规则，
     分析结束在 finally 中删除；规则名带 task id，避免并发分析互删
  6. 行为监控（简化 ETW：用 psutil 监控子进程 / 文件操作 / 网络连接）
  7. 自动生成分析报告（verdict / confidence / behaviors / risk_indicators / isolation）
  8. 历史分析记录持久化到 data/sandbox_history.json
  9. 支持分析超时控制与强制终止
 10. 可插拔隔离引擎（engine/isolation/）：copy = 复制式隔离（样本在沙箱内
     副本上执行），none = 样本在原路径执行（对照 / 降级目标）。每个引擎必须
     申报能力（capabilities）并写进 isolation.capabilities —— 用户态做不到
     绝对路径重定向，就绝不说做到了；copy 不可用时降级 none 并写进
     isolation.degraded_reason

注意：
  - 仅支持 Windows 平台（依赖 Job Object / ctypes / Windows API）
  - 非 PE 文件、文件缺失或分析失败时返回 verdict="unknown"，
    不抛异常，也绝不当成 clean（分析不出来不等于安全）
  - 隔离能力可能降级（无管理员权限时防火墙规则加不上、受限令牌进程
    创建失败时会退回同等完整性启动）。降级原因一律写入报告的
    isolation.degraded_reason，不静默跳过
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

# 隔离参数
SANDBOX_ROOT_DIRNAME = "yutian_sandbox"        # %TEMP% 下的沙箱根目录
NETWORK_RULE_PREFIX = "caelire_sandbox_block"  # 防火墙规则名前缀（后接 task id）
NETWORK_RULE_TIMEOUT_SEC = 15                  # netsh 调用超时 (秒)

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

# ── 令牌 / 完整性级别常量（Low IL 隔离）──
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
TOKEN_ALL_ACCESS = 0x000F01FF

# CreateRestrictedToken 标志
DISABLE_MAX_PRIVILEGE = 0x00000001
SANDBOX_INERT = 0x00000002
LUA_TOKEN = 0x00000004

# 令牌信息类
TokenIntegrityLevel = 25
SE_GROUP_INTEGRITY = 0x00000020

# 完整性级别 SID（字符串形式，用 ConvertStringSidToSidW 解析）
INTEGRITY_SID_LOW = "S-1-16-4096"              # 低完整性
INTEGRITY_SID_MEDIUM = "S-1-16-8192"           # 中完整性（仅用于比较/说明）

# 进程创建标志补充
CREATE_UNICODE_ENVIRONMENT = 0x00000400
LOGON_WITH_PROFILE = 0x00000001

# ── 防火墙常量 ──
NET_FW_RULE_DIR_IN = 1
NET_FW_RULE_DIR_OUT = 2
NET_FW_ACTION_BLOCK = 0
NET_FW_PROFILE2_ALL = 0x7FFFFFFF

# ── 环境变量块分隔 ──
_ENV_BLOCK_SEP = "\0"

# ── 隔离状态取值 ──
ISOLATION_LEVEL_LOW = "low"
ISOLATION_LEVEL_MEDIUM = "medium"
ISOLATION_LEVEL_NONE = "none"


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


class SID_AND_ATTRIBUTES(ctypes.Structure):
    """SID 及其属性（用于令牌完整性级别）"""
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    """令牌强制完整性标签（SetTokenInformation / TokenIntegrityLevel 用）"""
    _fields_ = [
        ("Label", SID_AND_ATTRIBUTES),
    ]


# ── Windows API 函数原型 ──

if IS_WINDOWS:
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

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

    # IsProcessInJob(ProcessHandle, JobHandle, Result)
    _kernel32.IsProcessInJob.restype = wintypes.BOOL
    _kernel32.IsProcessInJob.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)
    ]

    # QueryInformationJobObject(hJob, class, buf, len, retlen) -> BOOL
    _kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    _kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, wintypes.INT, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)
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

    # GetCurrentProcess() -> HANDLE（伪句柄，无需关闭）
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.GetCurrentProcess.argtypes = []

    # ── 令牌相关（advapi32）──

    # OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle)
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
    ]

    # CreateRestrictedToken(ExistingTokenHandle, Flags, DisableSidCount,
    #   SidsToDisable, DeletePrivilegeCount, PrivilegesToDelete,
    #   RestrictedSidCount, SidsToRestrict, NewTokenHandle)
    _advapi32.CreateRestrictedToken.restype = wintypes.BOOL
    _advapi32.CreateRestrictedToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
        ctypes.POINTER(wintypes.HANDLE)
    ]

    # ConvertStringSidToSidW(StringSid, Sid)
    # 注意：不要用 CreateWellKnownSid(WinLowLabelSid=69)，本机实测它返回的
    # 是 S-1-16-16384（中+完整性），必须按字符串解析 S-1-16-4096。
    _advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    _advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)
    ]

    # SetTokenInformation(TokenHandle, TokenInformationClass,
    #   TokenInformation, TokenInformationLength)
    _advapi32.SetTokenInformation.restype = wintypes.BOOL
    _advapi32.SetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
    ]

    # CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine,
    #   lpProcessAttributes, lpThreadAttributes, bInheritHandles,
    #   dwCreationFlags, lpEnvironment, lpCurrentDirectory,
    #   lpStartupInfo, lpProcessInformation)
    _advapi32.CreateProcessAsUserW.restype = wintypes.BOOL
    _advapi32.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
        ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p,
        wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p
    ]

    # CreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName,
    #   lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
    #   lpStartupInfo, lpProcessInformation)
    _advapi32.CreateProcessWithTokenW.restype = wintypes.BOOL
    _advapi32.CreateProcessWithTokenW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR,
        wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p,
        ctypes.c_void_p
    ]

    # GetTokenInformation(TokenHandle, Class, buf, len, retlen)
    _advapi32.GetTokenInformation.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)
    ]

    # ConvertSidToStringSidW(Sid, StringSid)  —— 仅用于诊断输出
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)
    ]


# ── psutil 可选导入 ──
try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    psutil = None
    _HAS_PSUTIL = False


# ── 可插拔隔离引擎（文件系统视野：copy = 复制式隔离 / none = 现状）──
# 缺了它沙箱仍然要能跑（退回"样本在原路径执行"的旧行为），所以导入失败
# 不抛异常，只把 _HAS_ISOLATION_ENGINE 置 False 并在报告里如实标注。
try:
    from engine.isolation import (
        get_engine as _get_isolation_engine,
        describe_engines as _describe_isolation_engines,
        DEFAULT_ENGINE as _DEFAULT_ISOLATION_ENGINE,
        ENGINE_NONE as _ENGINE_NONE,
    )
    _HAS_ISOLATION_ENGINE = True
except Exception:  # pragma: no cover - 备用相对导入
    try:
        from .isolation import (
            get_engine as _get_isolation_engine,
            describe_engines as _describe_isolation_engines,
            DEFAULT_ENGINE as _DEFAULT_ISOLATION_ENGINE,
            ENGINE_NONE as _ENGINE_NONE,
        )
        _HAS_ISOLATION_ENGINE = True
    except Exception:
        _get_isolation_engine = None
        _describe_isolation_engines = None
        _DEFAULT_ISOLATION_ENGINE = "none"
        _ENGINE_NONE = "none"
        _HAS_ISOLATION_ENGINE = False


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


# ── 系统控制台宿主识别（2026-10-03 沙箱误报修复）────────────────────────
#
# 为什么需要：Windows 上**任何**控制台程序都会被系统拉起一个 conhost.exe，
# 它是不是出现、出现几次，只取决于"样本是不是控制台程序"，与样本好坏无关。
# 实测：无害的 choice.exe、自己编的一行打印控制台程序，conhost 一律出现，
# 而修复前它被记成 child_process/high（+30 高危 +10 子进程 = 40 分）并进入
# strong_kinds，直接把 verdict 顶到 malicious（risk=80）。
#
# 只豁免**系统目录里**的同名映像：C:\Temp\conhost.exe 这种伪装仍然按
# child_process 计 —— 名字可以随便起，路径不能。
_CONSOLE_HOST_NAMES = frozenset(("conhost.exe", "openconsole.exe"))


def _child_image_path(exe_path: str, cmd_line: str) -> str:
    """取子进程映像路径：优先 psutil 给的 exe()，拿不到再从命令行里抠。

    实测 conhost 的 cmdline 形如 "\\??\\C:\\Windows\\system32\\conhost.exe 0x4"。
    """
    cand = (exe_path or "").strip()
    if cand:
        return cand
    low = (cmd_line or "").lower()
    idx = low.find(".exe")
    if idx < 0:
        return ""
    return (cmd_line or "")[:idx + 4].strip().strip('"')


def _is_console_host(exe_path: str, cmd_line: str) -> bool:
    """子进程是否是系统目录里的控制台宿主（conhost.exe / OpenConsole.exe）"""
    cand = _child_image_path(exe_path, cmd_line)
    if not cand:
        return False
    for pre in ("\\??\\", "\\\\?\\"):
        if cand.startswith(pre):
            cand = cand[len(pre):]
    if os.path.basename(cand).lower() not in _CONSOLE_HOST_NAMES:
        return False
    sysroot = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    try:
        full = os.path.normcase(os.path.abspath(cand))
    except Exception:
        return False
    for sub in ("system32", "syswow64"):
        if full.startswith(os.path.join(sysroot, sub) + os.sep):
            return True
    return False


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
#  隔离能力（Low IL 受限令牌 / 防火墙出网阻断 / 低完整性工作目录）
# ══════════════════════════════════════════════════════════════

def _empty_isolation(level: str = ISOLATION_LEVEL_NONE,
                     reason: str = "") -> dict:
    """构造隔离状态字典（所有报告都会带上它）

    既有的键（job_object / network_blocked / integrity_level /
    degraded_reason / low_il_workdir / firewall_rule /
    firewall_rule_removed / created_via）一个都不能少；
    下面 engine* 一组是隔离引擎（文件系统视野）的自述。
    """
    return {
        "job_object": False,
        "network_blocked": False,
        "integrity_level": level,
        "degraded_reason": reason,
        "low_il_workdir": None,
        "firewall_rule": None,
        "firewall_rule_removed": None,
        "created_via": None,
        # ── 隔离引擎（文件系统视野）──
        "engine": None,              # 本次真正生效的引擎（copy / none）
        "engine_requested": None,    # 调用方/配置请求的引擎（降级前）
        "capabilities": None,        # 能力申报（绝对路径重定向等，必须诚实）
        "exec_path": None,           # 实际被执行的路径（copy 下是沙箱内副本）
        "copied_files": 0,
        "copied_bytes": 0,
        "truncated": False,          # 因容量上限没复制全
        "engine_notes": [],          # 引擎自述（作用范围 / 跳过原因）
    }


def _select_isolation_engine(sample_path: str, task_id: str,
                             degraded: list, name: str | None = None) -> tuple[list, dict]:
    """选隔离引擎并 prepare（默认 copy；不可用时降级 none）

    降级原因一律追加进 degraded（最终写进 isolation.degraded_reason），
    绝不静默跳过隔离。

    Args:
        name: 显式指定的引擎名；None = 用户配置 > 环境变量 > 默认 copy

    Returns:
        (engines, info)：engines 是需要调用方在 finally 中 cleanup 的引擎
        列表（含降级前被弃用的那个，它可能已经建了目录）；
        info 是最终采用引擎的 prepare() 结果。

    注意：prepare 在这里**不删**任何目录（引擎契约如此）——万一 copy 失败，
    它建好的目录由调用方在 finally 里统一清理。
    """
    if not _HAS_ISOLATION_ENGINE:
        degraded.append("隔离引擎包不可用，样本将在原始路径执行（无复制式隔离）")
        return [], {
            "ok": False, "engine": None, "exec_path": sample_path,
            "work_dir": None, "root_dir": None, "capabilities": None,
            "copied_files": 0, "copied_bytes": 0, "truncated": False,
            "notes": [], "degraded_reason": "隔离引擎包不可用",
        }

    engines: list = []
    engine = _get_isolation_engine(name)      # 显式指定 > 配置 > 环境变量 > 默认
    engines.append(engine)
    if engine.fallback_reason:
        # 例如配置里写了不存在的引擎名：照实上报
        degraded.append(engine.fallback_reason)

    try:
        info = engine.prepare(sample_path, task_id)
    except Exception as e:
        info = {
            "ok": False, "engine": engine.name, "exec_path": sample_path,
            "work_dir": None, "root_dir": None,
            "capabilities": engine.capabilities(),
            "copied_files": 0, "copied_bytes": 0, "truncated": False,
            "notes": [],
            "degraded_reason": f"prepare 异常: {type(e).__name__}: {e}",
        }

    if info.get("ok"):
        return engines, info

    reason = info.get("degraded_reason") or "引擎未说明原因"
    failed_name = info.get("engine") or engine.name
    if failed_name == _ENGINE_NONE:
        degraded.append(f"隔离引擎 {failed_name} 不可用（{reason}），无更低的后端可降级")
        return engines, info

    degraded.append(
        f"隔离引擎 {failed_name} 不可用（{reason}），已降级为 {_ENGINE_NONE}"
    )
    fallback = _get_isolation_engine(_ENGINE_NONE)
    engines.append(fallback)
    try:
        info2 = fallback.prepare(sample_path, task_id)
    except Exception as e:
        info2 = dict(info)
        info2.update({
            "ok": False, "engine": fallback.name, "exec_path": sample_path,
            "work_dir": None, "capabilities": fallback.capabilities(),
            "degraded_reason": f"none 后端 prepare 异常: {type(e).__name__}: {e}",
        })
        degraded.append(info2["degraded_reason"])
    return engines, info2


def _run_netsh(args: list[str]) -> tuple[int, str, str]:
    """执行 netsh 并返回 (returncode, stdout, stderr)

    样本绝对路径可能含非 ASCII / 空格，netsh 的 = 语法接受这种写法，
    因此这里不做转义，只保证参数以列表形式传递（不经过 shell）。
    """
    try:
        proc = subprocess.run(
            ["netsh"] + args,
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            timeout=NETWORK_RULE_TIMEOUT_SEC,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return -1, "", "netsh.exe not found"
    except subprocess.TimeoutExpired:
        return -1, "", f"netsh timeout ({NETWORK_RULE_TIMEOUT_SEC}s)"
    except Exception as e:
        return -1, "", f"{type(e).__name__}: {e}"


def _network_rule_name(task_id: str) -> str:
    """生成唯一防火墙规则名（带 task id，避免并发分析互删规则）"""
    safe = "".join(ch if (ch.isalnum() or ch in "_-") else "_" for ch in str(task_id))
    return f"{NETWORK_RULE_PREFIX}_{safe}_{os.getpid()}"


def _network_block_rule(rule_name: str, program_path: str) -> tuple[bool, str]:
    """按程序路径阻断出网（dir=out, action=block）

    Returns:
        (是否生效, 失败原因)；成功时原因为空字符串
    """
    if not IS_WINDOWS:
        return False, "非 Windows 平台"
    rc, out, err = _run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        f"program={program_path}",
        "enable=yes",
        "profile=any",
    ])
    if rc == 0:
        return True, ""
    detail = (err.strip() or out.strip() or f"netsh 退出码 {rc}")
    if rc != 0 and ("denied" in detail.lower() or "拒绝" in detail
                    or "requires elevation" in detail.lower()
                    or rc == 5 or rc == 1):
        detail = f"{detail} (可能缺少管理员权限/被安全软件拦截)"
    return False, detail[:400]


def _network_unblock_rule(rule_name: str) -> tuple[bool, str]:
    """删除出网阻断规则（必须在 finally 中调用）

    Returns:
        (是否已删除或本就不存在, 失败原因)
    """
    if not IS_WINDOWS:
        return True, ""
    rc, out, err = _run_netsh([
        "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"
    ])
    if rc == 0:
        return True, ""
    detail = (err.strip() or out.strip() or f"netsh 退出码 {rc}")
    # 规则本来就不存在（添加就失败的情况）不算删除失败
    if "no rules match" in detail.lower() or "没有与指定条件匹配" in detail:
        return True, ""
    return False, detail[:400]


def _network_rule_exists(rule_name: str) -> bool:
    """检查防火墙规则是否还存在（仅用于自检 / 报告）"""
    if not IS_WINDOWS:
        return False
    rc, out, err = _run_netsh([
        "advfirewall", "firewall", "show", "rule", f"name={rule_name}"
    ])
    if rc != 0:
        return False
    return rule_name in out


def _create_low_il_token() -> tuple[int, str]:
    """创建低完整性级别（Low IL）受限令牌

    步骤：OpenProcessToken -> CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)
          -> ConvertStringSidToSidW("S-1-16-4096")
          -> SetTokenInformation(TokenIntegrityLevel)

    Returns:
        (令牌句柄, 失败原因)；失败时句柄为 0
    """
    if not IS_WINDOWS:
        return 0, "非 Windows 平台"

    base_token = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(
            _kernel32.GetCurrentProcess(), TOKEN_ALL_ACCESS,
            ctypes.byref(base_token)):
        return 0, f"OpenProcessToken 失败 (错误码 {ctypes.get_last_error()})"

    restricted = wintypes.HANDLE()
    try:
        if not _advapi32.CreateRestrictedToken(
                base_token, DISABLE_MAX_PRIVILEGE,
                0, None, 0, None, 0, None, ctypes.byref(restricted)):
            return 0, f"CreateRestrictedToken 失败 (错误码 {ctypes.get_last_error()})"

        sid_low = ctypes.c_void_p()
        if not _advapi32.ConvertStringSidToSidW(INTEGRITY_SID_LOW,
                                                ctypes.byref(sid_low)):
            _kernel32.CloseHandle(restricted)
            return 0, (f"ConvertStringSidToSidW({INTEGRITY_SID_LOW}) 失败 "
                       f"(错误码 {ctypes.get_last_error()})")

        label = TOKEN_MANDATORY_LABEL()
        label.Label.Sid = sid_low.value
        label.Label.Attributes = SE_GROUP_INTEGRITY
        if not _advapi32.SetTokenInformation(
                restricted, TokenIntegrityLevel, ctypes.byref(label),
                ctypes.sizeof(label)):
            err = ctypes.get_last_error()
            _kernel32.CloseHandle(restricted)
            return 0, (f"SetTokenInformation(TokenIntegrityLevel={INTEGRITY_SID_LOW}) "
                       f"失败 (错误码 {err})")

        return int(restricted.value or 0), ""
    finally:
        _kernel32.CloseHandle(base_token)


def _prepare_low_il_workdir(task_id: str) -> tuple[str, str]:
    """创建独立低完整性工作目录并用 icacls 打 Low 标签

    低完整性进程只能在该目录（以及其它显式标记 Low 的目录）里写文件，
    这正是我们要的效果。

    Returns:
        (目录路径, 失败原因)；失败原因为空表示 ACL 打标成功
    """
    work_dir = os.path.join(
        os.environ.get("TEMP") or os.path.expanduser("~"),
        SANDBOX_ROOT_DIRNAME, str(task_id)
    )
    try:
        os.makedirs(work_dir, exist_ok=True)
    except Exception as e:
        return work_dir, f"创建沙箱工作目录失败: {type(e).__name__}: {e}"

    if not IS_WINDOWS:
        return work_dir, "非 Windows 平台"

    try:
        proc = subprocess.run(
            ["icacls", work_dir, "/setintegritylevel", "(OI)(CI)Low"],
            capture_output=True, text=True, encoding="mbcs", errors="replace",
            timeout=NETWORK_RULE_TIMEOUT_SEC,
        )
        if proc.returncode == 0:
            return work_dir, ""
        detail = (proc.stderr or proc.stdout or "").strip() or f"icacls 退出码 {proc.returncode}"
        return work_dir, f"设置低完整性 ACL 失败: {detail[:300]}"
    except Exception as e:
        return work_dir, f"设置低完整性 ACL 异常: {type(e).__name__}: {e}"


def _build_sandbox_environment(work_dir: str | None) -> ctypes.Array:
    """构造沙箱子进程环境块

    Windows 要求环境块按变量名（不区分大小写）排序、各项以 NUL 分隔、
    整体以双 NUL 结尾；调用方还必须带上 CREATE_UNICODE_ENVIRONMENT，
    否则 CreateProcess* 会直接返回 ERROR_INVALID_PARAMETER(87)。

    TEMP/TMP 指向沙箱工作目录，避免样本被低完整性 ACL 卡住临时文件写入。
    """
    env = dict(os.environ)
    if work_dir:
        env["TEMP"] = work_dir
        env["TMP"] = work_dir
        env["YUTIAN_SANDBOX_WORKDIR"] = work_dir
    block = "".join(
        f"{key}={env[key]}{_ENV_BLOCK_SEP}"
        for key in sorted(env, key=lambda k: k.upper()) if key
    ) + _ENV_BLOCK_SEP
    return ctypes.create_unicode_buffer(block)


def _cleanup_sandbox_workdir(work_dir: str) -> str:
    """尽力清理沙箱工作目录（不删除未知内容之外的东西）

    Returns:
        空字符串表示已处理干净，否则为失败原因
    """
    if not work_dir or not os.path.isdir(work_dir):
        return ""
    import shutil
    try:
        shutil.rmtree(work_dir, ignore_errors=False)
        return ""
    except Exception as e:
        first = f"{type(e).__name__}: {e}"
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
            if not os.path.isdir(work_dir):
                return ""
        except Exception:
            pass
        return first[:300]


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
                     cancel=None, isolation_engine: str | None = None) -> dict:
        """在沙箱中分析文件

        流程：
          1. 建独立低完整性工作目录（icacls 打 Low 标签）
          1b. 准备隔离引擎（默认 copy = 复制式隔离；不可用则降级 none）
              —— 必须在建 Job Object 之前，执行路径取引擎给出的 exec_path
          2. 加防火墙出网阻断规则（按**实际执行路径**，规则名带 task id）
          3. 创建 Job Object（内存/CPU/进程数/关闭即杀/UI 限制）
          4. 创建 Low IL 受限令牌（CreateRestrictedToken + TokenIntegrityLevel）
          5. 用该令牌创建挂起进程（CreateProcessAsUserW，失败则
             CreateProcessWithTokenW，再失败降级为同等完整性启动）
          6. 将进程分配到 Job
          7. 恢复进程执行
          8. 等待 timeout 秒（分片轮询，可被 cancel 令牌提前打断）
          9. 收集行为日志
         10. 终止 Job（杀死所有子进程）
         11. finally：删除防火墙规则 + 清理隔离引擎目录 + 清理工作目录
         12. 生成报告（含 isolation 字段，降级原因如实写入）

        Args:
            file_path: 要分析的可执行文件路径
            timeout: 分析超时时间（秒）
            cancel: 可选取消令牌（is_cancelled()/is_set()）；置位后立即
                    终止沙箱进程并返回 cancelled=True 的部分报告
            isolation_engine: 可选引擎名覆盖（"copy"/"none"）；None = 走
                    用户配置 > 环境变量 > 默认 copy

        Returns:
            分析报告字典，包含 verdict / confidence / behaviors /
            risk_indicators / isolation；分析不了时 verdict 为 "unknown"
        """
        file_path = os.path.abspath(file_path)
        report_id = f"sandbox_{int(time.time() * 1000)}"

        # 非 Windows 平台：无法分析，返回 unknown（不是 clean）
        if not IS_WINDOWS:
            with self._stats_lock:
                self._stats["analysis_failed"] += 1
            return self._make_unknown_report(
                file_path, report_id, "非 Windows 平台，无法运行沙箱"
            )

        # 文件不存在：无法分析，返回 unknown（不是 clean）
        if not os.path.isfile(file_path):
            with self._stats_lock:
                self._stats["analysis_failed"] += 1
            return self._make_unknown_report(
                file_path, report_id, "文件不存在"
            )

        # 非 PE 文件：无法在沙箱中执行，返回 unknown（不是 clean）
        if not _is_pe_file(file_path):
            with self._stats_lock:
                self._stats["analysis_failed"] += 1
            return self._make_unknown_report(
                file_path, report_id, "非 PE 文件，无法沙箱执行"
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
        isolation = _empty_isolation()
        degraded: list[str] = []
        h_job = 0
        h_process = 0
        h_thread = 0
        pid = 0
        result = WAIT_TIMEOUT
        was_cancelled = False
        low_box_dir = ""
        firewall_rule = ""
        firewall_added = False
        cleanup_error = ""
        isolation_engines: list = []
        iso_info: dict = {}
        exec_path = file_path
        iso_work_dir: str | None = None

        try:
            # 1. 独立低完整性工作目录
            low_box_dir, acl_err = _prepare_low_il_workdir(report_id)
            isolation["low_il_workdir"] = low_box_dir
            if acl_err:
                degraded.append(f"低完整性工作目录 ACL 未生效: {acl_err}")

            # 1b. 准备隔离引擎（文件系统视野），必须在建 Job Object 之前。
            #     引擎的 work_dir 与上面的低完整性工作目录是同一条路径
            #     （%TEMP%\yutian_sandbox\<task_id>），副本因此天然落在已打
            #     Low 标签的目录里，低完整性进程写得进去。若将来某个后端把
            #     work_dir 指到别处，必须自己先给那个目录打 Low 标签。
            isolation_engines, iso_info = _select_isolation_engine(
                file_path, report_id, degraded, isolation_engine)
            exec_path = iso_info.get("exec_path") or file_path
            iso_work_dir = iso_info.get("work_dir") or low_box_dir or None
            isolation["engine"] = iso_info.get("engine")
            isolation["engine_requested"] = (
                isolation_engines[0].requested_name if isolation_engines else None)
            isolation["capabilities"] = iso_info.get("capabilities")
            isolation["exec_path"] = exec_path
            isolation["copied_files"] = iso_info.get("copied_files", 0)
            isolation["copied_bytes"] = iso_info.get("copied_bytes", 0)
            isolation["truncated"] = bool(iso_info.get("truncated"))
            isolation["engine_notes"] = list(iso_info.get("notes") or [])
            self._log(
                "info",
                f"隔离引擎={isolation['engine']} "
                f"(请求 {isolation['engine_requested']})，"
                f"执行路径={exec_path}，工作目录={iso_work_dir}"
            )

            # 2. 出网阻断（规则名唯一，按**实际执行路径**加规则）
            #    ⚠️ copy 引擎下样本从沙箱内副本启动，若仍按样本原路径加规则，
            #    防火墙按 program 匹配不到副本，出网阻断会形同虚设。
            firewall_rule = _network_rule_name(report_id)
            isolation["firewall_rule"] = firewall_rule
            blocked, block_err = _network_block_rule(firewall_rule, exec_path)
            firewall_added = blocked
            isolation["network_blocked"] = blocked
            if blocked:
                self._log("info", f"网络隔离已生效（防火墙规则 {firewall_rule}）")
            else:
                degraded.append(f"网络隔离未生效: {block_err}")
                self._log("error", f"网络隔离未生效: {block_err}")

            # 3. 创建并配置 Job Object
            h_job = self._setup_job()
            if not h_job:
                isolation["degraded_reason"] = "; ".join(degraded)
                with self._stats_lock:
                    self._stats["analysis_failed"] += 1
                return self._make_unknown_report(
                    file_path, report_id, "创建 Job Object 失败",
                    isolation=isolation
                )
            isolation["job_object"] = True

            # 4. 创建 Low IL 受限令牌
            h_token, token_err = _create_low_il_token()
            if token_err:
                degraded.append(f"低完整性令牌不可用: {token_err}；以当前完整性运行")

            startup_info = STARTUPINFO()
            startup_info.cb = ctypes.sizeof(STARTUPINFO)
            startup_info.dwFlags = 0x00000001  # STARTF_USESHOWWINDOW
            startup_info.wShowWindow = 0  # SW_HIDE
            proc_info = PROCESS_INFORMATION()

            creation_flags = (CREATE_SUSPENDED | CREATE_NO_WINDOW
                              | CREATE_UNICODE_ENVIRONMENT)
            # 注意：这里刻意不使用 CREATE_BREAKAWAY_FROM_JOB。
            # 本进程自身通常已位于某个 Job（例如启动器给的 Job），而“允许
            # 脱离”的权限取决于父 Job 的 JOB_OBJECT_LIMIT_BREAKAWAY_OK；
            # 一旦父 Job 未开放，CreateProcess* 会直接失败（错误码 5）。
            # 实测：不请求脱离时子进程仍能通过 AssignProcessToJobObject
            # 加入本沙箱 Job（嵌套 Job），资源限制照常生效。

            # CreateProcess* 需要可变字符串作为命令行
            # 注意：命令行给的是**引擎的执行路径**（copy 下 = 沙箱内副本），
            # 不是样本原路径。
            cmd_line = ctypes.create_unicode_buffer(f'"{exec_path}"')
            env_block = _build_sandbox_environment(iso_work_dir) \
                if iso_work_dir else None
            env_ptr = ctypes.cast(env_block, ctypes.c_void_p) if env_block else None

            success = False
            created_via = ""

            if h_token:
                # 5a. 正统路径：用 Low IL 令牌创建挂起进程
                success = _advapi32.CreateProcessAsUserW(
                    h_token, None, cmd_line, None, None, False,
                    creation_flags, env_ptr, iso_work_dir or None,
                    ctypes.byref(startup_info), ctypes.byref(proc_info)
                )
                if success:
                    created_via = "CreateProcessAsUserW(low_il)"
                else:
                    err_a = ctypes.get_last_error()
                    # 5b. 退路：CreateProcessWithTokenW（不支持 CREATE_SUSPENDED）
                    ok_b = _advapi32.CreateProcessWithTokenW(
                        h_token, 0, None, cmd_line,
                        creation_flags & ~CREATE_SUSPENDED,
                        env_ptr, iso_work_dir or None,
                        ctypes.byref(startup_info), ctypes.byref(proc_info)
                    )
                    if ok_b:
                        success = True
                        created_via = "CreateProcessWithTokenW(low_il,no_suspend)"
                        proc_info.hThread = 0
                        degraded.append(
                            "CreateProcessAsUser 失败 "
                            f"(错误码 {err_a})，改用 CreateProcessWithTokenW："
                            "样本未挂起即运行，Job 分配前存在极短窗口"
                        )
                        self._log("warning",
                                  f"CreateProcessAsUser 失败 {err_a}，已退到 "
                                  "CreateProcessWithTokenW")
                    else:
                        err_b = ctypes.get_last_error()
                        degraded.append(
                            f"低完整性进程创建失败 (CreateProcessAsUser={err_a}, "
                            f"CreateProcessWithTokenW={err_b})"
                        )
                _kernel32.CloseHandle(h_token)

            if not success:
                # 5c. 降级：同等完整性启动（隔离等级不足，如实记录）
                success = _kernel32.CreateProcessW(
                    None, cmd_line, None, None, False, creation_flags,
                    env_ptr, iso_work_dir or None,
                    ctypes.byref(startup_info), ctypes.byref(proc_info)
                )
                if success:
                    created_via = "CreateProcessW(no_low_il)"
                    degraded.append("已降级为当前完整性启动，文件系统/注册表隔离不足")
                    self._log("error", "低完整性隔离不可用，降级为同等完整性启动")

            isolation["created_via"] = created_via

            if not success:
                err = ctypes.get_last_error()
                self._log("error", f"创建进程失败: {err}")
                isolation["degraded_reason"] = "; ".join(degraded)
                with self._stats_lock:
                    self._stats["analysis_failed"] += 1
                return self._make_unknown_report(
                    file_path, report_id, f"创建进程失败 (错误码 {err})",
                    isolation=isolation
                )

            # 记录实际隔离等级
            if created_via == "CreateProcessW(no_low_il)":
                isolation["integrity_level"] = ISOLATION_LEVEL_NONE
            else:
                isolation["integrity_level"] = ISOLATION_LEVEL_LOW

            h_process = proc_info.hProcess
            h_thread = proc_info.hThread
            pid = proc_info.dwProcessId

            # 6. 将进程分配到 Job
            success = _kernel32.AssignProcessToJobObject(h_job, h_process)
            if not success:
                err = ctypes.get_last_error()
                degraded.append(f"AssignProcessToJobObject 失败 (错误码 {err})")
                self._log("warning", f"AssignProcessToJobObject 失败: {err}")
                # 继续执行，仍可监控

            # 7. 启动行为监控线程（独立线程）
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

            # 记录"进程确实跑起来了"这条证据，避免样本静默退出时
            # 报告里空无一物（无行为 != 安全）
            if was_cancelled:
                pass
            elif result == WAIT_OBJECT_0:
                behaviors.append({
                    "type": "process_exit",
                    "detail": (f"沙箱进程正常退出，退出码 {exit_code.value}"
                               f"（低完整性 {isolation.get('integrity_level')} 隔离下运行）"),
                    "severity": "low",
                    "timestamp": time.time(),
                })
            elif result == WAIT_TIMEOUT:
                behaviors.append({
                    "type": "process_exit",
                    "detail": "进程被超时强制终止，退出码不可信",
                    "severity": "low",
                    "timestamp": time.time(),
                })

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

            # ── 内存镜像扫描 ──
            # **必须在下面 finally 的 TerminateJobObject 之前做** —— 进程一死，
            # 内存就没了。这是抓加壳样本唯一有效的时机：加壳样本的磁盘字节是
            # 加密的（哈希库和 YARA 全打不中），但它跑起来后内存里就是裸代码。
            # 进程已自行退出（WAIT_OBJECT_0）时无从扫描，如实记录，不要假装扫过。
            if result == WAIT_TIMEOUT:
                try:
                    from engine.memory_scanner import scan_process_memory
                    from engine.yara_scanner import YaraScanner
                    _rules = os.path.join(
                        os.path.dirname(os.path.abspath(__file__)), "yara_rules")
                    _mem = scan_process_memory(pid, YaraScanner(_rules))
                    memory_scan = _mem.to_dict()
                    memory_scan["interpretation"] = (
                        "磁盘未命中但内存命中 —— 高度怀疑加壳或注入"
                        if _mem.hits else
                        "内存亦未命中")
                    if _mem.hits:
                        self._log("warning",
                                  "内存镜像命中 %d 条规则（磁盘未命中 -> 疑似加壳/注入）"
                                  % len(_mem.hits))
                    else:
                        self._log("info", "内存镜像未命中")
                except Exception as e:
                    memory_scan = {"ok": False, "error": str(e)}
                    degraded.append(f"内存镜像扫描失败: {e}")
                    self._log("error", f"内存镜像扫描失败: {e}")
            else:
                memory_scan = {"ok": False,
                               "error": "进程已自行退出，无法扫描内存",
                               "interpretation": "未覆盖内存"}

        except Exception as e:
            self._log("error", f"沙箱分析异常: {e}")
            memory_scan = {"ok": False, "error": "分析异常，未执行内存扫描"}
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

            # 10. 删除网络阻断规则（必须在 finally 中，绝不留在系统上）
            if firewall_rule:
                removed, unblock_err = _network_unblock_rule(firewall_rule)
                isolation["firewall_rule_removed"] = removed
                if not removed:
                    # 规则没删掉 = 系统上仍留着一条阻断规则，必须显式告警
                    isolation["network_blocked"] = False
                    cleanup_error = f"防火墙规则 {firewall_rule} 删除失败: {unblock_err}"
                else:
                    # 复核：确认系统上确实查不到这条规则
                    if _network_rule_exists(firewall_rule):
                        isolation["firewall_rule_removed"] = False
                        isolation["network_blocked"] = False
                        cleanup_error = f"防火墙规则 {firewall_rule} 删除后仍能查到"
                if cleanup_error:
                    degraded.append(cleanup_error)
                    self._log("error", cleanup_error)
                else:
                    self._log("info", f"防火墙规则已删除: {firewall_rule}")

            # 11. 隔离引擎清理（和防火墙规则删除、工作目录清理并列，
            #     且必须在 TerminateJobObject 之后 —— 进程还活着时目录删不掉）
            for _eng in isolation_engines:
                _eng_name = getattr(_eng, "name", "?")
                try:
                    _eng.cleanup()
                except Exception as e:
                    degraded.append(
                        f"隔离引擎清理异常({_eng_name}): {type(e).__name__}: {e}")
                    continue
                if getattr(_eng, "cleanup_error", ""):
                    degraded.append(
                        f"隔离引擎清理失败({_eng_name}): {_eng.cleanup_error}")
                else:
                    self._log("info", f"隔离引擎已清理: {_eng_name}")

            # 12. 清理沙箱工作目录（兜底清扫，防止引擎没管到的残留）
            if low_box_dir:
                wd_err = _cleanup_sandbox_workdir(low_box_dir)
                if wd_err:
                    degraded.append(f"沙箱工作目录清理失败: {wd_err}")

        isolation["degraded_reason"] = "; ".join(degraded)
        elapsed = round(time.time() - start_time, 2)

        # 13. 生成报告
        report = self._generate_report(
            file_path, behaviors, elapsed, report_id, isolation=isolation
        )

        # 12b. 内存镜像扫描结果 + 磁盘/内存对照结论
        #      "磁盘无、内存有" 是抓加壳样本最有价值的信号 —— 正常软件不会
        #      出现这种组合，它几乎不可能是巧合。所以这里可以**提升** verdict：
        #      磁盘没判恶意、而内存里命中了中高置信度规则 => 加壳或注入。
        report["memory_scan"] = memory_scan
        _mem_hits = (memory_scan or {}).get("hits") or []
        _strong = [h for h in _mem_hits
                   if (h.get("confidence") or "").lower() in ("high", "medium")]
        if _mem_hits:
            if _strong and report.get("verdict") in ("clean", "unknown"):
                report["verdict"] = "malicious"
                try:
                    report["confidence"] = max(float(report.get("confidence") or 0), 0.8)
                except Exception:
                    report["confidence"] = 0.8
                if isinstance(report.get("memory_scan"), dict):
                    report["memory_scan"]["interpretation"] = (
                        "磁盘无特征但内存命中 —— 高度怀疑加壳或注入")
            ri = report.setdefault("risk_indicators", [])
            ri.append("内存镜像命中 %d 条规则（中高置信度 %d 条）"
                      % (len(_mem_hits), len(_strong)))
            for h in _mem_hits[:5]:
                ri.append("内存规则: %s (置信度 %s, 模块 %s)" % (
                    h.get("rule"), h.get("confidence"), h.get("_module")))
            self._log("warning", "内存镜像命中 %d 条规则" % len(_mem_hits))

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
                            try:
                                img = child.exe()
                            except (psutil.Error, OSError):
                                img = ""
                            # 控制台宿主（conhost）单独归类：它是 Windows 为
                            # 控制台程序自动拉起的，不是样本"拉起了子进程"的证据。
                            # 只降级这一类；来路不明的可执行文件仍然按
                            # child_process/high 记（见 _is_console_host）。
                            host = _is_console_host(img, cmd)
                            behaviors.append({
                                "type": "console_host" if host else "child_process",
                                "detail": (f"系统控制台宿主进程: {cmd} (PID={child.pid})"
                                           if host else
                                           f"创建子进程: {cmd} (PID={child.pid})"),
                                "severity": "low" if host else "high",
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
                         elapsed: float, report_id: str,
                         isolation: dict | None = None) -> dict:
        """生成分析报告

        根据收集到的行为判定 verdict 与 confidence。
        进程被成功启动但没有任何可观测行为时返回 unknown（而不是 clean）：
        "没看到行为"不等于"安全"。

        Args:
            file_path: 分析的文件路径
            behaviors: 行为列表
            elapsed: 实际耗时（秒）
            report_id: 报告 ID
            isolation: 隔离状态字典（写入报告的 isolation 字段）

        Returns:
            报告字典，包含 verdict / confidence / behaviors /
            risk_indicators / isolation
        """
        # 计算风险评分
        #
        # 2026-10-03 实测修正：notepad.exe 原先被判 malicious，分数刚好 70：
        #     读自己的资源 notepad.exe.mun + 语言包  (medium×2 = 30)
        #   + 进程被超时终止                        (low     =  5)
        #   + 超时本身                              (medium  = 15)
        #   + 超时固定加成                          (        = 20)
        #   = 70 → 踩在 >= 70 判 malicious 的线上，一分不差。
        # 但这三件事全是**正常 GUI 程序的标准行为** —— GUI 程序永远不会自己退出，
        # 读自己的资源更是必然。所以这里加两道约束：
        #   ① 读系统目录 / 自己所在目录 / Program Files 的 file_access 不计风险
        #   ② 判 malicious **必须**拿到至少一个强指标
        #      （高危行为、子进程、网络连接），光靠"超时 + 读文件"堆分不够
        #
        # 2026-10-03 第二处实测修正：控制台程序一律被判 malicious。
        # notepad 是 GUI 程序，所以第一处修正没暴露这条 —— 只要样本是控制台
        # 程序，Windows 就会给它配一个 conhost.exe，监控把它记成
        # child_process/high，于是（+30 高危 +10 子进程 +5 退出 +15 超时
        # +20 超时加成）= 80 → malicious。实测 choice.exe 在 copy / none
        # 两个后端上都是 risk=80/verdict=malicious。
        #   ③ 系统目录里的 conhost.exe / OpenConsole.exe 按 console_host
        #      单独归类，只记录、不计分（见 _is_console_host）；
        #      非系统宿主子进程的分数从 +10 提到 +40，保证"真拉起了可疑
        #      子进程"仍然单独够到 70 分线，不因这次豁免被一起降级。
        _sysroot = os.environ.get("SystemRoot", r"C:\Windows").lower()
        _trusted_dirs = [
            d.lower() for d in (
                os.environ.get("ProgramFiles", ""),
                os.environ.get("ProgramFiles(x86)", ""),
                os.environ.get("ProgramData", ""),
                os.path.dirname(os.path.abspath(file_path)),
            ) if d
        ]

        def _benign_access(detail: str) -> bool:
            """读系统目录 / 自己所在目录 / Program Files —— 不算风险"""
            d = (detail or "").lower()
            if _sysroot and _sysroot in d:
                return True
            return any(t and t in d for t in _trusted_dirs)

        risk_score = 0
        risk_indicators: list[str] = []
        strong_kinds: set = set()      # 强指标：只有它们有资格支撑 malicious
        benign_count = 0
        host_child_count = 0

        # 各类行为计数
        behavior_counts: dict[str, int] = {}
        for b in behaviors:
            btype = b.get("type", "unknown")
            severity = b.get("severity", "low")

            # ① 正常文件读取不计风险（仍然出现在报告里，只是不加分）
            if btype == "file_access" and _benign_access(str(b.get("detail", ""))):
                benign_count += 1
                continue

            # ①b 系统控制台宿主（conhost.exe / OpenConsole.exe）不计风险。
            #     2026-10-03 实测修正：Windows 上任何控制台程序都会被系统
            #     拉起一个 conhost，它只说明"样本是控制台程序"，不说明样本
            #     拉起了子进程 —— 修复前它被记成 child_process/high，
            #     无害的 choice.exe 因此拿到 risk=80/verdict=malicious
            #     （copy 与 none 两个后端都一样；notepad 是 GUI 所以没暴露）。
            #     仍然留在 behaviors 里**可见**，只是不计分。
            if btype == "console_host":
                host_child_count += 1
                continue

            behavior_counts[btype] = behavior_counts.get(btype, 0) + 1

            # 根据严重程度累加风险分
            if severity == "high":
                risk_score += 30
                strong_kinds.add("high:" + btype)
            elif severity == "medium":
                risk_score += 15
            elif severity == "low":
                risk_score += 5

        if benign_count:
            risk_indicators.append("正常文件读取 %d 次（系统/自身目录，不计风险）" % benign_count)
        if host_child_count:
            risk_indicators.append(
                "系统控制台宿主进程 %d 次（conhost/OpenConsole，控制台程序由 Windows "
                "自动拉起，不计风险）" % host_child_count)

        # 高风险行为指标
        if behavior_counts.get("child_process", 0) > 0:
            # 这里只统计**非系统宿主**的子进程（conhost 已在上面剥离）。
            # 原为 +10；剥离 conhost 后它是"样本主动拉起外部可执行文件"的
            # 唯一证据 —— 修复前那 70 分线其实一半靠 conhost 撑着（+30 高危
            # +10 子进程）。若仍按 +10 计，单个真实子进程只剩 45 分，
            # verdict 会从 malicious 掉到 suspicious —— 那就是把真信号一起
            # 修瞎了。实测控制样本（无害父进程拉起一个非常规名字的无害子进程）
            # 补足到 +40 后仍为 malicious/risk=75，与修复前一致。
            risk_indicators.append("创建非系统宿主子进程（拉起外部可执行文件）")
            risk_score += 40
            strong_kinds.add("child_process")
        if behavior_counts.get("network", 0) > 0:
            risk_indicators.append("发起网络连接")
            risk_score += 20
            strong_kinds.add("network")
        if behavior_counts.get("file_access", 0) >= 5:
            risk_indicators.append("大量文件访问（非系统目录）")
            risk_score += 15
        if behavior_counts.get("timeout", 0) > 0:
            # 超时被杀 = 行为不可知，不能因为"只看到超时"就判 clean。
            # ⚠️ 但超时**不是强指标** —— GUI 程序（记事本、画图…）永远不会
            # 自己退出，把它当恶意证据会把所有带界面的程序全判成病毒。
            risk_indicators.append("运行超时未退出（行为不可知）")
            risk_score += 20
        if behavior_counts.get("error", 0) > 0:
            risk_indicators.append("运行异常")

        # 限制风险分上限
        risk_score = min(risk_score, 100)

        # 判定 verdict
        if behavior_counts.get("error", 0) > 0:
            # 分析过程本身出错：不下安全结论
            verdict = "unknown"
            confidence = 0.0
        elif risk_score >= 70 and strong_kinds:
            # ② 必须拿到强指标才敢判 malicious
            verdict = "malicious"
            confidence = round(risk_score / 100, 2)
            risk_indicators.append("强指标: " + ", ".join(sorted(strong_kinds)))
        elif risk_score >= 30 or behavior_counts.get("timeout", 0) > 0:
            verdict = "suspicious"
            confidence = round(risk_score / 100, 2)
            if behavior_counts.get("timeout", 0) > 0 and not strong_kinds:
                risk_indicators.append(
                    "仅有超时、无强指标 —— 不足以判恶意（GUI 程序本就不会自行退出）")
        elif not behaviors:
            # 进程跑完却没有采集到任何行为：无法判定，不能算 clean
            verdict = "unknown"
            confidence = 0.0
            risk_indicators.append("未观测到任何行为，无法判定")
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
            "isolation": isolation if isolation is not None else _empty_isolation(),
            "elapsed_sec": elapsed,
            "timestamp": time.time(),
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        return report

    def _make_unknown_report(self, file_path: str, report_id: str,
                             reason: str, isolation: dict | None = None) -> dict:
        """生成 unknown 报告（非 PE 文件 / 文件缺失 / 分析失败）

        这里绝不能返回 clean：分析不出来不等于安全。

        Args:
            file_path: 文件路径
            report_id: 报告 ID
            reason: 无法分析的原因
            isolation: 隔离状态字典

        Returns:
            verdict="unknown" 的报告字典
        """
        return {
            "report_id": report_id,
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path) if os.path.isfile(file_path) else 0,
            "verdict": "unknown",
            "confidence": 0.0,
            "risk_score": 0,
            "behaviors": [],
            "risk_indicators": [],
            "behavior_counts": {},
            "isolation": isolation if isolation is not None else _empty_isolation(
                reason="未进入沙箱执行，无隔离"
            ),
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
        verdict = report.get("verdict", "unknown")
        with self._stats_lock:
            self._stats["total_analyzed"] += 1
            if verdict == "malicious":
                self._stats["malicious_detected"] += 1
            elif verdict == "suspicious":
                self._stats["suspicious_detected"] += 1
            elif verdict == "unknown":
                self._stats["analysis_failed"] += 1
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
            "isolation": report.get("isolation", _empty_isolation()),
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
            "isolation_capabilities": {
                "job_object": True,
                "network_block": IS_WINDOWS,
                "low_integrity": IS_WINDOWS,
                "integrity_sid": INTEGRITY_SID_LOW,
                "sandbox_root": os.path.join(
                    os.environ.get("TEMP") or "", SANDBOX_ROOT_DIRNAME
                ),
                "isolation_engine_available": _HAS_ISOLATION_ENGINE,
                "isolation_engine_default": (
                    _DEFAULT_ISOLATION_ENGINE if _HAS_ISOLATION_ENGINE else "none"),
                "isolation_engines": (
                    _describe_isolation_engines()
                    if _HAS_ISOLATION_ENGINE else {}
                ),
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
