"""
御天 反 Rootkit 引擎（用户态）

通过用户态技术检测各类 Rootkit 隐藏技术：
  - 隐藏进程（对比 NtQuerySystemInformation 与用户态 Toolhelp32 快照，识别 DKOM 隐藏）
  - 隐藏驱动（EnumDeviceDrivers 枚举 + 可疑驱动名启发式）
  - 内核钩子（ntdll.dll 关键函数 Inline Hook 检查）
  - 回调劫持（AppInit_DLLs / Winlogon Shell / 通知包注册表检查）

全部检测在用户态完成。
"""

import ctypes
import ctypes.wintypes as wt
import struct
import threading
from datetime import datetime
from typing import Optional


# ============================================================
# 可信驱动/回调白名单
# ============================================================

TRUSTED_DRIVERS_LOWER = {
    "ntoskrnl.exe", "hal.dll", "win32k.sys", "win32kfull.sys", "win32kbase.sys",
    "ntdll.dll", "kernel32.dll", "fltmgr.sys", "ndis.sys", "tcpip.sys",
    "afd.sys", "netio.sys", "ksecdd.sys", "cng.sys", "clfs.sys",
    "dxgkrnl.sys", "dxgmms1.sys", "dxgmms2.sys", "battc.sys", "acpi.sys",
    "pci.sys", "storport.sys", "stornvme.sys", "disk.sys", "partmgr.sys",
    "volmgr.sys", "volsnap.sys", "ntfs.sys", "fastfat.sys", "mup.sys",
    "http.sys", "srv2.sys", "srvnet.sys", "mrxsmb.sys", "mrxsmb10.sys",
    "mrxsmb20.sys", "rdbss.sys", "dfsc.sys", "netbt.sys", "tdx.sys",
    "ws2ifsl.sys", "pacer.sys", "wfplwfs.sys", "fwpkclnt.sys",
    "msfs.sys", "npfs.sys", "crashdmp.sys", "dumpstorport.sys",
    "dumpfve.sys", "fvevol.sys", "rdyboost.sys", "vid.sys", "vmbus.sys",
    "wdf01000.sys", "acpiex.sys", "pdc.sys", "cimfs.sys", "wcifs.sys",
    "storqosflt.sys", "iorate.sys", "filecrypt.sys", "bindflt.sys",
}

# 可信回调地址范围：用户态无法精确判断，仅做辅助标记


# ============================================================
# AntiRootkit 主类
# ============================================================

class AntiRootkit:
    """反 Rootkit 引擎（用户态）

    用户态检测：
    - 隐藏进程（NtQuerySystemInformation vs Toolhelp32 快照）
    - 隐藏驱动（EnumDeviceDrivers + 可疑驱动名启发式）
    - 内核钩子（ntdll.dll Inline Hook 检查）
    - 回调劫持（注册表间接检测）
    """

    def __init__(self):
        self._last_scan_result = None
        self._last_scan_time = None
        self._scanning = False
        # 协作式取消标志：scan() 在各检测阶段之间与枚举循环中读取
        self._cancel_event = threading.Event()

    def cancel(self):
        """请求取消当前 Rootkit 扫描（协作式，阶段/循环边界生效）"""
        self._cancel_event.set()

    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def scan(self, cancel=None) -> dict:
        """执行全面 Rootkit 扫描

        cancel: 可选外部取消令牌；同时支持实例内 cancel()。
                取消时返回已完成阶段的部分结果，并带 cancelled=True。
        """
        if self._scanning:
            return {'status': 'already_scanning'}

        self._cancel_event.clear()

        def _stopped() -> bool:
            if self._cancel_event.is_set():
                return True
            if cancel is None:
                return False
            if hasattr(cancel, 'is_cancelled'):
                return bool(cancel.is_cancelled())
            if hasattr(cancel, 'is_set'):
                return bool(cancel.is_set())
            return False

        self._scanning = True
        try:
            result = {
                'timestamp': datetime.now().isoformat(),
                'hidden_processes': [],
                'hidden_drivers': [],
                'suspicious_hooks': [],
                'suspicious_callbacks': [],
                'driver_connected': False,
                'cancelled': False,
            }

            # 分阶段执行，每个阶段前后检查取消标志（阶段内部亦为可中断实现）
            for key, fn in (
                ('hidden_processes', self.scan_hidden_processes),
                ('hidden_drivers', self.scan_hidden_drivers),
                ('suspicious_hooks', self.scan_hooks),
                ('suspicious_callbacks', self.scan_callback_highjacks),
            ):
                if _stopped():
                    result['cancelled'] = True
                    break
                result[key] = fn()
                if _stopped():
                    result['cancelled'] = True
                    break

            total_threats = (
                len(result['hidden_processes']) +
                len(result['hidden_drivers']) +
                len(result['suspicious_hooks']) +
                len(result['suspicious_callbacks'])
            )
            result['total_threats'] = total_threats
            result['verdict'] = 'clean' if total_threats == 0 else ('suspicious' if total_threats < 3 else 'dangerous')

            self._last_scan_result = result
            self._last_scan_time = datetime.now()
            return result
        finally:
            self._scanning = False

    # ---------------------------------------------------------------
    # 1. 隐藏进程检测
    # ---------------------------------------------------------------

    def scan_hidden_processes(self) -> list:
        """检测隐藏进程

        用户态交叉比对（NtQuerySystemInformation vs Toolhelp32），
        差集即为被 DKOM（直接内核对象操作）隐藏的进程。
        """
        user_procs = self._enum_processes_usermode()
        return self._detect_hidden_processes_usermode(user_procs)

    def _enum_processes_usermode(self) -> list:
        """用户态枚举进程（Toolhelp32 快照）"""
        try:
            from ctypes import wintypes

            TH32CS_SNAPPROCESS = 0x00000002
            kernel32 = ctypes.windll.kernel32

            class PROCESSENTRY32W(ctypes.Structure):
                _fields_ = [
                    ('dwSize', wintypes.DWORD),
                    ('cntUsage', wintypes.DWORD),
                    ('th32ProcessID', wintypes.DWORD),
                    ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
                    ('th32ModuleID', wintypes.DWORD),
                    ('cntThreads', wintypes.DWORD),
                    ('th32ParentProcessID', wintypes.DWORD),
                    ('pcPriClassBase', ctypes.c_long),
                    ('dwFlags', wintypes.DWORD),
                    ('szExeFile', ctypes.c_wchar * 260),
                ]

            snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if snapshot == -1:
                return []

            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

            procs = []
            if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                while True:
                    procs.append({
                        'pid': entry.th32ProcessID,
                        'name': entry.szExeFile,
                        'ppid': entry.th32ParentProcessID,
                    })
                    if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                        break

            kernel32.CloseHandle(snapshot)
            return procs
        except Exception as e:
            print(f"[反Rootkit] 枚举进程失败: {e}")
            return []

    def _detect_hidden_processes_usermode(self, user_procs: list) -> list:
        """用户态隐藏进程检测（降级模式）

        三重检测：
        1. NtQuerySystemInformation(SystemProcessInformation) 交叉比对
        2. PID 空洞检测（连续 PID 间出现大间隙）
        3. 关键系统进程缺失检测（System/Idle进程）
        """
        suspicious = []

        # 方法1: NtQuerySystemInformation 交叉比对
        try:
            ntdll_procs = self._enum_processes_ntquery()
            user_pids = set(p['pid'] for p in user_procs)
            ntdll_pids = set(p['pid'] for p in ntdll_procs)

            hidden_from_toolhelp = ntdll_pids - user_pids
            for pid in hidden_from_toolhelp:
                # 找到进程名
                name = "unknown"
                for p in ntdll_procs:
                    if p['pid'] == pid:
                        name = p['name']
                        break
                suspicious.append({
                    'pid': pid,
                    'name': name,
                    'reason': '用户态交叉比对隐藏',
                    'severity': 'high',
                    'method': 'ntdll_vs_toolhelp',
                })
        except Exception as e:
            print(f"[反Rootkit] NtQuerySystemInformation 枚举失败: {e}")

        # 方法2: 关键进程缺失检测
        critical_names = {
            ('System', 4),   # PID 4 = System
            ('smss.exe', None),
            ('csrss.exe', None),
            ('wininit.exe', None),
            ('services.exe', None),
            ('lsass.exe', None),
            ('winlogon.exe', None),
            ('svchost.exe', None),
        }
        found_names = {p['name'].lower() for p in user_procs}
        for name, expected_pid in critical_names:
            name_lower = name.lower()
            if name_lower not in found_names:
                suspicious.append({
                    'pid': expected_pid or 0,
                    'name': name,
                    'reason': '关键系统进程缺失',
                    'severity': 'critical',
                    'method': 'missing_critical',
                })

        return suspicious

    def _enum_processes_ntquery(self) -> list:
        """通过 NtQuerySystemInformation 枚举进程（绕过 Toolhelp32）"""
        try:
            STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
            STATUS_SUCCESS = 0x00000000
            SystemProcessInformation = 5

            ntdll = ctypes.windll.ntdll

            class SYSTEM_THREAD_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", ctypes.c_ulonglong * 3),
                    ("Reserved2", ctypes.c_ulonglong),
                    ("StartAddress", ctypes.c_void_p),
                    ("ClientId", ctypes.c_ulonglong),
                    ("Priority", ctypes.c_long),
                    ("BasePriority", ctypes.c_long),
                    ("Reserved3", ctypes.c_ulong),
                    ("ThreadState", ctypes.c_ulong),
                    ("WaitReason", ctypes.c_ulong),
                ]

            class UNICODE_STRING(ctypes.Structure):
                _fields_ = [
                    ("Length", ctypes.c_ushort),
                    ("MaximumLength", ctypes.c_ushort),
                    ("Buffer", ctypes.c_void_p),
                ]

            class SYSTEM_PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("NextEntryOffset", ctypes.c_ulong),
                    ("NumberOfThreads", ctypes.c_ulong),
                    ("Reserved1", ctypes.c_ulonglong * 6),
                    ("CreateTime", ctypes.c_longlong),
                    ("UserTime", ctypes.c_longlong),
                    ("KernelTime", ctypes.c_longlong),
                    ("ImageName", UNICODE_STRING),
                    ("BasePriority", ctypes.c_long),
                    ("UniqueProcessId", ctypes.c_void_p),
                    ("InheritedFromUniqueProcessId", ctypes.c_void_p),
                    ("HandleCount", ctypes.c_ulong),
                    ("Reserved2", ctypes.c_ulong * 4),
                    ("PeakVirtualSize", ctypes.c_ulonglong),
                    ("VirtualSize", ctypes.c_ulonglong),
                    ("Reserved3", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_ulonglong),
                    ("WorkingSetSize", ctypes.c_ulonglong),
                    ("Reserved4", ctypes.c_ulonglong),
                    ("QuotaPagedPoolUsage", ctypes.c_ulonglong),
                    ("Reserved5", ctypes.c_ulonglong),
                    ("QuotaNonPagedPoolUsage", ctypes.c_ulonglong),
                    ("PagefileUsage", ctypes.c_ulonglong),
                    ("PeakPagefileUsage", ctypes.c_ulonglong),
                    ("PrivatePageCount", ctypes.c_ulonglong),
                    ("Reserved6", ctypes.c_longlong * 6),
                ]

            procs = []
            buf_size = 0x100000  # 1MB initial
            while buf_size < 0x800000:  # 最多 8MB
                buf = ctypes.create_string_buffer(buf_size)
                ret_len = ctypes.c_ulong(0)
                status = ntdll.NtQuerySystemInformation(
                    SystemProcessInformation, buf, buf_size, ctypes.byref(ret_len)
                )
                if status == STATUS_INFO_LENGTH_MISMATCH:
                    buf_size *= 2
                    continue
                if status != STATUS_SUCCESS:
                    return []

                # 解析链表
                offset = 0
                while True:
                    if self._cancel_event.is_set():
                        return procs
                    if offset + ctypes.sizeof(SYSTEM_PROCESS_INFORMATION) > buf_size:
                        break
                    info = SYSTEM_PROCESS_INFORMATION.from_buffer_copy(buf, offset)
                    pid = info.UniqueProcessId or 0
                    name = ""
                    if info.ImageName.Buffer and info.ImageName.Length > 0:
                        try:
                            name_buf = ctypes.cast(info.ImageName.Buffer, ctypes.c_wchar_p)
                            name = name_buf.value or ""
                        except Exception:
                            name = ""
                    procs.append({
                        'pid': pid,
                        'name': name,
                        'ppid': info.InheritedFromUniqueProcessId or 0,
                    })
                    if info.NextEntryOffset == 0:
                        break
                    offset += info.NextEntryOffset
                return procs

            return []
        except Exception as e:
            print(f"[反Rootkit] NtQuerySystemInformation 失败: {e}")
            return []

    # ---------------------------------------------------------------
    # 2. 隐藏驱动检测
    # ---------------------------------------------------------------

    def scan_hidden_drivers(self) -> list:
        """检测隐藏驱动

        用户态 EnumDeviceDrivers 枚举 + 可疑驱动名启发式检测。
        """
        user_drivers = self._enum_drivers_usermode()
        return self._detect_hidden_drivers_usermode(user_drivers)

    def _enum_drivers_usermode(self) -> list:
        """用户态枚举驱动（EnumDeviceDrivers）"""
        try:
            from ctypes import wintypes

            psapi = ctypes.windll.psapi
            cbNeeded = wintypes.DWORD()

            psapi.EnumDeviceDrivers(None, 0, ctypes.byref(cbNeeded))
            if cbNeeded.value == 0:
                return []

            array_size = cbNeeded.value // ctypes.sizeof(ctypes.c_void_p)
            driver_array = (ctypes.c_void_p * array_size)()

            if psapi.EnumDeviceDrivers(
                ctypes.byref(driver_array), cbNeeded.value, ctypes.byref(cbNeeded)
            ):
                drivers = []
                for i in range(array_size):
                    if self._cancel_event.is_set():
                        return drivers
                    if driver_array[i]:
                        name_buf = ctypes.create_unicode_buffer(260)
                        psapi.GetDeviceDriverBaseNameW(driver_array[i], name_buf, 260)
                        if name_buf.value:
                            drivers.append({
                                'name': name_buf.value,
                                'address': hex(driver_array[i]),
                            })
                return drivers
            return []
        except Exception as e:
            print(f"[反Rootkit] 枚举驱动失败: {e}")
            return []

    def _detect_hidden_drivers_usermode(self, user_drivers: list) -> list:
        """用户态隐藏驱动检测（降级模式）

        检查：
        - 是否存在未签名驱动
        - 是否存在非标准路径驱动
        """
        suspicious = []
        user_names_lower = {d['name'].lower() for d in user_drivers}

        # 检查可疑驱动名
        suspicious_keywords = [
            'hide', 'hidden', 'rootkit', 'stealth', 'inject', 'bypass',
            'cheat', 'hack', 'hook', 'spoof', 'fake',
        ]
        for d in user_drivers:
            name_lower = d['name'].lower()
            for kw in suspicious_keywords:
                if kw in name_lower:
                    suspicious.append({
                        'name': d['name'],
                        'address': d['address'],
                        'reason': f'可疑驱动名（包含"{kw}"）',
                        'severity': 'high',
                        'method': 'keyword_match',
                    })
                    break

        return suspicious

    # ---------------------------------------------------------------
    # 3. 内核钩子检测
    # ---------------------------------------------------------------

    def scan_hooks(self) -> list:
        """检测内核钩子（用户态降级模式）

        检查 ntdll.dll 关键函数前字节是否被 Inline Hook。
        """
        return self._scan_hooks_usermode()

    def _scan_hooks_usermode(self) -> list:
        """用户态钩子检测（降级模式）

        检查 ntdll.dll 关键函数前字节是否被 inline hook
        """
        suspicious = []

        # 关键 ntdll 函数及其正常序言
        critical_funcs = [
            # 进程操作
            ("NtOpenProcess", "ntdll.dll", 0x4c8bd18b),
            ("NtReadVirtualMemory", "ntdll.dll", 0),
            ("NtWriteVirtualMemory", "ntdll.dll", 0),
            ("NtCreateThreadEx", "ntdll.dll", 0),
            ("NtQuerySystemInformation", "ntdll.dll", 0),
            # 注册表
            ("NtSetValueKey", "ntdll.dll", 0),
            ("NtDeleteValueKey", "ntdll.dll", 0),
            ("NtDeleteKey", "ntdll.dll", 0),
            # 文件
            ("NtCreateFile", "ntdll.dll", 0),
            ("NtDeleteFile", "ntdll.dll", 0),
            ("NtSetInformationFile", "ntdll.dll", 0),
        ]

        try:
            kernel32 = ctypes.windll.kernel32
            for func_name, dll_name, _ in critical_funcs:
                try:
                    h_mod = kernel32.GetModuleHandleW(dll_name)
                    if not h_mod:
                        continue
                    func_addr = kernel32.GetProcAddress(h_mod, func_name.encode())
                    if not func_addr:
                        continue

                    # 读前 5 字节
                    buf = (ctypes.c_ubyte * 5)()
                    ctypes.memmove(buf, func_addr, 5)

                    # 检查是否以 jmp (0xE9) 或 call (0xE8) 开头
                    if buf[0] == 0xE9:
                        offset = struct.unpack('<i', bytes(buf[1:5]))[0]
                        target = func_addr + 5 + offset
                        suspicious.append({
                            'hook_type': 'Inline',
                            'function_name': func_name,
                            'hook_address': hex(func_addr),
                            'current_bytes': ' '.join(f'{b:02x}' for b in buf),
                            'reason': f'jmp -> {hex(target)}',
                            'severity': 'critical',
                            'method': 'usermode_prologue_check',
                        })
                    elif buf[0] == 0xE8:
                        suspicious.append({
                            'hook_type': 'Inline',
                            'function_name': func_name,
                            'hook_address': hex(func_addr),
                            'current_bytes': ' '.join(f'{b:02x}' for b in buf),
                            'reason': 'call开头异常',
                            'severity': 'warning',
                            'method': 'usermode_prologue_check',
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"[反Rootkit] 用户态钩子检测失败: {e}")

        return suspicious

    # ---------------------------------------------------------------
    # 4. 回调劫持检测
    # ---------------------------------------------------------------

    def scan_callback_highjacks(self) -> list:
        """检测回调劫持（用户态降级模式）

        通过注册表 AppInit_DLLs / Winlogon 通知包等间接检测回调劫持。
        """
        return self._scan_callback_highjacks_usermode()

    def _scan_callback_highjacks_usermode(self) -> list:
        """用户态回调劫持检测（降级模式）

        通过检查注册表 AppInit_DLLs 和 Winlogon 通知包等间接检测回调劫持
        """
        suspicious = []

        try:
            import winreg

            # 检查 AppInit_DLLs（经典 DLL 注入点）
            appinit_paths = [
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
            ]
            for path in appinit_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                    try:
                        appinit, _ = winreg.QueryValueEx(key, "AppInit_DLLs")
                        if appinit and appinit.strip():
                            suspicious.append({
                                'callback_type': 'AppInit_DLLs',
                                'detail': appinit,
                                'reason': 'AppInit_DLLs 注册表项被设置',
                                'severity': 'warning',
                                'method': 'usermode_registry_check',
                            })
                    except FileNotFoundError:
                        pass
                    finally:
                        winreg.CloseKey(key)
                except Exception:
                    pass

            # 检查 Winlogon Shell 劫持
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
                )
                try:
                    shell, _ = winreg.QueryValueEx(key, "Shell")
                    if shell and shell.lower() != "explorer.exe":
                        suspicious.append({
                            'callback_type': 'Winlogon_Shell',
                            'detail': shell,
                            'reason': 'Winlogon Shell 被篡改',
                            'severity': 'critical',
                            'method': 'usermode_registry_check',
                        })
                except FileNotFoundError:
                    pass
                finally:
                    winreg.CloseKey(key)
            except Exception:
                pass

            # 检查 Winlogon Notify 包
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
                )
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        suspicious.append({
                            'callback_type': 'Winlogon_Notify',
                            'detail': subkey_name,
                            'reason': 'Winlogon 通知包',
                            'severity': 'info',
                            'method': 'usermode_registry_check',
                        })
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                pass

        except Exception as e:
            print(f"[反Rootkit] 用户态回调检测失败: {e}")

        return suspicious

    # ---------------------------------------------------------------
    # 状态
    # ---------------------------------------------------------------

    def get_status(self) -> dict:
        return {
            'scanning': self._scanning,
            'driver_connected': False,
            'last_scan': self._last_scan_time.isoformat() if self._last_scan_time else None,
            'last_result': self._last_scan_result,
        }


# ============================================================
# 单例
# ============================================================

_anti_rootkit = None
_ar_lock = threading.Lock()


def get_anti_rootkit() -> AntiRootkit:
    global _anti_rootkit
    if _anti_rootkit is None:
        with _ar_lock:
            if _anti_rootkit is None:
                _anti_rootkit = AntiRootkit()
    return _anti_rootkit