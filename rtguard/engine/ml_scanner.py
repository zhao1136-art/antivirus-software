"""
PE 文件机器学习检测引擎 — EMBER v2 2381 维特征提取 + 规则评分回退

特征维度组成（共 2381 维）:
  ByteHistogram          256
  ByteEntropyHistogram   256
  StringExtractor        104
  GeneralFileInfo         10
  HeaderFileInfo          62
  SectionInfo            255
  ImportsInfo           1280
  ExportsInfo            128
  DataDirectories         30

设计策略:
  - 优先使用 pefile 库进行 PE 解析
  - pefile 不可用时回退到纯 Python 字节解析（struct 解析 PE 格式）
  - numpy 不可用时使用纯 Python 数学替代
  - 提供独立的规则评分机制作为机器学习特征的回退方案
"""
from __future__ import annotations

import re
import struct
import hashlib
import math
from typing import Optional

# ============================================================
# 尝试导入可选依赖
# ============================================================
try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False

try:
    import pefile
    _HAS_PEFILE = True
except ImportError:
    _HAS_PEFILE = False

# ============================================================
# 可疑 API 列表（约 50 个高危 Windows API）
# ============================================================
SUSPICIOUS_APIS: list[str] = [
    # ---- 进程注入 / Shellcode ----
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
    "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory",
    "ReadProcessMemory", "NtReadVirtualMemory", "NtWriteVirtualMemory",
    "OpenProcess", "NtOpenProcess",
    "ZwUnmapViewOfSection", "NtUnmapViewOfSection",
    # ---- 动态解析 / 反挂钩 ----
    "GetProcAddress", "LdrLoadDll",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetModuleHandleA", "GetModuleHandleW",
    # ---- 反调试 / 反分析 ----
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtQuerySystemInformation",
    "NtSetInformationProcess",
    "OutputDebugString", "OutputDebugStringA", "OutputDebugStringW",
    "GetTickCount", "QueryPerformanceCounter",
    "SetUnhandledExceptionFilter", "RtlAdjustPrivilege",
    # ---- 持久化 / 提权 ----
    "RegSetValueEx", "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyEx", "RegCreateKeyExA", "RegCreateKeyExW",
    "AdjustTokenPrivileges", "LookupPrivilegeValue", "LookupPrivilegeValueA",
    "OpenProcessToken",
    # ---- 网络通信 ----
    "InternetOpenUrl", "InternetOpenUrlA", "InternetOpenUrlW",
    "InternetOpenA", "InternetOpenW",
    "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
    "WinHttpOpen", "HttpSendRequestA", "HttpSendRequestW",
    "WSAStartup", "WSASocketA", "WSASocketW", "connect", "send", "recv",
    # ---- 加密（勒索软件特征）----
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
    "CryptAcquireContextA", "CryptAcquireContextW",
    # ---- 进程操作 ----
    "ShellExecute", "ShellExecuteA", "ShellExecuteW",
    "CreateProcess", "CreateProcessA", "CreateProcessW",
    "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
    "Thread32First", "Thread32Next",
    # ---- 键盘监控 ----
    "GetAsyncKeyState", "GetForegroundWindow", "FindWindowA", "FindWindowW",
    "GetKeyboardState",
    # ---- 其他可疑 ----
    "RtlGetVersion", "DeleteFileA", "DeleteFileW",
    "MoveFileExA", "MoveFileExW",
    # ---- 勒索软件/数据加密 ----
    "CryptAcquireContextA", "CryptAcquireContextW",
    "CryptReleaseContext", "CryptGenKey", "CryptExportKey",
    "CryptEncrypt", "CryptDecrypt", "CryptHashData",
    "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
    # ---- 自我复制/传播 ----
    "CopyFileA", "CopyFileW", "MoveFileA", "MoveFileW",
    "GetTempPathA", "GetTempPathW", "GetSystemDirectoryA",
    # ---- 进程挖矿 ----
    "GetSystemInfo", "GlobalMemoryStatusEx", "GetProcessAffinityMask",
    "SetProcessAffinityMask",
    # ---- 屏幕截图/监控 ----
    "CreateDC", "CreateCompatibleDC", "CreateCompatibleBitmap",
    "BitBlt", "GetDIBits", "GetPixel",
    # ---- 服务操作 ----
    "OpenSCManager", "CreateService", "StartService", "ControlService",
    "OpenService", "DeleteService",
    # ---- AMSI 绕过 ----
    "AmsiScanBuffer", "AmsiScanString", "AmsiInitialize",
]

# 预计算 SUSPICIOUS_APIS 的查找集合（大小写不敏感）
_SUSPICIOUS_SET: set[str] = {api.lower() for api in SUSPICIOUS_APIS}


# ============================================================
# 纯 Python FeatureHasher 替代（不依赖 scikit-learn）
# ============================================================
def _murmurish_hash_32(key: bytes, seed: int = 0) -> int:
    """仿 MurmurHash3 的 32 位哈希（纯 Python 实现）"""
    h = seed ^ (len(key) * 0x9E3779B9)
    h &= 0xFFFFFFFF
    for i in range(0, len(key) - len(key) % 4, 4):
        k = int.from_bytes(key[i:i + 4], "little", signed=False)
        k *= 0xCC9E2D51
        k &= 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k *= 0x1B873593
        k &= 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = h * 5 + 0xE6546B64
        h &= 0xFFFFFFFF
    tail = key[-(len(key) % 4):] if len(key) % 4 else b""
    if tail:
        k = int.from_bytes(tail.ljust(4, b"\x00"), "little", signed=False)
        k *= 0xCC9E2D51
        k &= 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k *= 0x1B873593
        k &= 0xFFFFFFFF
        h ^= k
    h ^= len(key)
    h ^= (h >> 16)
    h *= 0x85EBCA6B
    h &= 0xFFFFFFFF
    h ^= (h >> 13)
    h *= 0xC2B2AE35
    h &= 0xFFFFFFFF
    h ^= (h >> 16)
    return h


class FeatureHasher:
    """纯 Python 特征哈希器，替代 sklearn.feature_extraction.FeatureHasher"""

    def __init__(self, n_features: int, input_type: str = "string"):
        self.n_features = n_features
        self.input_type = input_type

    def transform(self, raw_items: list) -> "list[list[float]]":
        """将输入列表转换为哈希特征向量"""
        if self.input_type == "string":
            return self._transform_strings(raw_items)
        elif self.input_type == "pair":
            return self._transform_pairs(raw_items)
        else:
            return [[0.0] * self.n_features]

    def _transform_strings(self, raw_items: list) -> "list[list[float]]":
        """字符串列表哈希为一个向量"""
        if not raw_items or not raw_items[0]:
            return [[0.0] * self.n_features]
        items = raw_items[0] if isinstance(raw_items[0], list) else raw_items
        if not items:
            return [[0.0] * self.n_features]
        result = [0.0] * self.n_features
        for s in items:
            s = s.strip().lower() if isinstance(s, str) else str(s)
            if not s:
                continue
            h = _murmurish_hash_32(s.encode("utf-8", errors="replace"))
            idx = h % self.n_features
            sign = 1.0 if (h & 0x80000000) == 0 else -1.0
            result[idx] += sign
        return [result]

    def _transform_pairs(self, raw_items: list) -> "list[list[float]]":
        """键值对列表哈希为一个向量"""
        if not raw_items or not raw_items[0]:
            return [[0.0] * self.n_features]
        items = raw_items[0] if isinstance(raw_items[0], list) else raw_items
        if not items:
            return [[0.0] * self.n_features]
        result = [0.0] * self.n_features
        for pair in items:
            if not isinstance(pair, (list, tuple)) or len(pair) < 2:
                continue
            k, v = pair
            k = str(k).strip().lower()
            if not k:
                continue
            v = float(v) if isinstance(v, (int, float)) else 1.0
            h = _murmurish_hash_32(k.encode("utf-8", errors="replace"))
            idx = h % self.n_features
            sign = 1.0 if (h & 0x80000000) == 0 else -1.0
            result[idx] += sign * abs(v)
        return [result]


# ============================================================
# 纯 Python PE 解析器（当 pefile 不可用时）
# ============================================================

# PE 常量
IMAGE_DOS_SIGNATURE = 0x5A4D          # "MZ"
IMAGE_NT_SIGNATURE = 0x00004550       # "PE\x00\x00"

# 机器类型
MACHINE_TYPES = {
    0x014C: "IMAGE_FILE_MACHINE_I386",
    0x0200: "IMAGE_FILE_MACHINE_IA64",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0x01C4: "IMAGE_FILE_MACHINE_ARMNT",
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",
}

# COFF 特征标志
CHARACTERISTICS_FLAGS = [
    (0x0001, "IMAGE_FILE_RELOCS_STRIPPED"),
    (0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE"),
    (0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED"),
    (0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"),
    (0x0010, "IMAGE_FILE_AGGRESSIVE_WS_TRIM"),
    (0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE"),
    (0x0080, "IMAGE_FILE_BYTES_REVERSED_LO"),
    (0x0100, "IMAGE_FILE_32BIT_MACHINE"),
    (0x0200, "IMAGE_FILE_DEBUG_STRIPPED"),
    (0x0400, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "IMAGE_FILE_NET_RUN_FROM_SWAP"),
    (0x1000, "IMAGE_FILE_SYSTEM"),
    (0x2000, "IMAGE_FILE_DLL"),
    (0x4000, "IMAGE_FILE_UP_SYSTEM_ONLY"),
    (0x8000, "IMAGE_FILE_BYTES_REVERSED_HI"),
]

# 子系统
SUBSYSTEM_TYPES = {
    0: "IMAGE_SUBSYSTEM_UNKNOWN",
    1: "IMAGE_SUBSYSTEM_NATIVE",
    2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    3: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
    5: "IMAGE_SUBSYSTEM_OS2_CUI",
    7: "IMAGE_SUBSYSTEM_POSIX_CUI",
    9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    10: "IMAGE_SUBSYSTEM_EFI_APPLICATION",
    11: "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
    12: "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
    13: "IMAGE_SUBSYSTEM_EFI_ROM",
    14: "IMAGE_SUBSYSTEM_XBOX",
}

# DLL 特征标志
DLL_CHARACTERISTICS_FLAGS = [
    (0x0040, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"),
    (0x0080, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"),
    (0x0100, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"),
    (0x0200, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"),
    (0x0400, "IMAGE_DLLCHARACTERISTICS_NO_SEH"),
    (0x0800, "IMAGE_DLLCHARACTERISTICS_NO_BIND"),
    (0x1000, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"),
    (0x2000, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"),
]

# 节特征标志
SECTION_CHARACTERISTICS_FLAGS = [
    (0x00000008, "IMAGE_SCN_TYPE_NO_PAD"),
    (0x00000020, "IMAGE_SCN_CNT_CODE"),
    (0x00000040, "IMAGE_SCN_CNT_INITIALIZED_DATA"),
    (0x00000080, "IMAGE_SCN_CNT_UNINITIALIZED_DATA"),
    (0x00000100, "IMAGE_SCN_LNK_OTHER"),
    (0x00000200, "IMAGE_SCN_LNK_INFO"),
    (0x00000800, "IMAGE_SCN_LNK_REMOVE"),
    (0x00001000, "IMAGE_SCN_LNK_COMDAT"),
    (0x00008000, "IMAGE_SCN_GPREL"),
    (0x00020000, "IMAGE_SCN_MEM_PURGEABLE"),
    (0x00040000, "IMAGE_SCN_MEM_LOCKED"),
    (0x00080000, "IMAGE_SCN_MEM_PRELOAD"),
    (0x00100000, "IMAGE_SCN_ALIGN_1BYTES"),
    (0x00200000, "IMAGE_SCN_ALIGN_2BYTES"),
    (0x00300000, "IMAGE_SCN_ALIGN_4BYTES"),
    (0x00400000, "IMAGE_SCN_ALIGN_8BYTES"),
    (0x00500000, "IMAGE_SCN_ALIGN_16BYTES"),
    (0x00600000, "IMAGE_SCN_ALIGN_32BYTES"),
    (0x00700000, "IMAGE_SCN_ALIGN_64BYTES"),
    (0x00800000, "IMAGE_SCN_ALIGN_128BYTES"),
    (0x00900000, "IMAGE_SCN_ALIGN_256BYTES"),
    (0x00A00000, "IMAGE_SCN_ALIGN_512BYTES"),
    (0x00B00000, "IMAGE_SCN_ALIGN_1024BYTES"),
    (0x00C00000, "IMAGE_SCN_ALIGN_2048BYTES"),
    (0x00D00000, "IMAGE_SCN_ALIGN_4096BYTES"),
    (0x00E00000, "IMAGE_SCN_ALIGN_8192BYTES"),
    (0x01000000, "IMAGE_SCN_LNK_NRELOC_OVFL"),
    (0x02000000, "IMAGE_SCN_MEM_DISCARDABLE"),
    (0x04000000, "IMAGE_SCN_MEM_NOT_CACHED"),
    (0x08000000, "IMAGE_SCN_MEM_NOT_PAGED"),
    (0x10000000, "IMAGE_SCN_MEM_SHARED"),
    (0x20000000, "IMAGE_SCN_MEM_EXECUTE"),
    (0x40000000, "IMAGE_SCN_MEM_READ"),
    (0x80000000, "IMAGE_SCN_MEM_WRITE"),
]

# 资源类型 ID
RESOURCE_TYPES = {
    1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU",
    5: "RT_DIALOG", 6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT",
    9: "RT_ACCELERATOR", 10: "RT_RCDATA", 11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR", 14: "RT_GROUP_ICON",
    16: "RT_VERSION", 17: "RT_DLGINCLUDE", 19: "RT_PLUGPLAY",
    20: "RT_VXD", 21: "RT_ANICURSOR", 22: "RT_ANIICON",
    23: "RT_HTML", 24: "RT_MANIFEST",
}

DATA_DIRECTORY_NAMES = [
    "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE",
    "CERTIFICATE_TABLE", "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE",
    "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE", "BOUND_IMPORT",
    "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER",
]


def _decode_name(raw: bytes) -> str:
    """解码 PE 中的名称字段（去除空字节）"""
    return raw.rstrip(b"\x00").decode("ascii", errors="replace")


def _flags_to_list(flags: int, flag_map: list) -> list:
    """将整数标志位转换为名称列表"""
    return [name for mask, name in flag_map if flags & mask]


class _PEParser:
    """
    纯 Python PE 文件解析器
    支持 32 位和 64 位 PE 文件解析
    当 pefile 库不可用时使用此解析器
    """

    def __init__(self, data: bytes):
        self.data = data

        # 基本属性
        self.is_valid = False
        self.error = None
        self.entrypoint = 0
        self.imagebase = 0
        self.virtual_size = 0
        self.section_alignment = 0
        self.file_alignment = 0

        # 头部信息
        self.coff_timestamp = 0
        self.coff_machine = 0
        self.coff_characteristics = 0
        self.coff_machine_name = ""
        self.coff_characteristics_list: list[str] = []

        # 可选头
        self.opt_magic = ""
        self.opt_subsystem = 0
        self.opt_subsystem_name = ""
        self.opt_dll_characteristics = 0
        self.opt_dll_characteristics_list: list[str] = []
        self.opt_major_image_version = 0
        self.opt_minor_image_version = 0
        self.opt_major_linker_version = 0
        self.opt_minor_linker_version = 0
        self.opt_major_os_version = 0
        self.opt_minor_os_version = 0
        self.opt_major_subsystem_version = 0
        self.opt_minor_subsystem_version = 0
        self.opt_sizeof_code = 0
        self.opt_sizeof_headers = 0
        self.opt_sizeof_heap_commit = 0

        # 节列表
        self.sections: list[dict] = []        # {name, size, vsize, entropy, data, characteristics}
        self.section_names: list[str] = []
        self.entry_section = ""

        # 导入列表
        self.imports: list[dict] = []          # {dll_name, functions: [(name, ordinal)]}
        self.imported_function_count = 0

        # 导出列表
        self.exports: list[str] = []

        # 数据目录
        self.data_directories: list[dict] = []

        # 其他标志
        self.has_debug = False
        self.has_relocations = False
        self.has_resources = False
        self.has_signature = False
        self.has_tls = False

        # 开始解析
        self._parse()

    def _parse(self):
        """解析 PE 文件结构"""
        try:
            if len(self.data) < 64:
                self.error = "文件太小"
                return
            self._parse_dos_header()
        except (struct.error, IndexError, ValueError) as e:
            self.error = f"PE 解析错误: {e}"
            return
        self.is_valid = True

    def _parse_dos_header(self):
        """解析 DOS 头和 PE 签名"""
        if self.data[:2] != b"MZ":
            self.error = "非 PE 文件（缺少 MZ 签名）"
            return

        pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
        if pe_offset < 64 or pe_offset + 4 > len(self.data):
            self.error = "PE 头偏移无效"
            return

        # PE 签名
        sig = struct.unpack_from("<I", self.data, pe_offset)[0]
        if sig != IMAGE_NT_SIGNATURE:
            self.error = "无效的 PE 签名"
            return

        coff_offset = pe_offset + 4
        self._parse_coff_header(coff_offset)

    def _parse_coff_header(self, offset: int):
        """解析 COFF 文件头 (IMAGE_FILE_HEADER)"""
        fmt = "<HHIIIH"  # Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable, NumberOfSymbols, SizeOfOptionalHeader
        header = struct.unpack_from(fmt, self.data, offset)
        machine, num_sections, timestamp, _, num_symbols, opt_header_size = header

        self.coff_machine = machine
        self.coff_machine_name = MACHINE_TYPES.get(machine, f"UNKNOWN_{machine:04X}")
        self.coff_timestamp = timestamp

        # 特征标志在 NumberOfSymbols 之后（COFF 头固定大小 20 字节）
        char_offset = offset + 18
        if char_offset + 2 <= len(self.data):
            characteristics = struct.unpack_from("<H", self.data, char_offset)[0]
            self.coff_characteristics = characteristics
            self.coff_characteristics_list = _flags_to_list(characteristics, CHARACTERISTICS_FLAGS)

        # 可选头紧随 COFF 头之后
        opt_offset = offset + 20
        if opt_header_size > 0:
            self._parse_optional_header(opt_offset, opt_header_size)

        # 节表在可选头之后
        section_offset = opt_offset + opt_header_size
        self._parse_section_table(section_offset, num_sections)

    def _parse_optional_header(self, offset: int, size: int):
        """解析可选头 (IMAGE_OPTIONAL_HEADER)"""
        magic = struct.unpack_from("<H", self.data, offset)[0]
        self.opt_magic = "PE32" if magic == 0x10B else "PE32_PLUS" if magic == 0x20B else f"UNKNOWN_{magic:04X}"
        is_64bit = (magic == 0x20B)

        # 通用字段偏移（对 32/64 位都相同的位置）
        self.opt_major_linker_version = struct.unpack_from("<B", self.data, offset + 2)[0]
        self.opt_minor_linker_version = struct.unpack_from("<B", self.data, offset + 3)[0]
        self.opt_sizeof_code = struct.unpack_from("<I", self.data, offset + 4)[0]
        self.opt_sizeof_headers = struct.unpack_from("<I", self.data, offset + 40) if is_64bit else struct.unpack_from("<I", self.data, offset + 36)

        # ImageBase: 32位在 offset+28, 64位在 offset+24
        if is_64bit:
            self.imagebase = struct.unpack_from("<Q", self.data, offset + 24)[0]
        else:
            self.imagebase = struct.unpack_from("<I", self.data, offset + 28)[0]

        # SectionAlignment 和 FileAlignment
        if is_64bit:
            self.section_alignment = struct.unpack_from("<I", self.data, offset + 32)[0]
            self.file_alignment = struct.unpack_from("<I", self.data, offset + 36)[0]
        else:
            self.section_alignment = struct.unpack_from("<I", self.data, offset + 32)[0]
            self.file_alignment = struct.unpack_from("<I", self.data, offset + 36)[0]

        # 操作系统版本和映像版本
        if is_64bit:
            self.opt_major_os_version = struct.unpack_from("<I", self.data, offset + 40)[0]
            self.opt_minor_os_version = struct.unpack_from("<I", self.data, offset + 44)[0]
            self.opt_major_image_version = struct.unpack_from("<I", self.data, offset + 48)[0]
            self.opt_minor_image_version = struct.unpack_from("<I", self.data, offset + 52)[0]
            self.opt_major_subsystem_version = struct.unpack_from("<I", self.data, offset + 56)[0]
            self.opt_minor_subsystem_version = struct.unpack_from("<I", self.data, offset + 60)[0]
        else:
            self.opt_major_os_version = struct.unpack_from("<I", self.data, offset + 40)[0]
            self.opt_minor_os_version = struct.unpack_from("<I", self.data, offset + 44)[0]
            self.opt_major_image_version = struct.unpack_from("<I", self.data, offset + 48)[0]
            self.opt_minor_image_version = struct.unpack_from("<I", self.data, offset + 52)[0]
            self.opt_major_subsystem_version = struct.unpack_from("<I", self.data, offset + 56)[0]
            self.opt_minor_subsystem_version = struct.unpack_from("<I", self.data, offset + 60)[0]

        # SizeOfHeapCommit: 32位在 offset+64, 64位在 offset+68
        if is_64bit:
            self.opt_sizeof_heap_commit = struct.unpack_from("<Q", self.data, offset + 68)[0]
        else:
            self.opt_sizeof_heap_commit = struct.unpack_from("<I", self.data, offset + 64)[0]

        # EntryPoint: 32位在 offset+16, 64位在 offset+16
        self.entrypoint = struct.unpack_from("<I", self.data, offset + 16)[0]

        # Subsystem: 32位在 offset+68, 64位在 offset+72
        if is_64bit:
            # 64位可选头：Subsystem 在 offset+72
            self.opt_subsystem = struct.unpack_from("<H", self.data, offset + 68)[0]
            # DllCharacteristics: offset+74
            self.opt_dll_characteristics = struct.unpack_from("<H", self.data, offset + 70)[0]
            # SizeOfImage (virtual_size): offset+56
            self.virtual_size = struct.unpack_from("<I", self.data, offset + 56)[0]
            # DataDirectory 数量
            num_dd = struct.unpack_from("<I", self.data, offset + 104)[0]
            dd_offset = offset + 112
        else:
            self.opt_subsystem = struct.unpack_from("<H", self.data, offset + 68)[0]
            self.opt_dll_characteristics = struct.unpack_from("<H", self.data, offset + 70)[0]
            self.virtual_size = struct.unpack_from("<I", self.data, offset + 56)[0]
            num_dd = struct.unpack_from("<I", self.data, offset + 92)[0]
            dd_offset = offset + 96

        self.opt_subsystem_name = SUBSYSTEM_TYPES.get(self.opt_subsystem, f"UNKNOWN_{self.opt_subsystem}")
        self.opt_dll_characteristics_list = _flags_to_list(self.opt_dll_characteristics, DLL_CHARACTERISTICS_FLAGS)

        # 解析数据目录
        num_dd = min(num_dd, 15)
        for i in range(num_dd):
            dd_off = dd_offset + i * 8
            if dd_off + 8 > len(self.data):
                break
            rva, size_dd = struct.unpack_from("<II", self.data, dd_off)
            self.data_directories.append({
                "name": DATA_DIRECTORY_NAMES[i] if i < len(DATA_DIRECTORY_NAMES) else f"UNKNOWN_{i}",
                "rva": rva,
                "size": size_dd,
            })
            # 设置标志
            if rva > 0 and size_dd > 0:
                if i == 5:           # BASE_RELOCATION_TABLE
                    self.has_relocations = True
                elif i == 2:         # RESOURCE_TABLE
                    self.has_resources = True
                elif i == 9:         # TLS_TABLE
                    self.has_tls = True
                elif i == 6:         # DEBUG
                    self.has_debug = True
                elif i == 4:         # CERTIFICATE_TABLE
                    self.has_signature = True

    def _rva_to_offset(self, rva: int) -> int:
        """将 RVA 转换为文件偏移"""
        for sec in self.sections:
            sec_va = sec.get("virtual_address", 0)
            sec_size = sec.get("vsize", 0)
            if sec_va <= rva < sec_va + sec_size:
                return rva - sec_va + sec.get("pointer_to_raw_data", 0)
        return 0

    def _parse_section_table(self, offset: int, num_sections: int):
        """解析节表"""
        for i in range(num_sections):
            sec_off = offset + i * 40
            if sec_off + 40 > len(self.data):
                break

            name_raw = self.data[sec_off:sec_off + 8]
            name = _decode_name(name_raw)

            if name.startswith("/"):
                # 长节名，在字符串表中
                try:
                    str_idx = int(name[1:])
                    name = self._read_string_at(str_idx) or name
                except ValueError:
                    pass

            vsize = struct.unpack_from("<I", self.data, sec_off + 8)[0]
            virtual_address = struct.unpack_from("<I", self.data, sec_off + 12)[0]
            raw_size = struct.unpack_from("<I", self.data, sec_off + 16)[0]
            raw_offset = struct.unpack_from("<I", self.data, sec_off + 20)[0]
            characteristics = struct.unpack_from("<I", self.data, sec_off + 36)[0]

            # 读取节数据
            sec_data = b""
            if raw_offset > 0 and raw_size > 0 and raw_offset + raw_size <= len(self.data):
                sec_data = self.data[raw_offset:raw_offset + raw_size]

            # 计算熵
            entropy = self._calc_entropy(sec_data)

            sec_info = {
                "name": name,
                "size": raw_size,
                "vsize": vsize,
                "virtual_address": virtual_address,
                "pointer_to_raw_data": raw_offset,
                "entropy": entropy,
                "data": sec_data,
                "characteristics": characteristics,
                "characteristics_list": _flags_to_list(characteristics, SECTION_CHARACTERISTICS_FLAGS),
            }
            self.sections.append(sec_info)
            self.section_names.append(name)

        # 确定入口节
        ep_rva = self.entrypoint
        for sec in self.sections:
            sec_va = sec.get("virtual_address", 0)
            sec_vsize = sec.get("vsize", 0)
            if sec_va <= ep_rva < sec_va + sec_vsize:
                self.entry_section = sec["name"]
                break

        if not self.entry_section:
            # 备用：取第一个可执行节
            for sec in self.sections:
                if "IMAGE_SCN_MEM_EXECUTE" in sec.get("characteristics_list", []):
                    self.entry_section = sec["name"]
                    break

        # 解析导入表
        if self.data_directories:
            import_dd = self.data_directories[1] if len(self.data_directories) > 1 else None
            if import_dd and import_dd["rva"] > 0:
                self._parse_imports(import_dd["rva"])

        # 解析导出表
        if self.data_directories:
            export_dd = self.data_directories[0]
            if export_dd and export_dd["rva"] > 0:
                self._parse_exports(export_dd["rva"])

    def _parse_imports(self, rva: int):
        """解析导入表"""
        offset = self._rva_to_offset(rva)
        if offset == 0:
            return

        i = 0
        while True:
            desc_off = offset + i * 20
            if desc_off + 20 > len(self.data):
                break

            # IMAGE_IMPORT_DESCRIPTOR: OriginalFirstThunk(4), TimeDateStamp(4), ForwarderChain(4), Name(4), FirstThunk(4)
            fields = struct.unpack_from("<IIIII", self.data, desc_off)
            if fields[0] == 0 and fields[1] == 0 and fields[2] == 0 and fields[3] == 0 and fields[4] == 0:
                break

            _, _, _, name_rva, first_thunk = fields
            if name_rva == 0:
                i += 1
                continue

            dll_name_off = self._rva_to_offset(name_rva)
            if dll_name_off == 0:
                i += 1
                continue

            dll_name = b""
            for j in range(dll_name_off, min(dll_name_off + 256, len(self.data))):
                if self.data[j] == 0:
                    dll_name = self.data[dll_name_off:j]
                    break
            dll_name_str = _decode_name(dll_name) if dll_name else ""

            # 解析导入函数
            functions = []
            thunk_rva = first_thunk if first_thunk else fields[0]
            thunk_off = self._rva_to_offset(thunk_rva)
            if thunk_off == 0:
                i += 1
                continue

            # 判断 32/64 位架构（THUNK_DATA 大小不同）
            is_64bit = (self.opt_magic == "PE32_PLUS")
            thunk_size = 8 if is_64bit else 4
            ordinal_flag = 0x8000000000000000 if is_64bit else 0x80000000
            ordinal_mask = 0x7FFFFFFF if is_64bit else 0x7FFFFFFF
            unpack_fmt = "<Q" if is_64bit else "<I"

            j = 0
            while True:
                entry_off = thunk_off + j * thunk_size
                if entry_off + thunk_size > len(self.data):
                    break

                entry_val = struct.unpack_from(unpack_fmt, self.data, entry_off)[0]
                if entry_val == 0:
                    break

                if entry_val & ordinal_flag:
                    # 序号导入
                    ordinal = entry_val & 0xFFFF
                    functions.append((f"ordinal{ordinal}", ordinal))
                    self.imported_function_count += 1
                else:
                    # 名称导入
                    func_name_off = self._rva_to_offset(entry_val & ordinal_mask)
                    if func_name_off and func_name_off + 4 <= len(self.data):
                        hint = struct.unpack_from("<H", self.data, func_name_off)[0]
                        fname_end = self.data.find(b"\x00", func_name_off + 2)
                        if fname_end == -1:
                            fname_end = min(func_name_off + 2 + 256, len(self.data))
                        func_name = _decode_name(self.data[func_name_off + 2:fname_end])
                        functions.append((func_name, None))
                        self.imported_function_count += 1
                j += 1

            if dll_name_str:
                self.imports.append({"dll_name": dll_name_str, "functions": functions})
            i += 1

    def _parse_exports(self, rva: int):
        """解析导出表"""
        offset = self._rva_to_offset(rva)
        if offset == 0:
            return

        try:
            # IMAGE_EXPORT_DIRECTORY 结构
            num_names = struct.unpack_from("<I", self.data, offset + 24)[0]
            name_ptr_rva = struct.unpack_from("<I", self.data, offset + 32)[0]

            if num_names == 0 or name_ptr_rva == 0:
                return

            name_ptr_off = self._rva_to_offset(name_ptr_rva)
            if name_ptr_off == 0:
                return

            count = min(num_names, 500)  # 限制导出数量
            for i in range(count):
                ptr_off = name_ptr_off + i * 4
                if ptr_off + 4 > len(self.data):
                    break
                func_name_rva = struct.unpack_from("<I", self.data, ptr_off)[0]
                func_name_off = self._rva_to_offset(func_name_rva)
                if func_name_off:
                    fname_end = self.data.find(b"\x00", func_name_off)
                    if fname_end == -1:
                        fname_end = min(func_name_off + 256, len(self.data))
                    func_name = _decode_name(self.data[func_name_off:fname_end])
                    if func_name:
                        self.exports.append(func_name[:10000])
        except (struct.error, IndexError):
            pass

    def _read_string_at(self, idx: int) -> str:
        """从 COFF 字符串表读取指定偏移的字符串"""
        # COFF 符号表在 COFF 头 + 可选头 + 节表之后
        # 简单实现：在整个文件中搜索以 null 结尾的字符串
        # 标准实现应该读取字符串表，但这里简化处理
        return ""

    @staticmethod
    def _calc_entropy(data: bytes) -> float:
        """计算字节序列的香农熵"""
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        length = len(data)
        entropy = 0.0
        for c in counts:
            if c > 0:
                p = c / length
                entropy -= p * math.log2(p)
        return entropy


# ============================================================
# 特征提取器基类
# ============================================================
class _FeatureType:
    """特征类型基类"""
    name: str = ""
    dim: int = 0

    def raw_features(self, bytez: bytes, pe: Optional[_PEParser]) -> object:
        raise NotImplementedError

    def process_raw_features(self, raw_obj: object) -> list:
        raise NotImplementedError

    def feature_vector(self, bytez: bytes, pe: Optional[_PEParser]) -> list:
        return self.process_raw_features(self.raw_features(bytez, pe))


# ============================================================
# 字节直方图 (256 维)
# ============================================================
class ByteHistogram(_FeatureType):
    """文件整体字节频率分布"""
    name = "histogram"
    dim = 256

    def raw_features(self, bytez, pe):
        return bytez

    def process_raw_features(self, raw_obj):
        counts = [0] * 256
        for b in raw_obj:
            counts[b] += 1
        total = len(raw_obj)
        if total > 0:
            return [c / total for c in counts]
        return [0.0] * 256


# ============================================================
# 字节熵直方图 (256 维 = 16x16)
# ============================================================
class ByteEntropyHistogram(_FeatureType):
    """滑动窗口字节熵 vs 字节值二维直方图"""
    name = "byteentropy"
    dim = 256

    def __init__(self, step: int = 1024, window: int = 2048):
        self.step = step
        self.window = window

    def raw_features(self, bytez, pe):
        return bytez

    def process_raw_features(self, raw_obj):
        bytez = raw_obj
        output = [0] * 256  # 16x16 展平

        if len(bytez) < self.window:
            # 单窗口模式
            self._add_window(bytez, 0, len(bytez), output)
        else:
            # 滑动窗口
            for start in range(0, len(bytez) - self.window + 1, self.step):
                self._add_window(bytez, start, start + self.window, output)

        total = sum(output)
        if total > 0:
            return [v / total for v in output]
        return [0.0] * 256

    def _add_window(self, bytez, start, end, output):
        """向输出累加一个窗口的熵直方图"""
        # 统计高 4 位频率
        nibble_counts = [0] * 16
        for i in range(start, end):
            nibble_counts[bytez[i] >> 4] += 1

        window_size = end - start
        # 计算熵
        entropy = 0.0
        for c in nibble_counts:
            if c > 0:
                p = c / window_size
                entropy -= p * math.log2(p)

        # 将熵映射为 0-15 的 bin
        h_bin = min(15, int(entropy * 2))

        # 累加到对应的 (熵bin, 字节高4位bin) 位置
        for nibble in range(16):
            idx = h_bin * 16 + nibble
            output[idx] += nibble_counts[nibble]


# ============================================================
# 字符串特征 (104 维)
# ============================================================
class StringExtractor(_FeatureType):
    """可打印字符串统计特征"""
    name = "strings"
    dim = 104  # 1+1+1+96+1+1+1+1+1

    def __init__(self):
        self._printable = re.compile(rb"[\x20-\x7f]{5,}")
        self._url = re.compile(rb"https?://", re.IGNORECASE)
        self._registry = re.compile(rb"HKEY_")
        self._mz = re.compile(rb"MZ")

    def raw_features(self, bytez, pe):
        return bytez

    def process_raw_features(self, raw_obj):
        bytez = raw_obj
        strings = self._printable.findall(bytez)

        if not strings:
            return [0.0] * self.dim

        # 数量和平均长度
        numstrings = len(strings)
        lengths = [len(s) for s in strings]
        avlength = sum(lengths) / numstrings

        # 可打印字符分布（96维：0x20-0x7f 映射到 0-95）
        all_chars = b"".join(strings)
        char_counts = [0] * 96
        for b in all_chars:
            idx = b - 0x20
            if 0 <= idx < 96:
                char_counts[idx] += 1
        total_printable = sum(char_counts)

        if total_printable > 0:
            printabledist = [c / total_printable for c in char_counts]
            # 熵
            entropy = 0.0
            for c in char_counts:
                if c > 0:
                    p = c / total_printable
                    entropy -= p * math.log2(p)
        else:
            printabledist = [0.0] * 96
            entropy = 0.0

        # 模式计数
        paths = len(re.findall(rb"c:\\", bytez) + re.findall(rb"C:\\", bytez))
        urls = len(self._url.findall(bytez))
        registry = len(self._registry.findall(bytez))
        mz_count = len(self._mz.findall(bytez))

        return [float(numstrings), avlength, float(total_printable)] + \
               printabledist + \
               [entropy, float(paths), float(urls), float(registry), float(mz_count)]


# ============================================================
# 通用文件信息 (10 维)
# ============================================================
class GeneralFileInfo(_FeatureType):
    """PE 文件通用统计信息"""
    name = "general"
    dim = 10

    def raw_features(self, bytez, pe):
        if pe is None or not pe.is_valid:
            return {
                "size": len(bytez), "vsize": 0, "has_debug": 0, "exports": 0,
                "imports": 0, "has_relocations": 0, "has_resources": 0,
                "has_signature": 0, "has_tls": 0, "symbols": 0,
            }
        return {
            "size": len(bytez),
            "vsize": pe.virtual_size,
            "has_debug": int(pe.has_debug),
            "exports": len(pe.exports),
            "imports": pe.imported_function_count,
            "has_relocations": int(pe.has_relocations),
            "has_resources": int(pe.has_resources),
            "has_signature": int(pe.has_signature),
            "has_tls": int(pe.has_tls),
            "symbols": 0,  # 纯 Python 解析器暂不统计 COFF 符号数
        }

    def process_raw_features(self, raw_obj):
        return [
            float(raw_obj["size"]), float(raw_obj["vsize"]),
            float(raw_obj["has_debug"]), float(raw_obj["exports"]),
            float(raw_obj["imports"]), float(raw_obj["has_relocations"]),
            float(raw_obj["has_resources"]), float(raw_obj["has_signature"]),
            float(raw_obj["has_tls"]), float(raw_obj["symbols"]),
        ]


# ============================================================
# 头部信息 (62 维)
# ============================================================
class HeaderFileInfo(_FeatureType):
    """COFF 头和可选头特征"""
    name = "header"
    dim = 62

    def raw_features(self, bytez, pe):
        if pe is None or not pe.is_valid:
            return {
                "coff": {"timestamp": 0, "machine": "", "characteristics": []},
                "optional": {
                    "subsystem": "", "dll_characteristics": [], "magic": "",
                    "major_image_version": 0, "minor_image_version": 0,
                    "major_linker_version": 0, "minor_linker_version": 0,
                    "major_operating_system_version": 0, "minor_operating_system_version": 0,
                    "major_subsystem_version": 0, "minor_subsystem_version": 0,
                    "sizeof_code": 0, "sizeof_headers": 0, "sizeof_heap_commit": 0,
                },
            }
        return {
            "coff": {
                "timestamp": pe.coff_timestamp,
                "machine": pe.coff_machine_name,
                "characteristics": pe.coff_characteristics_list,
            },
            "optional": {
                "subsystem": pe.opt_subsystem_name,
                "dll_characteristics": pe.opt_dll_characteristics_list,
                "magic": pe.opt_magic,
                "major_image_version": pe.opt_major_image_version,
                "minor_image_version": pe.opt_minor_image_version,
                "major_linker_version": pe.opt_major_linker_version,
                "minor_linker_version": pe.opt_minor_linker_version,
                "major_operating_system_version": pe.opt_major_os_version,
                "minor_operating_system_version": pe.opt_minor_os_version,
                "major_subsystem_version": pe.opt_major_subsystem_version,
                "minor_subsystem_version": pe.opt_minor_subsystem_version,
                "sizeof_code": pe.opt_sizeof_code,
                "sizeof_headers": pe.opt_sizeof_headers,
                "sizeof_heap_commit": pe.opt_sizeof_heap_commit,
            },
        }

    def process_raw_features(self, raw_obj):
        coff = raw_obj["coff"]
        opt = raw_obj["optional"]

        machine_h = FeatureHasher(10, "string").transform([[coff["machine"]]])[0]
        char_h = FeatureHasher(10, "string").transform([coff["characteristics"]])[0]
        subsystem_h = FeatureHasher(10, "string").transform([[opt["subsystem"]]])[0]
        dll_h = FeatureHasher(10, "string").transform([opt["dll_characteristics"]])[0]
        magic_h = FeatureHasher(10, "string").transform([[opt["magic"]]])[0]

        result = [
            float(coff["timestamp"]),
        ] + machine_h + char_h + subsystem_h + dll_h + magic_h + [
            float(opt["major_image_version"]), float(opt["minor_image_version"]),
            float(opt["major_linker_version"]), float(opt["minor_linker_version"]),
            float(opt["major_operating_system_version"]), float(opt["minor_operating_system_version"]),
            float(opt["major_subsystem_version"]), float(opt["minor_subsystem_version"]),
            float(opt["sizeof_code"]), float(opt["sizeof_headers"]), float(opt["sizeof_heap_commit"]),
        ]
        # 确保返回 dim 维
        while len(result) < self.dim:
            result.append(0.0)
        return result[:self.dim]


# ============================================================
# 节信息 (255 维)
# ============================================================
class SectionInfo(_FeatureType):
    """PE 节表特征"""
    name = "section"
    dim = 255  # 5 + 50*5

    def raw_features(self, bytez, pe):
        if pe is None or not pe.is_valid or not pe.sections:
            return {"entry": "", "sections": []}

        return {
            "entry": pe.entry_section,
            "sections": [
                {
                    "name": s["name"],
                    "size": s["size"],
                    "entropy": s["entropy"],
                    "vsize": s["vsize"],
                    "props": s.get("characteristics_list", []),
                }
                for s in pe.sections
            ],
        }

    def process_raw_features(self, raw_obj):
        sections = raw_obj["sections"]
        entry = raw_obj.get("entry", "")

        # 通用节统计 (5 维)
        general = [
            float(len(sections)),                                                     # 节数量
            float(sum(1 for s in sections if s["size"] == 0)),                        # 零大小节数量
            float(sum(1 for s in sections if s["name"] == "")),                       # 空名称节数量
            float(sum(1 for s in sections if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"])),  # RX 节
            float(sum(1 for s in sections if "MEM_WRITE" in s["props"])),             # 可写节
        ]

        # 节名→属性 哈希（各 50 维）
        section_sizes = [(s["name"], s["size"]) for s in sections]
        section_entropy = [(s["name"], s["entropy"]) for s in sections]
        section_vsize = [(s["name"], s["vsize"]) for s in sections]
        entry_name = entry
        entry_chars = [p for s in sections for p in s["props"] if s["name"] == entry]

        sz_h = FeatureHasher(50, "pair").transform([section_sizes])[0]
        ent_h = FeatureHasher(50, "pair").transform([section_entropy])[0]
        vsz_h = FeatureHasher(50, "pair").transform([section_vsize])[0]
        entry_h = FeatureHasher(50, "string").transform([[entry_name]])[0]
        chars_h = FeatureHasher(50, "string").transform([entry_chars])[0]

        return general + sz_h + ent_h + vsz_h + entry_h + chars_h


# ============================================================
# 导入信息 (1280 维)
# ============================================================
class ImportsInfo(_FeatureType):
    """导入表 DLL 和函数哈希特征"""
    name = "imports"
    dim = 1280  # 256 + 1024

    def raw_features(self, bytez, pe):
        if pe is None or not pe.is_valid:
            return {}

        imports = {}
        for imp in pe.imports:
            dll_name = imp["dll_name"]
            if dll_name not in imports:
                imports[dll_name] = []
            for func_name, ordinal in imp.get("functions", []):
                imports[dll_name].append(func_name[:10000] if func_name else f"ordinal{ordinal}")
        return imports

    def process_raw_features(self, raw_obj):
        if not raw_obj:
            return [0.0] * self.dim

        # 库名哈希 (256 维)
        libraries = list({lib.lower() for lib in raw_obj.keys()})
        lib_h = FeatureHasher(256, "string").transform([libraries])[0]

        # 函数名 "library:function" 哈希 (1024 维)
        func_pairs = []
        for lib, funcs in raw_obj.items():
            for f in funcs:
                func_pairs.append(f"{lib.lower()}:{f}")

        func_h = FeatureHasher(1024, "string").transform([func_pairs])[0]

        return lib_h + func_h


# ============================================================
# 导出信息 (128 维)
# ============================================================
class ExportsInfo(_FeatureType):
    """导出表函数名哈希特征"""
    name = "exports"
    dim = 128

    def raw_features(self, bytez, pe):
        if pe is None or not pe.is_valid:
            return []
        return pe.exports

    def process_raw_features(self, raw_obj):
        return FeatureHasher(128, "string").transform([raw_obj])[0]


# ============================================================
# 数据目录 (30 维)
# ============================================================
class DataDirectories(_FeatureType):
    """数据目录表的大小和虚拟地址特征"""
    name = "datadirectories"
    dim = 30  # 15 * 2

    def raw_features(self, bytez, pe):
        if pe is None or not pe.is_valid:
            return []

        return [
            {
                "name": dd["name"],
                "size": dd["size"],
                "virtual_address": dd["rva"],
            }
            for dd in pe.data_directories
        ]

    def process_raw_features(self, raw_obj):
        features = [0.0] * self.dim
        for i in range(min(len(raw_obj), self.dim // 2)):
            features[2 * i] = float(raw_obj[i]["size"])
            features[2 * i + 1] = float(raw_obj[i]["virtual_address"])
        return features


# ============================================================
# PE 特征提取器 —— EMBER v2 2381 维向量
# ============================================================
class PEFeatureExtractor:
    """
    EMBER v2 兼容的 PE 特征提取器
    提取 2381 维特征向量

    特征组分布:
      ByteHistogram          256
      ByteEntropyHistogram   256
      StringExtractor        104
      GeneralFileInfo         10
      HeaderFileInfo          62
      SectionInfo            255
      ImportsInfo           1280
      ExportsInfo            128
      DataDirectories         30
      ─────────────────────────
      TOTAL                 2381
    """

    def __init__(self, feature_version: int = 2):
        self.features: list[_FeatureType] = [
            ByteHistogram(),
            ByteEntropyHistogram(),
            StringExtractor(),
            GeneralFileInfo(),
            HeaderFileInfo(),
            SectionInfo(),
            ImportsInfo(),
            ExportsInfo(),
        ]
        if feature_version == 2:
            self.features.append(DataDirectories())
        self.dim = sum(f.dim for f in self.features)  # 2381

    def _parse_pe(self, bytez: bytes) -> Optional[_PEParser]:
        """
        解析 PE 数据，优先使用 pefile，回退到纯 Python 解析

        返回:
            _PEParser 实例或 None
        """
        # 快速检查 MZ 头
        if len(bytez) < 2 or bytez[:2] != b"MZ":
            return None

        # 优先使用 pefile
        if _HAS_PEFILE:
            try:
                pe = pefile.PE(data=bytez, fast_load=True)
                return self._from_pefile(pe, bytez)
            except Exception:
                pass

        # 回退到纯 Python 解析
        parser = _PEParser(bytez)
        if parser.is_valid:
            return parser
        return None

    def _from_pefile(self, pe, bytez: bytes) -> Optional["_PEParserWrapper"]:
        """将 pefile 对象包装为统一接口"""
        return _PEParserWrapper(pe, bytez)

    def raw_features(self, bytez: bytes) -> dict:
        """提取原始特征字典"""
        pe = self._parse_pe(bytez)
        result = {"sha256": hashlib.sha256(bytez).hexdigest()}
        for feat in self.features:
            result[feat.name] = feat.raw_features(bytez, pe)
        return result

    def process_raw_features(self, raw_obj: dict) -> list:
        """将原始特征处理为 2381 维向量"""
        vectors = []
        for feat in self.features:
            vec = feat.process_raw_features(raw_obj[feat.name])
            # 确保维度正确
            while len(vec) < feat.dim:
                vec.append(0.0)
            vectors.append(vec[:feat.dim])
        result = []
        for v in vectors:
            result.extend(v)
        return result

    def feature_vector(self, bytez: bytes) -> list:
        """一步提取 2381 维特征向量"""
        return self.process_raw_features(self.raw_features(bytez))


# ============================================================
# pefile 包装器 —— 提供与 _PEParser 统一的接口
# ============================================================
class _PEParserWrapper:
    """
    将 pefile.PE 对象包装为与纯 Python _PEParser 相同的接口
    这样所有 FeatureType 可以统一处理
    """

    def __init__(self, pe, bytez: bytes):
        self.pe = pe
        self.bytez = bytez
        self.is_valid = True
        self.error = None

        # 头部信息
        self.coff_machine = pe.FILE_HEADER.Machine if hasattr(pe, "FILE_HEADER") else 0
        self.coff_machine_name = MACHINE_TYPES.get(self.coff_machine, f"UNKNOWN_{self.coff_machine:04X}")
        self.coff_timestamp = pe.FILE_HEADER.TimeDateStamp if hasattr(pe, "FILE_HEADER") else 0

        chars = pe.FILE_HEADER.Characteristics if hasattr(pe, "FILE_HEADER") else 0
        self.coff_characteristics = chars
        self.coff_characteristics_list = _flags_to_list(chars, CHARACTERISTICS_FLAGS)

        # 可选头
        if hasattr(pe, "OPTIONAL_HEADER"):
            oh = pe.OPTIONAL_HEADER
            magic = oh.Magic if hasattr(oh, "Magic") else 0
            self.opt_magic = "PE32" if magic == 0x10B else "PE32_PLUS" if magic == 0x20B else f"UNKNOWN_{magic:04X}"
            self.entrypoint = oh.AddressOfEntryPoint if hasattr(oh, "AddressOfEntryPoint") else 0
            self.imagebase = oh.ImageBase if hasattr(oh, "ImageBase") else 0
            self.virtual_size = oh.SizeOfImage if hasattr(oh, "SizeOfImage") else 0
            self.section_alignment = oh.SectionAlignment if hasattr(oh, "SectionAlignment") else 0
            self.file_alignment = oh.FileAlignment if hasattr(oh, "FileAlignment") else 0

            self.opt_subsystem = oh.Subsystem if hasattr(oh, "Subsystem") else 0
            self.opt_subsystem_name = SUBSYSTEM_TYPES.get(self.opt_subsystem, f"UNKNOWN_{self.opt_subsystem}")

            dll_chars = oh.DllCharacteristics if hasattr(oh, "DllCharacteristics") else 0
            self.opt_dll_characteristics = dll_chars
            self.opt_dll_characteristics_list = _flags_to_list(dll_chars, DLL_CHARACTERISTICS_FLAGS)

            self.opt_major_image_version = oh.MajorImageVersion if hasattr(oh, "MajorImageVersion") else 0
            self.opt_minor_image_version = oh.MinorImageVersion if hasattr(oh, "MinorImageVersion") else 0
            self.opt_major_linker_version = oh.MajorLinkerVersion if hasattr(oh, "MajorLinkerVersion") else 0
            self.opt_minor_linker_version = oh.MinorLinkerVersion if hasattr(oh, "MinorLinkerVersion") else 0
            self.opt_major_os_version = oh.MajorOperatingSystemVersion if hasattr(oh, "MajorOperatingSystemVersion") else 0
            self.opt_minor_os_version = oh.MinorOperatingSystemVersion if hasattr(oh, "MinorOperatingSystemVersion") else 0
            self.opt_major_subsystem_version = oh.MajorSubsystemVersion if hasattr(oh, "MajorSubsystemVersion") else 0
            self.opt_minor_subsystem_version = oh.MinorSubsystemVersion if hasattr(oh, "MinorSubsystemVersion") else 0
            self.opt_sizeof_code = oh.SizeOfCode if hasattr(oh, "SizeOfCode") else 0
            self.opt_sizeof_headers = oh.SizeOfHeaders if hasattr(oh, "SizeOfHeaders") else 0
            self.opt_sizeof_heap_commit = oh.SizeOfHeapCommit if hasattr(oh, "SizeOfHeapCommit") else 0
        else:
            self._set_default_optional()

        # 节信息
        self.sections = []
        self.section_names = []
        self.entry_section = ""
        self.has_high_entropy_section = False
        self.has_writable_executable_section = False

        if hasattr(pe, "sections"):
            for sec in pe.sections:
                name = _decode_name(sec.Name.rstrip(b"\x00") if isinstance(sec.Name, bytes) else str(sec.Name).rstrip("\x00"))
                size = sec.SizeOfRawData if hasattr(sec, "SizeOfRawData") else 0
                vsize = sec.Misc_VirtualSize if hasattr(sec, "Misc_VirtualSize") else sec.Misc if hasattr(sec, "Misc") else 0
                chars_val = sec.Characteristics if hasattr(sec, "Characteristics") else 0

                sec_data = b""
                try:
                    sec_data = sec.get_data()
                except Exception:
                    pass

                entropy = _PEParser._calc_entropy(sec_data) if sec_data else 0.0
                if entropy >= 7.2:
                    self.has_high_entropy_section = True
                if (chars_val & 0x80000000) and (chars_val & 0x20000000):
                    self.has_writable_executable_section = True

                va = sec.VirtualAddress if hasattr(sec, "VirtualAddress") else 0
                ptr_raw = sec.PointerToRawData if hasattr(sec, "PointerToRawData") else 0

                self.sections.append({
                    "name": name,
                    "size": size,
                    "vsize": vsize,
                    "virtual_address": va,
                    "pointer_to_raw_data": ptr_raw,
                    "entropy": entropy,
                    "data": sec_data,
                    "characteristics": chars_val,
                    "characteristics_list": _flags_to_list(chars_val, SECTION_CHARACTERISTICS_FLAGS),
                })
                self.section_names.append(name)

        # 入口节
        ep_rva = self.entrypoint
        for sec in self.sections:
            va = sec.get("virtual_address", 0)
            vsz = sec.get("vsize", 0)
            if va <= ep_rva < va + vsz:
                self.entry_section = sec["name"]
                break
        if not self.entry_section:
            for sec in self.sections:
                if "IMAGE_SCN_MEM_EXECUTE" in sec.get("characteristics_list", []):
                    self.entry_section = sec["name"]
                    break

        # 导入信息
        self.imports = []
        self.imported_function_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = _decode_name(entry.dll) if isinstance(entry.dll, bytes) else (entry.dll or "")
                funcs = []
                for imp in entry.imports:
                    fname = ""
                    if imp.name:
                        fname = _decode_name(imp.name) if isinstance(imp.name, bytes) else imp.name
                    elif imp.ordinal is not None:
                        fname = f"ordinal{imp.ordinal}"
                    funcs.append((fname, imp.ordinal))
                    self.imported_function_count += 1
                if dll:
                    self.imports.append({"dll_name": dll, "functions": funcs})

        # 导出信息
        self.exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            try:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    name = exp.name if hasattr(exp, "name") else ""
                    if isinstance(name, bytes):
                        name = _decode_name(name)
                    if name:
                        self.exports.append(name)
            except Exception:
                pass

        # 数据目录
        self.data_directories = []
        self.has_debug = False
        self.has_relocations = False
        self.has_resources = False
        self.has_signature = False
        self.has_tls = False

        if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            dd_list = pe.OPTIONAL_HEADER.DATA_DIRECTORY
            for i, dd in enumerate(dd_list):
                name = DATA_DIRECTORY_NAMES[i] if i < len(DATA_DIRECTORY_NAMES) else f"UNKNOWN_{i}"
                rva = dd.VirtualAddress if hasattr(dd, "VirtualAddress") else 0
                size_dd = dd.Size if hasattr(dd, "Size") else 0
                self.data_directories.append({"name": name, "rva": rva, "size": size_dd})
                if rva > 0 and size_dd > 0:
                    if i == 5:
                        self.has_relocations = True
                    elif i == 2:
                        self.has_resources = True
                    elif i == 9:
                        self.has_tls = True
                    elif i == 6:
                        self.has_debug = True
                    elif i == 4:
                        self.has_signature = True

    def _set_default_optional(self):
        """设置默认可选头值"""
        self.opt_magic = "UNKNOWN"
        self.entrypoint = 0
        self.imagebase = 0
        self.virtual_size = 0
        self.section_alignment = 0
        self.file_alignment = 0
        self.opt_subsystem = 0
        self.opt_subsystem_name = ""
        self.opt_dll_characteristics = 0
        self.opt_dll_characteristics_list = []
        self.opt_major_image_version = 0
        self.opt_minor_image_version = 0
        self.opt_major_linker_version = 0
        self.opt_minor_linker_version = 0
        self.opt_major_os_version = 0
        self.opt_minor_os_version = 0
        self.opt_major_subsystem_version = 0
        self.opt_minor_subsystem_version = 0
        self.opt_sizeof_code = 0
        self.opt_sizeof_headers = 0
        self.opt_sizeof_heap_commit = 0


# ============================================================
# 规则评分引擎 —— 基于 PE 特征的启发式评分
# ============================================================
class RuleBasedScorer:
    """
    基于规则的 PE 恶意软件评分器
    作为机器学习特征的回退方案，提供可解释的判定原因

    评分规则:
      1. 导入表含大量可疑 API（进程注入、反调试、加密等）
      2. 节属性异常（RWX 节、高熵节、零大小节）
      3. PE 头部异常（无效时间戳、异常节数）
      4. 缺少常见导入（无导入 DLL 可能意味着动态解析）
      5. 数字签名缺失
      6. 入口点不在代码节
      7. 包含 URL / 注册表 / 路径字符串
    """

    # 评分权重
    WEIGHT_SUSPICIOUS_API = 20       # 每个可疑 API 加分（原 15）
    WEIGHT_RWX_SECTION = 30          # 可写可执行节
    WEIGHT_HIGH_ENTROPY = 20         # 高熵节（可能加壳/加密）
    WEIGHT_ZERO_SIZE_SECTION = 10    # 零大小节
    WEIGHT_EMPTY_NAME_SECTION = 5    # 空名称节
    WEIGHT_NO_IMPORTS = 20           # 无导入 DLL
    WEIGHT_LOW_IMPORTS = 10          # 导入 DLL 很少但有很多可疑 API
    WEIGHT_NO_SIGNATURE = 15         # 缺少数字签名
    WEIGHT_ENTRY_MISMATCH = 25       # 入口点不在可执行节
    WEIGHT_STRINGS_URL = 10          # 包含 URL 字符串
    WEIGHT_STRINGS_REG = 10          # 包含注册表路径
    WEIGHT_STRINGS_PATH = 5          # 包含文件路径
    WEIGHT_DLL_FILE = 5              # DLL 文件缺少导出
    WEIGHT_ANOMALOUS_HEADER = 15     # 异常的 PE 头

    # 置信度阈值
    SCORE_MALICIOUS = 60    # >= 此分数判定为 MALICIOUS（原 80）
    SCORE_SUSPICIOUS = 30   # >= 此分数判定为 SUSPICIOUS（原 40）

    def score(self, bytez: bytes, pe) -> tuple[float, list[str]]:
        """
        对 PE 文件进行规则评分

        返回:
            (score, reasons) - 评分和原因列表
        """
        score = 0.0
        reasons = []

        # 预先提取字符串
        strings = self._extract_strings(bytez)
        all_funcs = self._collect_imports(pe)

        # 1. 检查可疑 API 导入
        suspicious_found = self._check_suspicious_apis(all_funcs)
        if suspicious_found:
            api_score = min(len(suspicious_found) * self.WEIGHT_SUSPICIOUS_API, 70)
            score += api_score
            api_names = ", ".join(suspicious_found[:10])
            if len(suspicious_found) > 10:
                api_names += f"... 等共 {len(suspicious_found)} 个"
            reasons.append(f"发现 {len(suspicious_found)} 个可疑 API: {api_names}")

        # 2. 节属性检查
        if pe is not None and pe.is_valid:
            count_rwx = 0
            count_high_ent = 0
            count_zero = 0
            count_empty = 0
            entry_in_exec = False

            for sec in pe.sections:
                props = sec.get("characteristics_list", [])
                if "IMAGE_SCN_MEM_WRITE" in props and "IMAGE_SCN_MEM_EXECUTE" in props:
                    count_rwx += 1
                if sec.get("entropy", 0) >= 7.0:
                    count_high_ent += 1
                if sec.get("size", 0) == 0:
                    count_zero += 1
                if not sec.get("name", ""):
                    count_empty += 1
                if "IMAGE_SCN_MEM_EXECUTE" in props and pe.entry_section == sec.get("name"):
                    entry_in_exec = True

            if count_rwx > 0:
                score += self.WEIGHT_RWX_SECTION * count_rwx
                reasons.append(f"发现 {count_rwx} 个可写可执行(RWX)节，存在代码注入风险")

            if count_high_ent > 0:
                score += self.WEIGHT_HIGH_ENTROPY * count_high_ent
                reasons.append(f"发现 {count_high_ent} 个高熵节(>=7.0)，可能被加壳或加密")

            if count_zero > 0:
                score += self.WEIGHT_ZERO_SIZE_SECTION * count_zero
                reasons.append(f"发现 {count_zero} 个零大小节")

            if count_empty > 0:
                score += self.WEIGHT_EMPTY_NAME_SECTION * count_empty

            # 入口点不在代码节
            if not entry_in_exec and pe.entry_section:
                score += self.WEIGHT_ENTRY_MISMATCH
                reasons.append(f"入口点不在可执行节(位于: {pe.entry_section})")

            # 检查导入 DLL 数量
            if len(pe.imports) == 0:
                score += self.WEIGHT_NO_IMPORTS
                reasons.append("PE 文件无导入表，可能使用动态 API 解析")

            # DLL 文件检查
            is_dll = "IMAGE_FILE_DLL" in pe.coff_characteristics_list
            if is_dll and len(pe.exports) == 0 and len(pe.imports) > 0:
                # DLL 导出很少但有很多可疑导入
                if suspicious_found and len(suspicious_found) >= 3:
                    score += self.WEIGHT_DLL_FILE
                    reasons.append("DLL 文件缺少合法导出但包含可疑导入")

            # 数字签名缺失
            if not pe.has_signature:
                # 只在其他方面可疑时才加分
                if score > 20:
                    score += self.WEIGHT_NO_SIGNATURE
                    reasons.append("缺少数字签名")

            # PE 头异常检查
            header_anomalies = self._check_header_anomalies(pe)
            if header_anomalies:
                score += self.WEIGHT_ANOMALOUS_HEADER
                reasons.append(f"PE 头异常: {header_anomalies}")

        # 3. 字符串检查（在非 PE 或 PE 解析失败时也能用）
        string_findings = self._check_strings(bytez, strings)
        score += string_findings[0]
        reasons.extend(string_findings[1])

        return score, reasons

    def _collect_imports(self, pe) -> list[str]:
        """收集所有导入函数名"""
        funcs = []
        if pe is not None and pe.is_valid:
            for imp in pe.imports:
                for func_name, _ in imp.get("functions", []):
                    if func_name:
                        funcs.append(func_name)
        return funcs

    def _check_suspicious_apis(self, all_funcs: list[str]) -> list[str]:
        """检查导入表中匹配的可疑 API"""
        found = []
        for f in all_funcs:
            # 去除函数名前后的修饰（可能的 @ 后缀等）
            clean = f.split("@")[0].strip()
            if clean.lower() in _SUSPICIOUS_SET:
                found.append(clean)
        return found

    def _check_header_anomalies(self, pe) -> str:
        """检查 PE 头中的异常"""
        anomalies = []
        # 时间戳为 0 可能表示被篡改
        if pe.coff_timestamp == 0:
            anomalies.append("时间戳为零")
        # 节数量异常多或异常少
        num_sections = len(pe.sections)
        if num_sections > 20:
            anomalies.append(f"节数量异常多({num_sections})")
        elif num_sections == 0:
            anomalies.append("无节表")
        # 入口点为零
        if pe.entrypoint == 0:
            anomalies.append("入口点为零")
        return "; ".join(anomalies) if anomalies else ""

    def _extract_strings(self, bytez: bytes) -> list[bytes]:
        """提取可打印字符串"""
        pattern = re.compile(rb"[\x20-\x7f]{5,}")
        return pattern.findall(bytez)

    def _check_strings(self, bytez: bytes, strings: list[bytes]) -> tuple[float, list[str]]:
        """检查字符串中的可疑模式"""
        score = 0.0
        reasons = []

        # URL 检测
        url_pattern = re.compile(rb"https?://[^\x00-\x1f\x7f-\xff]{4,}")
        urls = url_pattern.findall(bytez)
        if urls:
            score += self.WEIGHT_STRINGS_URL
            reasons.append(f"发现 {len(urls)} 个 URL，可能存在网络通信行为")

        # 注册表路径
        reg_pattern = re.compile(rb"HKEY_[A-Z_]+\\[^\x00]+")
        regs = reg_pattern.findall(bytez)
        if regs:
            score += self.WEIGHT_STRINGS_REG
            reasons.append(f"发现 {len(regs)} 个注册表路径，可能存在持久化行为")

        # 文件路径
        path_count = sum(1 for s in strings if b"\\" in s and len(s) > 10)
        if path_count > 5:
            score += self.WEIGHT_STRINGS_PATH
            reasons.append(f"发现 {path_count} 个文件路径引用")

        # 可疑命令行
        cmd_keywords = [b"cmd.exe", b"powershell", b"rundll32", b"regsvr32",
                        b"schtasks", b"wmic", b"certutil", b"bitsadmin",
                        b"mshta", b"cscript", b"wscript"]
        cmd_found = [kw for kw in cmd_keywords if kw.lower() in bytez.lower()]
        if cmd_found:
            score += 10
            reasons.append(f"发现可疑命令行工具引用: {', '.join(k.decode('ascii') for k in cmd_found)}")

        return score, reasons


# ============================================================
# scan_pe —— PE 文件扫描入口
# ============================================================
_EMBER_PREDICTOR_CACHE = None
_EMBER_PREDICTOR_LOADED = False


def _get_ember_predictor():
    """惰性加载 EMBER 模型；缺失或无模型文件返回 None（安全跳过）。"""
    from engine.ember_model import find_ember_model, load_ember_model
    global _EMBER_PREDICTOR_CACHE, _EMBER_PREDICTOR_LOADED
    if _EMBER_PREDICTOR_LOADED:
        return _EMBER_PREDICTOR_CACHE
    _EMBER_PREDICTOR_LOADED = True
    path = find_ember_model()
    _EMBER_PREDICTOR_CACHE = load_ember_model(path) if path else None
    return _EMBER_PREDICTOR_CACHE


def scan_pe(data: bytes, sha256: str = "") -> dict:
    """
    扫描 PE 文件，返回判定结果

    参数:
        data: PE 文件的原始字节数据
        sha256: 可选，调用方已算好的 sha256（避免对大缓冲重复哈希）；为空时内部计算

    返回:
        {
            "verdict": "MALICIOUS" | "SUSPICIOUS" | "CLEAN",
            "confidence": 0.0 ~ 1.0,
            "reasons": ["原因1", "原因2", ...],
            "features": {
                "sha256": "...",
                "file_size": 12345,
                "is_pe": true,
                "suspicious_apis": ["api1", ...],
                "suspicious_count": 3,
                "pe_info": {...},
                "feature_vector": [...]  # 2381 维可选
            }
        }
    """
    result: dict = {
        "verdict": "CLEAN",
        "confidence": 0.0,
        "reasons": [],
        "features": {
            "sha256": sha256 or (hashlib.sha256(data).hexdigest() if data else ""),
            "file_size": len(data),
            "is_pe": False,
            "suspicious_apis": [],
            "suspicious_count": 0,
            "pe_info": {},
        },
    }

    # 基本大小检查
    if len(data) < 64:
        result["reasons"].append("文件太小，非 PE 文件")
        return result

    # 检查 DOS 魔数
    if data[:2] != b"MZ":
        result["reasons"].append("非 PE 文件（缺少 MZ 签名）")
        return result

    result["features"]["is_pe"] = True

    # 解析 PE 结构
    try:
        extractor = PEFeatureExtractor()
        pe = extractor._parse_pe(data)
    except Exception as e:
        result["verdict"] = "SUSPICIOUS"
        result["confidence"] = 0.3
        result["reasons"].append(f"PE 解析异常: {e}")
        return result

    # PE 解析失败（非标准 PE），标记为可疑
    if pe is None:
        result["verdict"] = "SUSPICIOUS"
        result["confidence"] = 0.25
        result["reasons"].append("PE 文件格式异常，无法完整解析")
        return result

    # ---- 规则评分 ----
    scorer = RuleBasedScorer()
    raw_score, reasons = scorer.score(data, pe)

    # 记录评分阶段原因
    result["reasons"].extend(reasons)

    # 收集 PE 基本信息
    pe_info = {
        "machine": pe.coff_machine_name,
        "timestamp": pe.coff_timestamp,
        "entry_point": pe.entrypoint,
        "image_base": pe.imagebase,
        "section_count": len(pe.sections),
        "import_dll_count": len(pe.imports),
        "import_func_count": pe.imported_function_count,
        "export_count": len(pe.exports),
        "has_signature": pe.has_signature,
        "has_resources": pe.has_resources,
        "has_tls": pe.has_tls,
        "has_debug": pe.has_debug,
        "has_relocations": pe.has_relocations,
    }

    # 提取可疑 API 列表
    all_funcs = scorer._collect_imports(pe)
    suspicious_found = scorer._check_suspicious_apis(all_funcs)

    result["features"]["suspicious_apis"] = suspicious_found
    result["features"]["suspicious_count"] = len(suspicious_found)
    result["features"]["pe_info"] = pe_info

    # ---- 提取 EMBER 特征向量（可选，用于外部 ML 模型）----
    ml_status = "no_model"
    ml_prob = None
    try:
        fv = extractor.feature_vector(data)
        # 特征向量摘要（首尾各 5 维）
        result["features"]["feature_vector_summary"] = {
            "dim": len(fv),
            "head": fv[:5],
            "tail": fv[-5:],
            "non_zero_count": sum(1 for v in fv if v != 0.0),
        }

        # 真实 LightGBM/EMBER 推理（模型缺失时安全跳过）
        try:
            import numpy as _np  # noqa: F401  # 仅 numpy，打包安全
            pred = _get_ember_predictor()
            if pred is not None and fv:
                ml_prob = float(pred.predict_proba(list(fv)))
                ml_status = "ok"
            else:
                ml_status = "no_model"
        except Exception:
            ml_status = "error"
        result["features"]["ml_ember"] = {
            "status": ml_status,
            "probability": round(ml_prob, 4) if ml_prob is not None else None,
        }
    except Exception:
        result["features"]["feature_vector_summary"] = {"error": "特征提取失败"}
        result["features"]["ml_ember"] = {"status": "error", "probability": None}

    # ---- 综合判定 ----
    # 将原始评分归一化到 0.0-1.0 置信度
    # 评分范围：理论上可以很高（很多可疑 API 会累积），但实际上很少超过 200
    normalized = min(raw_score / 150.0, 1.0)

    if raw_score >= RuleBasedScorer.SCORE_MALICIOUS:
        result["verdict"] = "MALICIOUS"
        result["confidence"] = max(0.7, min(normalized, 0.99))
    elif raw_score >= RuleBasedScorer.SCORE_SUSPICIOUS:
        result["verdict"] = "SUSPICIOUS"
        result["confidence"] = max(0.35, min(normalized * 0.85, 0.69))
    else:
        result["verdict"] = "CLEAN"
        # 即使判定为 CLEAN，也根据少量可疑点给出低置信度
        if raw_score > 0:
            result["confidence"] = min(raw_score / 150.0, 0.3)
        else:
            result["confidence"] = 0.05

    # ---- 融入 EMBER ML 概率（模型可用时）----
    if ml_prob is not None:
        if ml_prob >= 0.9:
            if result["verdict"] != "MALICIOUS":
                result["verdict"] = "MALICIOUS"
            result["confidence"] = max(result["confidence"], 0.92)
            result["reasons"].append(f"EMBER 机器学习判定恶意（概率 {ml_prob:.2f}）")
        elif ml_prob >= 0.6:
            if result["verdict"] == "CLEAN":
                result["verdict"] = "SUSPICIOUS"
            result["confidence"] = max(result["confidence"], 0.55)
            result["reasons"].append(f"EMBER 机器学习提示可疑（概率 {ml_prob:.2f}）")
        elif ml_prob <= 0.15:
            # 明确安全的样本：压低置信度，作为强清洁信号
            if result["verdict"] == "CLEAN":
                result["confidence"] = min(result["confidence"], 0.1)
            result["reasons"].append(f"EMBER 机器学习判定清洁（概率 {ml_prob:.2f}）")
        else:
            result["reasons"].append(f"EMBER 机器学习概率 {ml_prob:.2f}（低置信）")

    return result
