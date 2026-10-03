"""
进程内存镜像扫描 —— 抓加壳 / 注入样本

思路
----
加壳样本的**磁盘字节是加密的**：哈希特征库打不中、YARA 字面量也打不中。
但它一旦跑起来，壳必须把原始代码解密到内存 —— **内存里就是裸代码**。
所以对"磁盘扫不出、内存扫得出"的进程，高度怀疑加壳或注入。

为什么不需要 pe-sieve / dbghelp / PE 重建
-----------------------------------------
**YARA 扫的是字节，不是可执行结构。** 只要把进程里已加载模块的内存读出来
拼成一个 buffer，就能直接喂给现有的 YaraScanner。不需要重建 PE 头、不需要
修复导入表、不需要重定位 —— 那些是"要让 dump 出来的东西能再运行"才需要的。

这个取舍带来三个直接好处：
  * 不依赖任何第三方未签名 exe（pe-sieve 未签名，会被别的杀软拦掉 ——
    对一个杀毒软件来说这是致命的）；
  * 不需要 dbghelp / MiniDumpWriteDump 那套；
  * 复用已有的原生 Aho-Corasick 匹配器（337 MB/s），扫几 MB 内存不到 20 毫秒。

权限方向
--------
高完整性进程可以读低完整性进程的内存。沙箱把样本降为 Low IL 之后，
本模块（跑在正常完整性下）仍然读得到它的内存 —— 方向是对的。

用法
----
    from engine.memory_scanner import scan_process_memory
    r = scan_process_memory(pid, yara_scanner)
    # r = {"ok": True, "modules": [...], "scanned_bytes": N, "hits": [...], "truncated": bool}
"""
from __future__ import annotations

import ctypes
import os
import sys
import time
from ctypes import wintypes

__all__ = ["scan_process_memory", "list_process_modules", "MemoryScanResult"]

IS_WINDOWS = sys.platform == "win32"

# ── 常量 ──
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_PATH = 260
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# 单次扫描的字节上限 —— 防止把一个几百 MB 的进程整个读进内存
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
# 单个模块的读取上限（.text 通常远小于这个数）
DEFAULT_MAX_MODULE_BYTES = 32 * 1024 * 1024

if IS_WINDOWS:
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # ⚠️ 64 位下必须显式声明 restype/argtypes，否则句柄/指针会被当 c_int 截断
    #    （今天在 tray_icon.py 上刚被这个坑过）
    _k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

    _k32.ReadProcessMemory.restype = wintypes.BOOL
    _k32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]

    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]

    _k32.Module32FirstW.restype = wintypes.BOOL
    _k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _k32.Module32NextW.restype = wintypes.BOOL
    _k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * MAX_PATH),
    ]


class MemoryScanResult:
    __slots__ = ("ok", "error", "pid", "modules", "scanned_bytes", "truncated",
                 "hits", "elapsed", "skipped")

    def __init__(self, pid=0):
        self.pid = pid
        self.ok = False
        self.error = ""
        self.modules = []          # 成功读到的模块名
        self.scanned_bytes = 0
        self.truncated = False
        self.hits = []             # YARA 命中（含来源模块）
        self.skipped = []          # [(模块名, 原因)]
        self.elapsed = 0.0

    def to_dict(self):
        return {
            "ok": self.ok, "error": self.error, "pid": self.pid,
            "modules_total": len(self.modules) + len(self.skipped),
            "modules_read": len(self.modules),
            "scanned_bytes": self.scanned_bytes, "truncated": self.truncated,
            "hits": self.hits, "skipped": self.skipped,
            "elapsed_ms": round(self.elapsed * 1000, 1),
        }

    def __repr__(self):
        return "<MemoryScanResult pid=%d ok=%s modules=%d bytes=%d hits=%d>" % (
            self.pid, self.ok, len(self.modules), self.scanned_bytes, len(self.hits))


def list_process_modules(pid: int):
    """枚举目标进程已加载的模块 -> [(模块名, 基址, 大小, 路径)]"""
    if not IS_WINDOWS:
        return []
    h = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if not h or h == INVALID_HANDLE_VALUE:
        raise OSError("CreateToolhelp32Snapshot 失败 pid=%d err=%d"
                      % (pid, ctypes.get_last_error()))
    out = []
    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)
        ok = _k32.Module32FirstW(h, ctypes.byref(me))
        while ok:
            base = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value or 0
            out.append((me.szModule, base, int(me.modBaseSize), me.szExePath))
            me.dwSize = ctypes.sizeof(MODULEENTRY32W)
            ok = _k32.Module32NextW(h, ctypes.byref(me))
    finally:
        _k32.CloseHandle(h)
    return out


def _read_region(hproc, base, size, want_size=None):
    """从目标进程读一段内存；返回 bytes（可能短于请求，读不到就返回已读部分）"""
    n = int(size if want_size is None else min(size, want_size))
    if n <= 0:
        return b""
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    ok = _k32.ReadProcessMemory(hproc, ctypes.c_void_p(base), buf,
                                ctypes.c_size_t(n), ctypes.byref(got))
    if not ok or got.value == 0:
        return b""
    return buf.raw[:got.value]


def scan_process_memory(pid: int, yara_scanner=None, max_bytes: int = DEFAULT_MAX_BYTES,
                        max_module_bytes: int = DEFAULT_MAX_MODULE_BYTES,
                        module_filter=None) -> MemoryScanResult:
    """把目标进程已加载模块的内存读出来，喂给 YARA 扫描。

    pid             目标进程
    yara_scanner    有 scan_content(data, tag) -> list[dict] 的对象（YaraScanner）
    max_bytes       所有模块合计读取上限
    max_module_bytes 单个模块读取上限（.text 一般远小于这个数）
    module_filter   可调用 (name, path) -> bool，返回 False 则跳过该模块
                    （默认跳过可能会误报的规则来源，例如样本自己释放的临时文件）
    """
    res = MemoryScanResult(pid)
    t0 = time.perf_counter()
    if not IS_WINDOWS:
        res.error = "仅支持 Windows"
        return res
    if not pid or pid <= 0:
        res.error = "无效 pid"
        return res

    try:
        mods = list_process_modules(pid)
    except OSError as e:
        res.error = str(e)
        return res

    hproc = _k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not hproc:
        res.error = "OpenProcess 失败 err=%d（权限不足或进程已退出）" % ctypes.get_last_error()
        res.elapsed = time.perf_counter() - t0
        return res

    try:
        for name, base, size, path in mods:
            if max_bytes and res.scanned_bytes >= max_bytes:
                res.truncated = True
                break
            if module_filter and not module_filter(name, path):
                res.skipped.append((name, "被 module_filter 排除"))
                continue
            if size <= 0 or base <= 0:
                res.skipped.append((name, "基址/大小无效"))
                continue

            want = min(size, max_module_bytes)
            if max_bytes:
                want = min(want, max_bytes - res.scanned_bytes)
            data = _read_region(hproc, base, size, want)
            if not data:
                # 页不可读（常见于已卸载但快照仍列出的模块、或保护页）
                res.skipped.append((name, "读取失败（页保护或已卸载）"))
                continue

            res.modules.append(name)
            res.scanned_bytes += len(data)

            if yara_scanner is not None:
                try:
                    hits = yara_scanner.scan_content(data, "<mem:%s>" % name)
                except Exception as exc:
                    res.skipped.append((name, "扫描异常: %s" % exc))
                    continue
                for h in hits or ():
                    hh = dict(h)
                    hh["_source"] = "memory"
                    hh["_module"] = name
                    res.hits.append(hh)
        res.ok = True
    finally:
        _k32.CloseHandle(hproc)
        res.elapsed = time.perf_counter() - t0
    return res
