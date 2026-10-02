"""
多模式字面量匹配器 —— 原生 Aho-Corasick 优先，纯 Python 回退

为什么不用现成的 YARA
---------------------
老实现（御天精简版 engine/yara_scanner.py）是纯 Python 的 YARA 复刻：
每个文件要把缓冲区遍历「模式数」次，实测吞吐 **0.145 MB/s**
（196 KB 文件 1.32 秒；scan.log 里 22.5 MB 文件 141.8 秒）。

本模块用 C 写的 Aho-Corasick 完全 DFA（native/matcher.c）做匹配：
扫描开销只与数据长度有关、与模式数量无关，实测 **337 MB/s**，
同一份数据快约 2000 倍。DLL 不可用时自动回退到纯 Python 逐模式查找
（正确但慢），保证功能不缺失。

接口
----
    ps = PatternSet([b"pattern1", b"pattern2", ...])
    ps.backend                     # "native" | "python"
    hit_indexes = ps.scan(data)    # -> set[int]，命中的模式下标
"""
from __future__ import annotations

import ctypes
import os
import sys

__all__ = ["PatternSet", "native_available", "native_path"]

_HERE = os.path.dirname(os.path.abspath(__file__))
_DLL_NAMES = ("matcher.dll", "libmatcher.dll")

_probe_cache = None  # None=未探测 / False=不可用 / str=有效路径


def native_path():
    """返回可用的 matcher.dll 路径，找不到返回 None（结果缓存）"""
    global _probe_cache
    if _probe_cache is not None:
        return _probe_cache or None

    candidates = [os.path.join(_HERE, "..", "native", n) for n in _DLL_NAMES]
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", "") or os.path.dirname(sys.executable)
        candidates += [os.path.join(base, "native", n) for n in _DLL_NAMES]
        candidates += [os.path.join(base, n) for n in _DLL_NAMES]
    for p in candidates:
        p = os.path.abspath(p)
        if os.path.isfile(p):
            _probe_cache = p
            return p
    _probe_cache = False
    return None


def native_available() -> bool:
    return native_path() is not None


class _NativeBackend:
    """matcher.dll 的 ctypes 绑定

    C 侧导出的是 C 默认 __cdecl 调用约定，必须用 CDLL（不是 WinDLL）——
    用错会让栈不平衡并直接触发 0xC0000005 访问违例。
    """

    def __init__(self, patterns):
        path = native_path()
        if not path:
            raise RuntimeError("未找到 matcher.dll")
        dll = ctypes.CDLL(path)
        dll.ac_build.restype = ctypes.c_void_p
        dll.ac_build.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int32),
                                 ctypes.POINTER(ctypes.c_int32), ctypes.c_int32]
        dll.ac_scan.restype = ctypes.c_int32
        dll.ac_scan.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                ctypes.POINTER(ctypes.c_int32), ctypes.c_int32]
        dll.ac_free.restype = None
        dll.ac_free.argtypes = [ctypes.c_void_p]
        dll.ac_node_count.restype = ctypes.c_int32
        dll.ac_node_count.argtypes = [ctypes.c_void_p]

        n = len(patterns)
        blob = b"".join(patterns)
        offsets = []
        lengths = []
        off = 0
        for p in patterns:
            offsets.append(off)
            lengths.append(len(p))
            off += len(p)
        arr_o = (ctypes.c_int32 * n)(*offsets)
        arr_l = (ctypes.c_int32 * n)(*lengths)

        self._dll = dll
        self._n = n
        self._out = (ctypes.c_int32 * (n + 8))()
        self._handle = dll.ac_build(blob, arr_o, arr_l, n)
        if not self._handle:
            raise RuntimeError("ac_build 失败（内存不足或模式数超限）")
        self.node_count = int(dll.ac_node_count(self._handle))
        self._closed = False

    def scan(self, data: bytes) -> set:
        if self._closed or not data:
            return set()
        n = self._dll.ac_scan(self._handle, data, len(data), self._out, self._n + 8)
        if n <= 0:
            return set()
        return {self._out[i] for i in range(n)}

    def close(self):
        if not self._closed and self._handle:
            self._dll.ac_free(self._handle)
            self._closed = True
            self._handle = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class _PythonBackend:
    """纯 Python 回退：逐模式 bytes.find

    正确但慢（约 0.7 s/MB / 1000 个模式）。仅在没有 native/matcher.dll 时使用。
    bytes.find 本身是 C 速度，瓶颈在 Python 层的循环次数。
    """

    def __init__(self, patterns):
        self._patterns = list(patterns)
        self.node_count = 0

    def scan(self, data: bytes) -> set:
        if not data:
            return set()
        return {i for i, p in enumerate(self._patterns) if p and p in data}

    def close(self):
        pass


class PatternSet:
    """多模式匹配器。构造时优先装载原生后端，失败自动回退。"""

    def __init__(self, patterns, prefer_native: bool = True):
        self.patterns = [bytes(p) for p in patterns if p]
        self.error = ""
        self._backend = None

        if prefer_native and self.patterns:
            try:
                self._backend = _NativeBackend(self.patterns)
                self.backend = "native"
                return
            except Exception as exc:
                self.error = "%s: %s" % (type(exc).__name__, exc)
        elif not prefer_native:
            self.error = "调用方显式禁用原生后端"

        self._backend = _PythonBackend(self.patterns)
        self.backend = "python"

    @property
    def node_count(self) -> int:
        return getattr(self._backend, "node_count", 0)

    def describe(self) -> str:
        if self.backend == "native":
            return "native Aho-Corasick (%d 模式, %d 节点)" % (
                len(self.patterns), self.node_count)
        return "pure-python (%d 模式; 原生不可用: %s)" % (
            len(self.patterns), self.error or "未尝试")

    def scan(self, data: bytes) -> set:
        """返回命中的模式下标集合"""
        if self._backend is None or not data:
            return set()
        return self._backend.scan(data)

    def close(self):
        if self._backend is not None:
            self._backend.close()
            self._backend = None
