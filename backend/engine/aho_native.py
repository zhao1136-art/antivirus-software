"""
Aho-Corasick 原生后端（matcher.dll）—— 与 yara_scanner._AhoCorasick 同接口

这是一层**适配层**：`yara_scanner` 原本有一个纯 Python 的 `_AhoCorasick`
（多模式一遍遍历），但 Python 逐字节推进太慢，实测整条扫描链路只有
约 0.145 MB/s。这里把同一套 `add / build / find` 契约换成 C 实现
（native/matcher.dll，Aho-Corasick 完全 DFA），实测 337 MB/s。

契约（与 _AhoCorasick 完全一致）
--------------------------------
    ac = NativeAhoCorasick()
    ac.add(pattern: bytes, payload)     # payload 任意对象，本引擎传 (rid, name)
    ac.build()
    ac.find(data: bytes) -> list        # 返回命中的 payload 列表

失败语义
--------
构造时找不到 DLL、或 build 失败，一律**抛异常**，由 `yara_scanner`
捕获后回退到纯 Python 实现 —— 适配层不允许让扫描功能缺失。
"""
from __future__ import annotations

import ctypes
import os
import sys
import threading

__all__ = ["NativeAhoCorasick", "find_matcher_dll", "native_available"]

_HERE = os.path.dirname(os.path.abspath(__file__))
_DLL_NAMES = ("matcher.dll", "libmatcher.dll")

_probe_cache = None  # None=未探测 / False=不可用 / str=有效路径


def _candidate_paths():
    env = os.environ.get("RTGUARD_MATCHER_DLL")
    if env:
        yield env
    for base in (_HERE, os.path.join(_HERE, "native"),
                 os.path.join(os.path.dirname(_HERE), "native")):
        for n in _DLL_NAMES:
            yield os.path.join(base, n)
    # rtguard 项目里的那份（两个项目共用同一个匹配器）
    for base in (r"H:\Caelire\rtguard\native",):
        for n in _DLL_NAMES:
            yield os.path.join(base, n)
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", "") or os.path.dirname(sys.executable)
        for n in _DLL_NAMES:
            yield os.path.join(base, n)
            yield os.path.join(base, "native", n)


def find_matcher_dll():
    """返回 matcher.dll 路径，找不到返回 None（结果进程内缓存）"""
    global _probe_cache
    if _probe_cache is not None:
        return _probe_cache or None
    for p in _candidate_paths():
        if p and os.path.isfile(p):
            _probe_cache = os.path.abspath(p)
            return _probe_cache
    _probe_cache = False
    return None


def native_available() -> bool:
    return find_matcher_dll() is not None


class NativeAhoCorasick:
    """matcher.dll 的薄封装，接口对齐 _AhoCorasick"""

    def __init__(self):
        path = find_matcher_dll()
        if not path:
            raise RuntimeError("未找到 matcher.dll")
        # C 侧是 C 默认 __cdecl；必须用 CDLL。用 WinDLL 会栈不平衡 -> 0xC0000005
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
        self._dll = dll
        self.dll_path = path
        self._patterns = []
        self._payloads = []
        self._handle = None
        self._out = None
        self._lock = threading.Lock()
        self.node_count = 0

    # ── 与 _AhoCorasick 相同的三个方法 ──
    def add(self, pattern, payload):
        if isinstance(pattern, (bytearray, memoryview)):
            pattern = bytes(pattern)
        if not isinstance(pattern, bytes) or not pattern:
            return
        self._patterns.append(pattern)
        self._payloads.append(payload)

    def build(self):
        n = len(self._patterns)
        if n == 0:
            self._handle = None
            return
        blob = b"".join(self._patterns)
        offsets = []
        lengths = []
        off = 0
        for p in self._patterns:
            offsets.append(off)
            lengths.append(len(p))
            off += len(p)
        arr_o = (ctypes.c_int32 * n)(*offsets)
        arr_l = (ctypes.c_int32 * n)(*lengths)
        handle = self._dll.ac_build(blob, arr_o, arr_l, n)
        if not handle:
            raise RuntimeError("ac_build 失败（内存不足或模式数超限）")
        self._handle = handle
        self._out = (ctypes.c_int32 * (n + 8))()
        self.node_count = int(self._dll.ac_node_count(handle))

    def find(self, data):
        """返回命中的 payload 列表（每个模式只报一次）"""
        if self._handle is None or not data:
            return []
        with self._lock:
            n = self._dll.ac_scan(self._handle, data, len(data),
                                  self._out, len(self._patterns) + 8)
            if n <= 0:
                return []
            return [self._payloads[self._out[i]] for i in range(n)]

    def describe(self):
        return "native Aho-Corasick (%s, %d 模式, %d 节点)" % (
            os.path.basename(self.dll_path), len(self._patterns), self.node_count)

    def close(self):
        with self._lock:
            if self._handle:
                self._dll.ac_free(self._handle)
                self._handle = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
