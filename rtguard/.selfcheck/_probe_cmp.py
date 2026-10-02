"""决定性对比：把 watcher 里用的调用原样抄出来，逐项对照。"""
import ctypes
import os
import shutil
import sys
import tempfile
import threading
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
k32.CreateFileW.restype = wintypes.HANDLE
k32.ReadDirectoryChangesW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                      wintypes.BOOL, wintypes.DWORD,
                                      ctypes.POINTER(wintypes.DWORD),
                                      ctypes.c_void_p, ctypes.c_void_p]
k32.ReadDirectoryChangesW.restype = wintypes.BOOL
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.CloseHandle.restype = wintypes.BOOL


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE)]


FILTER_ALL = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x40 | 0x100   # watcher 用的
FILTER_P1F = 0x1FF

base = os.path.join(tempfile.gettempdir(), "rdcw-cmp-%d" % os.getpid())
os.makedirs(base, exist_ok=True)
print("dir:", base)
print("sizeof(OVERLAPPED) =", ctypes.sizeof(OVERLAPPED))
print("watcher FILTER = 0x%X" % FILTER_ALL)

h = k32.CreateFileW(base, 0x80000000, 0x1 | 0x2 | 0x4, None, 3, 0x02000000, None)
invalid = ctypes.c_void_p(-1).value
print("handle:", hex(h if isinstance(h, int) else 0), "invalid?", h == invalid,
      "err", ctypes.get_last_error())

# 每个 case 都在子线程里跑，5 秒超时判定"是否真的阻塞"
def run_case(label, buffer_size, filter_flags, subtree, use_overlapped, timeout=5.0):
    result = {}

    def body():
        buf = ctypes.create_string_buffer(buffer_size)
        ov = OVERLAPPED()
        ov.hEvent = None
        ret = wintypes.DWORD(0)
        t0 = time.monotonic()
        ok = k32.ReadDirectoryChangesW(
            h, ctypes.cast(buf, ctypes.c_void_p), buffer_size, subtree,
            filter_flags, ctypes.byref(ret), ctypes.byref(ov) if use_overlapped else None, None)
        result["elapsed"] = time.monotonic() - t0
        result["ok"] = bool(ok)
        result["err"] = ctypes.get_last_error() if not ok else 0
        result["returned"] = ret.value

    th = threading.Thread(target=body, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        print("%-46s BLOCKED (>=%.1fs)  <-- 阻塞，正常" % (label, timeout))
    else:
        print("%-46s returned ok=%s err=%s bytes=%s after %.4fs"
              % (label, result.get("ok"), result.get("err"), result.get("returned"),
                 result.get("elapsed", -1)))

    # 触发一次写，让阻塞的调用返回
    with open(os.path.join(base, "trigger.tmp"), "w") as fh:
        fh.write("x")
    th.join(2.0)
    try:
        os.remove(os.path.join(base, "trigger.tmp"))
    except OSError:
        pass
    return result


run_case("A: 256KB, watcher FILTER, subtree, overlapped", 256 * 1024, FILTER_ALL, True, True)
run_case("B: 64KB,  watcher FILTER, subtree, overlapped", 64 * 1024, FILTER_ALL, True, True)
run_case("C: 256KB, 0x1FF filter,  subtree, overlapped", 256 * 1024, FILTER_P1F, True, True)
run_case("D: 256KB, watcher FILTER, subtree, NULL ov", 256 * 1024, FILTER_ALL, True, False)

k32.CloseHandle(h)
shutil.rmtree(base, ignore_errors=True)
