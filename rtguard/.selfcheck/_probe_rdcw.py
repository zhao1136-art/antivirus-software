"""最小复现：同步 ReadDirectoryChangesW 返回值行为探查。"""
import ctypes
import os
import sys
import tempfile
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
k32.GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                    ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
k32.GetOverlappedResult.restype = wintypes.BOOL
k32.GetLastError.restype = wintypes.DWORD


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE)]


base = os.path.join(tempfile.gettempdir(), "rdcw-probe-%d" % os.getpid())
os.makedirs(base, exist_ok=True)
print("dir:", base)

h = k32.CreateFileW(base, 0x80000000, 0x7, None, 3, 0x02000000, None)
print("handle:", hex(h or 0), "err", ctypes.get_last_error())
if h in (None, 0) or h == ctypes.c_void_p(-1).value:
    sys.exit("CreateFileW failed: %d" % ctypes.get_last_error())

BUF = 65536
buf = ctypes.create_string_buffer(BUF)
ov = OVERLAPPED()
ov.hEvent = None
ret = wintypes.DWORD(0)

FILTER = 0x1FF  # FILE_NAME|DIR_NAME|ATTR|SIZE|LAST_WRITE|CREATION|SECURITY

print("\n--- A) bWait=TRUE, lpBytesReturned 非空, lpOverlapped 非空 ---")
t0 = time.monotonic()
ok = k32.ReadDirectoryChangesW(h, ctypes.cast(buf, ctypes.c_void_p), BUF, True,
                               FILTER, ctypes.byref(ret), ctypes.byref(ov), None)
print("ok=%s err=%d returned=%d elapsed=%.4fs" % (ok, ctypes.get_last_error(), ret.value, time.monotonic() - t0))

print("\n--- B) bWait=TRUE, lpBytesReturned=NULL, lpOverlapped 非空 ---")
t0 = time.monotonic()
ok = k32.ReadDirectoryChangesW(h, ctypes.cast(buf, ctypes.c_void_p), BUF, True,
                               FILTER, None, ctypes.byref(ov), None)
print("ok=%s err=%d elapsed=%.4fs" % (ok, ctypes.get_last_error(), time.monotonic() - t0))
if ok:
    n = wintypes.DWORD(0)
    gr = k32.GetOverlappedResult(h, ctypes.byref(ov), ctypes.byref(n), True)
    print("  GetOverlappedResult ok=%s err=%d bytes=%d" % (gr, ctypes.get_last_error(), n.value))

print("\n--- C) 同步模式: lpOverlapped=NULL, bWait 无关 ---")
t0 = time.monotonic()
ok = k32.ReadDirectoryChangesW(h, ctypes.cast(buf, ctypes.c_void_p), BUF, True,
                               FILTER, ctypes.byref(ret), None, None)
print("ok=%s err=%d returned=%d elapsed=%.4fs" % (ok, ctypes.get_last_error(), ret.value, time.monotonic() - t0))
if ok and ret.value:
    off = 0
    class FNI(ctypes.Structure):
        _fields_ = [("NextEntryOffset", wintypes.DWORD), ("Action", wintypes.DWORD),
                    ("FileNameLength", wintypes.DWORD)]
    while True:
        info = FNI.from_buffer(buf, off)
        raw = bytes(buf[off + 12: off + 12 + info.FileNameLength])
        print("   action=%d name=%r" % (info.Action, raw.decode("utf-16-le")))
        if info.NextEntryOffset == 0:
            break
        off += info.NextEntryOffset

print("\n--- 触发一次写入 ---")
with open(os.path.join(base, "x.txt"), "w") as fh:
    fh.write("hi")

k32.CloseHandle(h)
time.sleep(0.1)
import shutil
shutil.rmtree(base, ignore_errors=True)
