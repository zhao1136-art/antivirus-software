"""精确刻画：同一句柄上连续多次同步读取的返回行为。"""
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


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE)]


FILTER = 0x15F
BUF = 256 * 1024

base = os.path.join(tempfile.gettempdir(), "rdcw-seq-%d" % os.getpid())
os.makedirs(base, exist_ok=True)
print("dir:", base)

h = k32.CreateFileW(base, 0x80000000, 0x7, None, 3, 0x02000000, None)
print("handle:", hex(h))

buf = ctypes.create_string_buffer(BUF)
ov = OVERLAPPED()
ov.hEvent = None
ret = wintypes.DWORD(0)


def rd(label, timeout=3.0):
    """在子线程里发起读取；超时说明"阻塞中"（正常）。"""
    box = {}

    def body():
        t0 = time.monotonic()
        ok = k32.ReadDirectoryChangesW(h, ctypes.cast(buf, ctypes.c_void_p), BUF, True,
                                       FILTER, ctypes.byref(ret), ctypes.byref(ov), None)
        box["elapsed"] = time.monotonic() - t0
        box["ok"] = bool(ok)
        box["err"] = 0 if ok else ctypes.get_last_error()
        box["bytes"] = ret.value

    th = threading.Thread(target=body, daemon=True)
    th.start()
    th.join(timeout)
    blocked = th.is_alive()
    print("  %-28s %s" % (label, "BLOCKED (正常)" if blocked
                          else "immediate ok=%s err=%s bytes=%s in %.4fs"
                          % (box.get("ok"), box.get("err"), box.get("bytes"), box.get("elapsed"))))
    return th, blocked, box


def touch(name="t.tmp"):
    p = os.path.join(base, name)
    with open(p, "w") as fh:
        fh.write("x")
    time.sleep(0.2)
    os.remove(p)
    time.sleep(0.2)


print("\n[1] 首次读取（无任何 pending）")
th, blocked, box = rd("call #1")
if blocked:
    touch()
    th.join(2.0)
print("   call #1 结果: ok=%s bytes=%s" % (box.get("ok"), box.get("bytes")))

print("\n[2] 同句柄第二次读取，目录里保证没有新事件")
time.sleep(0.5)
th, blocked, box = rd("call #2")
if blocked:
    touch()
    th.join(2.0)

print("\n[3] 同句柄第三次读取")
time.sleep(0.5)
th, blocked, box = rd("call #3")
if blocked:
    touch()
    th.join(2.0)

print("\n[4] 同句柄第四次：紧接一次真实写入，看能否拿到事件")
th, blocked, box = rd("call #4 (先阻塞等待)")
touch("real.txt")
th.join(2.0)
print("   call #4 结果: ok=%s bytes=%s" % (box.get("ok"), box.get("bytes")))

print("\n[5] 全新句柄，第一次读取")
k32.CloseHandle(h)
h2 = k32.CreateFileW(base, 0x80000000, 0x7, None, 3, 0x02000000, None)
h = h2
ov2 = OVERLAPPED()
ov2.hEvent = None
th, blocked, box = rd("fresh handle call #1")
if blocked:
    touch("fresh.txt")
    th.join(2.0)
print("   fresh#1 结果: ok=%s bytes=%s" % (box.get("ok"), box.get("bytes")))

print("\n[6] 新句柄第二次读取")
time.sleep(0.3)
th, blocked, box = rd("fresh handle call #2")
if blocked:
    touch("fresh2.txt")
    th.join(2.0)

k32.CloseHandle(h)
time.sleep(0.2)
try:
    shutil.rmtree(base, ignore_errors=True)
except Exception as e:
    print("cleanup:", e)
print("\nDONE")
