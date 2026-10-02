"""Decisive test: reuse buffer/OVERLAPPED vs fresh ones, interleaved in one process."""
import ctypes
import os
import shutil
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
k32.CloseHandle.argtypes = [wintypes.HANDLE]


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE)]


FILTER = 0x15F
BUF_SIZE = 256 * 1024
base = os.path.join(tempfile.gettempdir(), "rdcw-fresh-%d" % os.getpid())
os.makedirs(base, exist_ok=True)
LOG = r"H:\Caelire\rtguard\.selfcheck\fresh.log"
_out = open(LOG, "w", encoding="utf-8", buffering=1)


def log(*a):
    _out.write(" ".join(str(x) for x in a) + "\n")
    _out.flush()


log("dir:", base)


def show(buf, count):
    off = 0
    while off + 12 <= count:
        nxt = wintypes.DWORD.from_buffer(buf, off).value
        act = wintypes.DWORD.from_buffer(buf, off + 4).value
        nlen = wintypes.DWORD.from_buffer(buf, off + 8).value
        name = bytes(buf[off + 12:off + 12 + nlen]).decode("utf-16-le", "replace")
        log("        action=%d name=%s" % (act, name))
        if nxt == 0 or off + nxt >= count:
            break
        off += nxt


def round_test(tag, reuse, n=3):
    h = k32.CreateFileW(base, 0x80000000, 0x7, None, 3, 0x02000000, None)
    fixed_buf = ctypes.create_string_buffer(BUF_SIZE)
    fixed_ov = OVERLAPPED()
    got = zero = 0
    for i in range(n):
        if reuse:
            buf = fixed_buf
            ov = fixed_ov
        else:
            buf = ctypes.create_string_buffer(BUF_SIZE)
            ov = OVERLAPPED()
        ov.hEvent = None
        ret = wintypes.DWORD(0)
        t0 = time.monotonic()
        ok = k32.ReadDirectoryChangesW(h, ctypes.cast(buf, ctypes.c_void_p), BUF_SIZE,
                                       True, FILTER, ctypes.byref(ret), ctypes.byref(ov), None)
        dt = time.monotonic() - t0
        err = 0 if ok else ctypes.get_last_error()
        p = os.path.join(base, "%s-%d.txt" % (tag, i))
        with open(p, "w") as fh:
            fh.write("x")
        time.sleep(0.25)
        log("    [%s] call#%d blocked=%.3fs ok=%s err=%d bytes=%d"
            % (tag, i, dt, bool(ok), err, ret.value))
        if ret.value:
            got += 1
            show(buf, ret.value)
        else:
            zero += 1
        try:
            os.remove(p)
        except OSError:
            pass
        time.sleep(0.15)
    k32.CloseHandle(h)
    log("    [%s] got=%d zero=%d" % (tag, got, zero))


for rnd in range(2):
    log("=== round %d ===" % rnd)
    round_test("reuse", True)
    round_test("fresh", False)

shutil.rmtree(base, ignore_errors=True)
log("DONE")
os._exit(0)
