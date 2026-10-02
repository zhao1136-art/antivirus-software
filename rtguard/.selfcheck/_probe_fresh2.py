"""Decisive test with hard timeouts: reuse vs fresh buffer/OVERLAPPED.

Each ReadDirectoryChangesW runs in a worker thread. If it has not completed
within TIMEOUT seconds we close the directory handle (aborting the pending
IRP) and record a TIMEOUT, then use a fresh handle for the next iteration.
"""
import ctypes
import os
import shutil
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


FILTER = 0x15F
BUF_SIZE = 256 * 1024
TIMEOUT = 2.5
base = os.path.join(tempfile.gettempdir(), "rdcw-to-%d" % os.getpid())
os.makedirs(base, exist_ok=True)
LOG = r"H:\Caelire\rtguard\.selfcheck\fresh2.log"
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


def open_dir():
    return k32.CreateFileW(base, 0x80000000, 0x7, None, 3, 0x02000000, None)


def one_call(h, buf, ov):
    """Run one read with a watchdog. Returns (status, bytes, seconds)."""
    box = {}
    done = threading.Event()

    def body():
        ret = wintypes.DWORD(0)
        t0 = time.monotonic()
        ok = k32.ReadDirectoryChangesW(h, ctypes.cast(buf, ctypes.c_void_p), BUF_SIZE,
                                       True, FILTER, ctypes.byref(ret),
                                       ctypes.byref(ov), None)
        box["dt"] = time.monotonic() - t0
        box["ok"] = bool(ok)
        box["err"] = 0 if ok else ctypes.get_last_error()
        box["bytes"] = ret.value
        done.set()

    th = threading.Thread(target=body, daemon=True)
    th.start()
    p = os.path.join(base, "evt-%d.txt" % (time.monotonic_ns() % 100000))
    with open(p, "w") as fh:
        fh.write("x")
    if not done.wait(TIMEOUT):
        k32.CloseHandle(h)          # abort the pending IRP
        done.wait(2.0)
        return "TIMEOUT", 0, box.get("dt", -1.0), p
    return ("ok" if box["ok"] else "err"), box["bytes"], box["dt"], p


def round_test(tag, reuse, n=3):
    fixed_buf = ctypes.create_string_buffer(BUF_SIZE)
    fixed_ov = OVERLAPPED()
    h = open_dir()
    got = zero = 0
    for i in range(n):
        buf = fixed_buf if reuse else ctypes.create_string_buffer(BUF_SIZE)
        ov = fixed_ov if reuse else OVERLAPPED()
        ov.hEvent = None
        status, nbytes, dt, p = one_call(h, buf, ov)
        log("    [%s] call#%d status=%s blocked=%.3fs bytes=%d"
            % (tag, i, status, dt, nbytes))
        if status == "TIMEOUT":
            h = open_dir()          # handle was closed to abort
            remain = n - i - 1
            if remain > 0:
                log("    [%s] (handle re-opened; aborting run early)" % tag)
            try:
                os.remove(p)
            except OSError:
                pass
            break
        if nbytes:
            got += 1
            show(buf, nbytes)
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
