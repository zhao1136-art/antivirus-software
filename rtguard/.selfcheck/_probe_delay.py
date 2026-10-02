"""Measure: how does the delay between starting the read and the write affect results?"""
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

FILTER = 0x15F
BUF_SIZE = 256 * 1024
base = os.path.join(tempfile.gettempdir(), "rdcw-delay-%d" % os.getpid())
os.makedirs(base, exist_ok=True)
LOG = r"H:\Caelire\rtguard\.selfcheck\delay.log"
_out = open(LOG, "w", encoding="utf-8", buffering=1)


def log(*a):
    _out.write(" ".join(str(x) for x in a) + "\n")
    _out.flush()


log("dir:", base)


def open_dir():
    return k32.CreateFileW(base, 0x80000000, 0x7, None, 3, 0x02000000, None)


def run(delay, n=2):
    results = []
    for k in range(n):
        h = open_dir()
        buf = ctypes.create_string_buffer(BUF_SIZE)

        class OV(ctypes.Structure):
            _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                        ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                        ("hEvent", wintypes.HANDLE)]
        ov = OV()
        ov.hEvent = None
        ret = wintypes.DWORD(0)
        box = {}
        done = threading.Event()

        def body():
            t0 = time.monotonic()
            ok = k32.ReadDirectoryChangesW(h, ctypes.cast(buf, ctypes.c_void_p), BUF_SIZE,
                                           True, FILTER, ctypes.byref(ret),
                                           ctypes.byref(ov), None)
            box["dt"] = time.monotonic() - t0
            box["ok"] = bool(ok)
            box["err"] = 0 if ok else ctypes.get_last_error()
            done.set()

        th = threading.Thread(target=body, daemon=True)
        th.start()
        time.sleep(delay)
        p = os.path.join(base, "d%d-%d-%d.txt" % (int(delay * 1000), k, time.monotonic_ns() % 9999))
        with open(p, "w") as fh:
            fh.write("x")
        finished = done.wait(3.0)
        bytes_ = ret.value
        if not finished:
            k32.CloseHandle(h)
            results.append(("TIMEOUT", -1, 0))
        else:
            results.append(("ok" if box["ok"] else "err", round(box["dt"], 4), bytes_))
        try:
            os.remove(p)
        except OSError:
            pass
        try:
            k32.CloseHandle(h)
        except Exception:
            pass
        time.sleep(0.2)
    return results


for delay in (0.0, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0):
    res = run(delay)
    log("delay=%6.0fms -> %s" % (delay * 1000, res))

shutil.rmtree(base, ignore_errors=True)
log("DONE")
os._exit(0)
