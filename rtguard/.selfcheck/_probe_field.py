"""Which field carries the byte count? lpBytesReturned vs OVERLAPPED.InternalHigh,
   and does the NULL-OVERLAPPED sync form deliver data?"""
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
k32.GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                    ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
k32.GetOverlappedResult.restype = wintypes.BOOL


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE)]


FILTER = 0x15F
BUF_SIZE = 256 * 1024
base = os.path.join(tempfile.gettempdir(), "rdcw-field-%d" % os.getpid())
os.makedirs(base, exist_ok=True)
LOG = r"H:\Caelire\rtguard\.selfcheck\field.log"
_out = open(LOG, "w", encoding="utf-8", buffering=1)


def log(*a):
    _out.write(" ".join(str(x) for x in a) + "\n")
    _out.flush()


def open_dir():
    return k32.CreateFileW(base, 0x80000000, 0x7, None, 3, 0x02000000, None)


def parse(buf, count, label):
    off = 0
    n = 0
    while off + 12 <= count and n < 8:
        nxt = wintypes.DWORD.from_buffer(buf, off).value
        act = wintypes.DWORD.from_buffer(buf, off + 4).value
        nlen = wintypes.DWORD.from_buffer(buf, off + 8).value
        name = bytes(buf[off + 12:off + 12 + nlen]).decode("utf-16-le", "replace")
        log("        %s action=%d name=%s" % (label, act, name))
        n += 1
        if nxt == 0 or off + nxt >= count:
            break
        off += nxt


def scenario(tag, use_ov, delay=0.3, n=2):
    for k in range(n):
        h = open_dir()
        buf = ctypes.create_string_buffer(BUF_SIZE)
        ov = OVERLAPPED()
        ov.hEvent = None
        ret = wintypes.DWORD(0)
        box = {}
        done = threading.Event()

        def body():
            t0 = time.monotonic()
            ok = k32.ReadDirectoryChangesW(
                h, ctypes.cast(buf, ctypes.c_void_p), BUF_SIZE, True, FILTER,
                ctypes.byref(ret), ctypes.byref(ov) if use_ov else None, None)
            box["dt"] = time.monotonic() - t0
            box["ok"] = bool(ok)
            box["err"] = 0 if ok else ctypes.get_last_error()
            done.set()

        th = threading.Thread(target=body, daemon=True)
        th.start()
        time.sleep(delay)
        p = os.path.join(base, "%s-%d.txt" % (tag.replace("/", "_"), k))
        with open(p, "w") as fh:
            fh.write("x")
        finished = done.wait(3.0)
        if not finished:
            k32.CloseHandle(h)
            log("  %-22s call#%d TIMEOUT" % (tag, k))
            continue
        inner = wintypes.c_size_t.from_buffer(ov, 8).value if use_ov else None
        log("  %-22s call#%d ok=%s err=%d dt=%.3f lpBytesReturned=%d InternalHigh=%s"
            % (tag, k, box.get("ok"), box.get("err", -1), box.get("dt", -1),
               ret.value, inner))
        if ret.value:
            parse(buf, min(ret.value, BUF_SIZE), tag)
        if use_ov and inner:
            parse(buf, min(inner, BUF_SIZE), tag + "/IH")
        # also ask GetOverlappedResult
        if use_ov:
            gr = wintypes.DWORD(0)
            ok2 = k32.GetOverlappedResult(h, ctypes.byref(ov), ctypes.byref(gr), False)
            log("        GetOverlappedResult ok=%s got=%d" % (bool(ok2), gr.value))
        try:
            os.remove(p)
        except OSError:
            pass
        k32.CloseHandle(h)
        time.sleep(0.2)


log("dir:", base)
scenario("ov/nonnull", True)
scenario("ov/null", False)
shutil.rmtree(base, ignore_errors=True)
log("DONE")
os._exit(0)
