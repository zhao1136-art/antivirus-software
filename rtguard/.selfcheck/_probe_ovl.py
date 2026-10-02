"""Validate the fully-documented overlapped pattern:
   FILE_FLAG_OVERLAPPED handle + OVERLAPPED.hEvent + bWait=FALSE +
   WaitForSingleObject(hEvent, timeout) + GetOverlappedResult.
"""
import ctypes
import os
import shutil
import tempfile
import time
from ctypes import wintypes

class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE)]


k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
k32.CreateFileW.restype = wintypes.HANDLE
k32.ReadDirectoryChangesW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                      wintypes.BOOL, wintypes.DWORD,
                                      ctypes.POINTER(wintypes.DWORD),
                                      ctypes.POINTER(OVERLAPPED), ctypes.c_void_p]
k32.ReadDirectoryChangesW.restype = wintypes.BOOL
k32.GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED),
                                    ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
k32.GetOverlappedResult.restype = wintypes.BOOL
k32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
k32.CreateEventW.restype = wintypes.HANDLE
k32.ResetEvent.argtypes = [wintypes.HANDLE]
k32.SetEvent.argtypes = [wintypes.HANDLE]
k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
k32.WaitForSingleObject.restype = wintypes.DWORD
k32.CloseHandle.argtypes = [wintypes.HANDLE]

FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OVERLAPPED = 0x40000000
FILTER = 0x15F
BUF_SIZE = 256 * 1024
WAIT_TIMEOUT = 0x102
ERROR_IO_PENDING = 997

base = os.path.join(tempfile.gettempdir(), "rdcw-ovl-%d" % os.getpid())
os.makedirs(base, exist_ok=True)
LOG = r"H:\Caelire\rtguard\.selfcheck\ovl.log"
_out = open(LOG, "w", encoding="utf-8", buffering=1)


def log(*a):
    _out.write(" ".join(str(x) for x in a) + "\n")
    _out.flush()


def parse(buf, count):
    out = []
    off = 0
    while off + 12 <= count:
        nxt = wintypes.DWORD.from_buffer(buf, off).value
        act = wintypes.DWORD.from_buffer(buf, off + 4).value
        nlen = wintypes.DWORD.from_buffer(buf, off + 8).value
        name = bytes(buf[off + 12:off + 12 + nlen]).decode("utf-16-le", "replace")
        out.append((act, name))
        if nxt == 0 or off + nxt >= count:
            break
        off += nxt
    return out


log("dir:", base)

h = k32.CreateFileW(base, 0x80000000, 0x7, None, 3,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, None)
log("handle:", hex(h), "err", ctypes.get_last_error())

buf = ctypes.create_string_buffer(BUF_SIZE)
ov = (wintypes.c_void_p * 8)()          # 64-byte OVERLAPPED storage
ev = k32.CreateEventW(None, True, False, None)
ov[4] = ev                               # hEvent at offset 32 (64-bit)
ret = wintypes.DWORD(0)
got = timeout = zero = 0

for i in range(6):
    k32.ResetEvent(ev)
    ret.value = 0
    ok = k32.ReadDirectoryChangesW(h, ctypes.cast(buf, ctypes.c_void_p), BUF_SIZE,
                                   True, FILTER, ctypes.byref(ret),
                                   ctypes.byref(ov), None)
    err = ctypes.get_last_error()
    if not ok and err != ERROR_IO_PENDING:
        log("call#%d issue FAILED err=%d" % (i, err))
        break

    time.sleep(0.25)
    p = os.path.join(base, "file%02d.txt" % i)
    with open(p, "w") as fh:
        fh.write("data")
    time.sleep(0.15)
    if i % 2 == 0:
        with open(p, "a") as fh:
            fh.write("more")

    t0 = time.monotonic()
    wr = k32.WaitForSingleObject(ev, 3000)
    dt = time.monotonic() - t0
    if wr == WAIT_TIMEOUT:
        log("call#%d WAIT TIMEOUT (no completion)" % i)
        timeout += 1
    else:
        n = wintypes.DWORD(0)
        gr = k32.GetOverlappedResult(h, ctypes.byref(ov), ctypes.byref(n), False)
        ger = ctypes.get_last_error()
        log("call#%d wait=0x%X after %.3fs GetOverlappedResult=%s err=%d bytes=%d lpBytesReturned=%d"
            % (i, wr, dt, bool(gr), ger, n.value, ret.value))
        if n.value:
            got += 1
            for act, name in parse(buf, min(n.value, BUF_SIZE)):
                log("        action=%d name=%s" % (act, name))
        else:
            zero += 1
    try:
        os.remove(p)
    exc