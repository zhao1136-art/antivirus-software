"""在 sysdiag(火绒) 过滤驱动存在的环境下，测量哪种调用模式能真正收到事件。"""
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
k32.GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                    ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
k32.GetOverlappedResult.restype = wintypes.BOOL
k32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
k32.CreateEventW.restype = wintypes.HANDLE
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
k32.WaitForSingleObject.restype = wintypes.DWORD
k32.FindFirstChangeNotificationW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD]
k32.FindFirstChangeNotificationW.restype = wintypes.HANDLE
k32.FindNextChangeNotification.argtypes = [wintypes.HANDLE]
k32.FindNextChangeNotification.restype = wintypes.BOOL
k32.FindCloseChangeNotification.argtypes = [wintypes.HANDLE]
k32.FindCloseChangeNotification.restype = wintypes.BOOL


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE)]


FILTER = 0x15F
BUF = 256 * 1024
WAIT_TIMEOUT = 0x102
N = 5

base = os.path.join(tempfile.gettempdir(), "rdcw-matrix-%d" % os.getpid())
os.makedirs(base, exist_ok=True)
print("dir:", base)


def parse(buf, count):
    out = []
    off = 0
    while off + 12 <= count:
        nxt = wintypes.DWORD.from_buffer(buf, off).value
        act = wintypes.DWORD.from_buffer(buf, off + 4).value
        nlen = wintypes.DWORD.from_buffer(buf, off + 8).value
        name = bytes(buf[off + 12: off + 12 + nlen]).decode("utf-16-le", "replace")
        out.append((act, name))
        if nxt == 0 or off + nxt >= count:
            break
        off += nxt
    return out


def make_write(i):
    p = os.path.join(base, "w%02d.txt" % i)
    with open(p, "w") as fh:
        fh.write("x" * 10)
    return p


def scenario_sync(label, bwait):
    """同步模式：bWait=TRUE/FALSE + 非空 OVERLAPPED。每次读取前写一个文件。"""
    h = k32.CreateFileW(base, 0x80000000, 0x7, None, 3, 0x02000000, None)
    buf = ctypes.create_string_buffer(BUF)
    got, immediate, zero = 0, 0, 0
    for i in range(N):
        ov = OVERLAPPED()
        ov.hEvent = None
        ret = wintypes.DWORD(0)
        ev = threading.Event()
        box = {}

        def body():
            box["ok"] = bool(k32.ReadDirectoryChangesW(
                h, ctypes.cast(buf, ctypes.c_void_p), BUF, True, FILTER,
                ctypes.byref(ret), ctypes.byref(ov), None))
            box["err"] = ctypes.get_last_error()
            box["bytes"] = ret.value
            ev.set()

        th = threading.Thread(target=body, daemon=True)
        th.start()
        if ev.wait(1.0):
            immediate += 1
        # 无论是否立即返回，都制造一次真实变更
        p = make_write(i)
        ev.wait(3.0)
        th.join(3.0)
        bytes_ = box.get("bytes", 0)
        if bytes_:
            got += 1
        else:
            zero += 1
        try:
            os.remove(p)
        except OSError:
            pass
        time.sleep(0.25)
    print("  %-40s 收到事件 %d/%d, 立即返回 %d, bytes=0 %d"
          % (label, got, N, immediate, zero))
    k32.CloseHandle(h)
    return got


def scenario_overlapped(label, poll_stop=False):
    """真正的 overlapped：hEvent + WaitForSingleObject + GetOverlappedResult。"""
    h = k32.CreateFileW(base, 0x80000000, 0x7, None, 3, 0x02000000, None)
    buf = ctypes.create_string_buffer(BUF)
    got, immediate, zero = 0, 0, 0
    for i in range(N):
        ov = OVERLAPPED()
        ev_handle = k32.CreateEventW(None, True, False, None)
        ov.hEvent = ev_handle
        ret = wintypes.DWORD(0)
        t0 = time.monotonic()
        ok = k32.ReadDirectoryChangesW(h, ctypes.cast(buf, ctypes.c_void_p), BUF, True,
                                       FILTER, ctypes.byref(ret), ctypes.byref(ov), None)
        err = ctypes.get_last_error()
        if not ok and err != 997:  # ERROR_IO_PENDING
            print("  %-40s 发起失败 err=%d" % (label, err))
            k32.CloseHandle(ev_handle)
            break
        wr = k32.WaitForSingleObject(ev_handle, 1000)
        if wr == WAIT_TIMEOUT:
            pass  # 正常挂起
        else:
            immediate += 1
        p = make_write(i)
        wr = k32.WaitForSingleObject(ev_handle, 3000)
        n = wintypes.DWORD(0)
        if wr != WAIT_TIMEOUT:
            k32.GetOverlappedResult(h, ctypes.byref(ov), ctypes.byref(n), True)
        if n.value:
            got += 1
        else:
            zero += 1
        try:
            os.remove(p)
        except OSError:
            pass
        k32.CloseHandle(ev_handle)
        time.sleep(0.2)
    print("  %-40s 收到事件 %d/%d, 立即返回 %d, bytes=0 %d"
          % (label, got, N, immediate, zero))
    k32.CloseHandle(h)
    return got


def scenario_findchange(label):
    """FindFirstChangeNotification 系（无数据，只报"有变化"）。"""
    h = k32.FindFirstChangeNotificationW(base, True, FILTER)
    got = 0
    for i in range(N):
        p = make_write(i)
        wr = k32.WaitForSingleObject(h, 3000)
        if wr != WAIT_TIMEOUT:
            got += 1
            k32.FindNextChangeNotification(h)
        try:
            os.remove(p)
        except OSError:
            pass
        time.sleep(0.15)
    print("  %-40s 收到信号 %d/%d" % (label, got, N))
    k32.FindCloseChangeNotification(h)
    return got


print("\n=== 同步模式 ===")
scenario_sync("sync bWait=TRUE", True)
scenario_sync("sync bWait=FALSE", False)
print("\n=== overlapped + event ===")
scenario_overlapped("overlapped hEvent + Wait")
print("\n=== FindFirstChangeNotification ===")
scenario_findchange("FindFirstChangeNotification")

shutil.rmtree(base, ignore_errors=True)
print("\nDONE")
