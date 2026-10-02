"""基于 Windows ``ReadDirectoryChangesW`` 的目录变更监控（纯标准库 + ctypes）。

模块定位
--------
用户态实时防护的"眼睛"。每个根目录一条 daemon 线程，同步调用
``ReadDirectoryChangesW`` 阻塞等待变更，回调以 ``(path, action)`` 形式上报。

不依赖任何第三方包（无 pywin32 / watchdog / psutil），仅使用
``ctypes`` / ``threading`` / ``os`` / ``sys`` / ``time`` / ``queue``。

公开接口
--------
``DirWatcher(on_event, dirs=None)``
    ``on_event(path: str, action: str) -> None``，``action`` 取值
    ``"added" | "modified" | "renamed" | "removed"``。
``DirWatcher.start()`` / ``stop(timeout=3.0)`` / ``running()`` / ``stats``

设计要点（都是实测会踩的坑）
----------------------------
* 打开目录必须带 ``FILE_FLAG_BACKUP_SEMANTICS``，否则 ``CreateFileW`` 直接
  返回 ``ERROR_ACCESS_DENIED``。
* 缓冲区 256KB，事件风暴下 ``ReadDirectoryChangesW`` 会返回
  ``lpBytesReturned == 0`` 表示"缓冲区溢出，通知已丢失"：此时只记一次
  ``errors`` 并立刻重新发起读取，**绝不退出线程**。
* 可唤醒性：``overlapped`` 结构 + 手动复位的 stop 事件 + ``bWait=TRUE``。
  这里用的是 P9 的同步语义（函数内部等 I/O 完成，返回时数据已就绪），
  ``hEvent`` 仅作为"监视对象"交给 ``WaitForSingleObject``，因此不需要
  ``GetOverlappedResult``，也就没有 ``ERROR_IO_PENDING`` 分支；
  ``stop()`` 置位事件即可让阻塞中的线程在毫秒级内退出。
* ``stop()`` 会 drain 掉已排队的取消操作：长循环里每轮开头都检查事件，
  再加一次 self-poke 兜底，避免线程在关闭句柄后仍卡在读取里。
* 回调在监控线程上执行（热点路径）：任何异常都被吞掉并计入 ``stats["errors"]``，
  回调绝不能把监控线程搞死；重的防抖交给调用方。
* 重启时``overlapped``/缓冲区按线程重新分配，避免复用已损坏的 OVERLAPPED。

已知取舍
--------
* 不跑 overlapped 事件循环（``bWait=TRUE`` 同步等待），更简单、更少坑；
  代价是每个根目录占一条阻塞线程，且无法同时等待"读取完成"与"stop"两个
  事件——靠 ``stop()`` 的 self-poke 解决。
* 重命名事件按 Windows 的原始语义上报两条：``Action=4``（旧名）与
  ``Action=5``（新名）都映射为 ``"renamed"``，调用方若要配对需自行按时间
  窗口聚合（本模块不做有状态的配对，以免引入延迟）。
* ``FILE_NOTIFY_CHANGE_SECURITY`` 在部分文件系统上会被拒绝
  （``ERROR_INVALID_PARAMETER``），此时会自动降级重试，见 ``_FILTER_FALLBACKS``。
"""

from __future__ import annotations

import ctypes
import os
import queue
import sys
import threading
import time
from ctypes import wintypes

__all__ = ["DirWatcher", "DEFAULT_ROOTS", "DEFAULT_BUFFER_SIZE", "ACTIONS"]

_IS_WINDOWS = sys.platform == "win32"

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------

# CreateFileW
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # 打开目录必须带，否则 ACCESS_DENIED

# 错误码
_ERROR_OPERATION_ABORTED = 995
_ERROR_ACCESS_DENIED = 5
_ERROR_INVALID_PARAMETER = 87
_ERROR_INVALID_HANDLE = 6
_ERROR_NOTIFY_ENUM_DIR = 1022  # 一次性通知：缓冲区溢出，通知已丢失

# WaitForSingleObject
_WAIT_OBJECT_0 = 0x00000000
_WAIT_ABANDONED = 0x00000080
_WAIT_TIMEOUT = 0x00000102
_WAIT_FAILED = 0xFFFFFFFF
_INFINITE = 0xFFFFFFFF

# ReadDirectoryChangesW 的 watch 过滤器：全开
_FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
_FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
_FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
_FILE_NOTIFY_CHANGE_SIZE = 0x00000008
_FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
_FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
_FILE_NOTIFY_CHANGE_CREATION = 0x00000040
_FILE_NOTIFY_CHANGE_SECURITY = 0x00000100

FILTER_ALL = (
    _FILE_NOTIFY_CHANGE_FILE_NAME
    | _FILE_NOTIFY_CHANGE_DIR_NAME
    | _FILE_NOTIFY_CHANGE_ATTRIBUTES
    | _FILE_NOTIFY_CHANGE_SIZE
    | _FILE_NOTIFY_CHANGE_LAST_WRITE
    | _FILE_NOTIFY_CHANGE_CREATION
    | _FILE_NOTIFY_CHANGE_SECURITY
)

# 某些文件系统（或旧驱动）不接受 SECURITY / LAST_ACCESS 位，逐级降级
_FILTER_FALLBACKS = (
    FILTER_ALL,
    FILTER_ALL & ~_FILE_NOTIFY_CHANGE_SECURITY,
    _FILE_NOTIFY_CHANGE_FILE_NAME
    | _FILE_NOTIFY_CHANGE_DIR_NAME
    | _FILE_NOTIFY_CHANGE_ATTRIBUTES
    | _FILE_NOTIFY_CHANGE_SIZE
    | _FILE_NOTIFY_CHANGE_LAST_WRITE
    | _FILE_NOTIFY_CHANGE_CREATION,
    _FILE_NOTIFY_CHANGE_FILE_NAME | _FILE_NOTIFY_CHANGE_DIR_NAME,
)

# FILE_NOTIFY_INFORMATION.Action -> 对外 action
ACTIONS = {
    1: "added",        # FILE_ACTION_ADDED
    2: "removed",      # FILE_ACTION_REMOVED
    3: "modified",     # FILE_ACTION_MODIFIED
    4: "renamed",      # FILE_ACTION_RENAMED_OLD_NAME
    5: "renamed",      # FILE_ACTION_RENAMED_NEW_NAME
}

DEFAULT_BUFFER_SIZE = 256 * 1024  # 256KB，抗事件风暴
DEFAULT_SUBTREE = True            # 是否递归监控子目录
_STOP_WAIT_MS = 250               # 每轮额外自唤醒周期，兜底检查 stop

# 建议默认监控的根（用户目录，避开系统目录）
DEFAULT_ROOTS = ("Desktop", "Downloads", "%TEMP%", "%APPDATA%")


# --------------------------------------------------------------------------
# Win32 结构体 / 函数绑定
# --------------------------------------------------------------------------


class _OVERLAPPED(ctypes.Structure):
    """OVERLAPPED。仅用到 hEvent 字段，其余作对齐占位。"""

    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


class _FILE_NOTIFY_INFORMATION(ctypes.Structure):
    """FILE_NOTIFY_INFORMATION 头部（FileName 变长，单独切片读取）。"""

    _fields_ = [
        ("NextEntryOffset", wintypes.DWORD),
        ("Action", wintypes.DWORD),
        ("FileNameLength", wintypes.DWORD),
        # FileName 紧随其后，长度 FileNameLength 字节，UTF-16LE，无 NUL 结尾
    ]


_FNI_HEADER_SIZE = ctypes.sizeof(_FILE_NOTIFY_INFORMATION)

try:
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
except OSError:  # pragma: no cover - 仅非 Windows 上可能发生
    _k32 = None


def _bind_kernel32(k32) -> None:
    """绑定签名。放在函数里，方便导入期在任何平台都能安全跳过。"""
    k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    k32.CreateFileW.restype = wintypes.HANDLE

    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL

    k32.ReadDirectoryChangesW.argtypes = [
        wintypes.HANDLE,      # hDirectory
        ctypes.c_void_p,      # lpBuffer
        wintypes.DWORD,       # nBufferLength
        wintypes.BOOL,        # bWatchSubtree
        wintypes.DWORD,       # dwNotifyFilter
        ctypes.POINTER(wintypes.DWORD),  # lpBytesReturned
        ctypes.POINTER(_OVERLAPPED),     # lpOverlapped
        ctypes.c_void_p,      # lpCompletionRoutine
    ]
    k32.ReadDirectoryChangesW.restype = wintypes.BOOL

    k32.CreateEventW.argtypes = [
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.BOOL,
        wintypes.LPCWSTR,
    ]
    k32.CreateEventW.restype = wintypes.HANDLE

    k32.SetEvent.argtypes = [wintypes.HANDLE]
    k32.SetEvent.restype = wintypes.BOOL

    k32.ResetEvent.argtypes = [wintypes.HANDLE]
    k32.ResetEvent.restype = wintypes.BOOL

    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.WaitForSingleObject.restype = wintypes.DWORD


if _IS_WINDOWS and _k32 is not None:
    try:
        _bind_kernel32(_k32)
    except (AttributeError, TypeError):  # pragma: no cover
        _k32 = None


def _last_error() -> int:
    try:
        return ctypes.get_last_error()
    except Exception:  # pragma: no cover
        return 0


def _format_winerror(code: int) -> str:
    if not code:
        return "unknown error"
    try:
        return "%s (WinError %d)" % (ctypes.FormatError(code), code)
    except Exception:  # pragma: no cover
        return "WinError %d" % code


def _strip_long_prefix(path: str) -> str:
    r"""去掉 \\?\ 长路径前缀，返回调用方友好的普通路径。"""
    if not isinstance(path, str):
        path = os.fspath(path)
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def _dir_key(path: str) -> str:
    """用于去重的规范化 key（大小写与尾部分隔符不敏感）。"""
    key = os.path.normpath(path)
    return key.rstrip("\\/").lower() or key.lower()


def _default_roots():
    """Desktop / Downloads / %TEMP% / %APPDATA%，只保留真实存在的目录。"""
    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Desktop"),
        os.path.join(home, "Downloads"),
        os.environ.get("TEMP") or os.environ.get("TMP"),
        os.environ.get("APPDATA"),
    ]
    roots, seen = [], set()
    for cand in candidates:
        if not cand:
            continue
        try:
            full = os.path.normpath(_strip_long_prefix(os.path.expandvars(cand)))
        except Exception:  # pragma: no cover
            continue
        key = _dir_key(full)
        if key in seen:
            continue
        seen.add(key)
        if os.path.isdir(full):
            roots.append(full)
    return roots


# --------------------------------------------------------------------------
# 监控线程
# --------------------------------------------------------------------------


class _RootWorker:
    """单个根目录的监控线程。"""

    def __init__(self, watcher, root, on_event, buffer_size, subtree):
        self._watcher = watcher
        self.root = root
        self._on_event = on_event
        self._buffer_size = buffer_size
        self._subtree = bool(subtree)
        self._thread = None
        self._stop_event = None      # 手动复位事件，置位表示要求退出
        self._handle = None          # 目录句柄
        self._handle_lock = threading.Lock()
        # 诊断计数（debug=True 时也有意义）
        self.calls = 0               # ReadDirectoryChangesW 调用次数
        self.immediate = 0           # 调用立即返回（未阻塞）的次数
        self.zero_bytes = 0          # 返回 0 字节的次数
        self.blocked = 0             # 阻塞过的次数
        self.trace = []              # debug 时记录最近若干次调用结果

    # -- 生命周期 ---------------------------------------------------------
    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        if _k32 is None:
            raise OSError("kernel32 unavailable (non-Windows platform)")
        event = _k32.CreateEventW(None, True, False, None)  # 手动复位，未置位
        if not event:
            code = _last_error()
            raise OSError(
                "CreateEventW failed: %s" % _format_winerror(code), code
            )
        self._stop_event = event
        self._thread = threading.Thread(
            target=self._run,
            name="rtguard-dirwatch",
            daemon=True,
        )
        self._thread.start()

    def signal_stop(self):
        event = self._stop_event
        if event:
            try:
                _k32.SetEvent(event)
            except Exception:
                pass

    def join(self, deadline):
        thread = self._thread
        if thread is not None and thread.is_alive():
            remaining = deadline - time.monotonic()
            if remaining > 0:
                thread.join(remaining)

    def is_alive(self):
        thread = self._thread
        return bool(thread is not None and thread.is_alive())

    def close(self):
        """幂等清理：关事件句柄。若线程仍在跑，先请求它自行结束。"""
        if self.is_alive():
            self.signal_stop()
            try:
                self._thread.join(1.0)
            except Exception:
                pass
        event, self._stop_event = self._stop_event, None
        if event:
            try:
                _k32.CloseHandle(event)
            except Exception:
                pass
        self._thread = None

    # -- 句柄 -------------------------------------------------------------
    def _snapshot_handle(self):
        with self._handle_lock:
            return self._handle

    def _open_directory(self):
        handle = _k32.CreateFileW(
            self.root,
            _GENERIC_READ,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS,  # 缺这个 → ERROR_ACCESS_DENIED
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in (None, 0, invalid):
            code = _last_error()
            return None, code
        with self._handle_lock:
            self._handle = handle
        return handle, 0

    def _close_directory(self):
        with self._handle_lock:
            handle, self._handle = self._handle, None
        if handle:
            try:
                _k32.CloseHandle(handle)
            except Exception:
                pass

    # -- 线程主循环 -------------------------------------------------------
    def _run(self):
        watcher = self._watcher
        buffer = ctypes.create_string_buffer(self._buffer_size)
        overlay = _OVERLAPPED()
        overlay.hEvent = None  # 同步 bWait=TRUE 模式：不使用完成事件
        bytes_returned = wintypes.DWORD(0)
        filter_index = 0

        handle = None
        try:
            while not self._stop_requested():
                if handle is None:
                    handle, code = self._open_directory()
                    if handle is None:
                        watcher._note_error(
                            "%s: CreateFileW failed: %s"
                            % (self.root, _format_winerror(code))
                        )
                        # 打不开的根（权限/被占用）：不算致命，稍后重试一次
                        if self._stop_requested():
                            return
                        if not self._sleep(1.0):
                            return
                        continue

                _t_call = time.monotonic()
                ok = bool(
                    _k32.ReadDirectoryChangesW(
                        handle,
                        ctypes.cast(buffer, ctypes.c_void_p),
                        self._buffer_size,
                        self._subtree,
                        _FILTER_FALLBACKS[filter_index],
                        ctypes.byref(bytes_returned),
                        ctypes.byref(overlay),
                        None,
                    )
                )
                if self._watcher.debug:
                    elapsed = time.monotonic() - _t_call
                    self.calls += 1
                    if elapsed < 0.001:
                        self.immediate += 1
                    else:
                        self.blocked += 1
                    if len(self.trace) < 40:
                        self.trace.append(
                            (round(elapsed, 4), bool(ok), bytes_returned.value)
                        )

                if self._stop_requested():
                    return

                if not ok:
                    code = _last_error()
                    if code == _ERROR_OPERATION_ABORTED or self._stop_requested():
                        return  # 句柄被关闭 → 正常退出路径
                    if code == _ERROR_INVALID_HANDLE:
                        return
                    if code == _ERROR_INVALID_PARAMETER and filter_index + 1 < len(
                        _FILTER_FALLBACKS
                    ):
                        filter_index += 1
                        watcher._note_error(
                            "%s: filter 0x%X rejected, retry with 0x%X"
                            % (
                                self.root,
                                _FILTER_FALLBACKS[filter_index - 1],
                                _FILTER_FALLBACKS[filter_index],
                            )
                        )
                        continue
                    watcher._note_error(
                        "%s: ReadDirectoryChangesW failed: %s"
                        % (self.root, _format_winerror(code))
                    )
                    self._close_directory()
                    handle = None
                    if not self._sleep(0.5):
                        return
                    continue

                count = bytes_returned.value
                if count == 0:
                    # 缓冲区溢出 / 一次性通知：通知已丢失，只记一次 error，
                    # 立刻重新发起读取，绝不退出监控线程。
                    watcher._note_error(
                        "%s: notification buffer overflow, events lost"
                        % self.root
                    )
                    continue

                try:
                    self._dispatch(buffer, count)
                except Exception as exc:  # 解析异常也不能杀线程
                    watcher._note_error(
                        "%s: dispatch failed: %r" % (self.root, exc)
                    )
        except Exception as exc:  # pragma: no cover - 最后一道防线
            watcher._note_error("%s: worker crashed: %r" % (self.root, exc))
        finally:
            self._close_directory()

    def _stop_requested(self):
        event = self._stop_event
        if event is None:
            return True
        try:
            return (
                _k32.WaitForSingleObject(event, 0) != _WAIT_TIMEOUT
            )
        except Exception:  # pragma: no cover
            return True

    def _sleep(self, seconds):
        """分段等待 stop 事件；返回 False 表示应当退出线程。"""
        deadline = time.monotonic() + seconds
        while True:
            if self._stop_requested():
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return True
            time.sleep(min(0.05, remaining))

    # -- 解析 FILE_NOTIFY_INFORMATION 链表 --------------------------------
    def _dispatch(self, buffer, count):
        on_event = self._on_event
        root = self.root
        offset = 0
        while True:
            if offset + _FNI_HEADER_SIZE > count:
                return
            info = _FILE_NOTIFY_INFORMATION.from_buffer(buffer, offset)
            name_len = int(info.FileNameLength)
            name_start = offset + _FNI_HEADER_SIZE
            name_end = name_start + name_len
            if name_len and name_end > count:
                return  # 缓冲区尾部截断，丢弃这条不完整记录

            action = ACTIONS.get(int(info.Action))
            if action is not None:
                # FileName 是 UTF-16LE，长度严格按 FileNameLength 截取（无 NUL 结尾）
                raw = bytes(buffer[name_start:name_end])
                try:
                    rel = raw.decode("utf-16-le", "surrogatepass")
                except Exception:
                    rel = raw.decode("utf-16-le", "replace")
                if rel:
                    # 相对名统一用反斜杠，再交给 os.path.join 拼回绝对路径
                    rel = rel.replace("/", "\\").lstrip("\\")
                    path = _strip_long_prefix(os.path.join(root, rel))
                    self._safe_emit(on_event, path, action)

            next_offset = int(info.NextEntryOffset)
            if next_offset == 0:
                return
            offset += next_offset
            if offset <= 0 or offset >= count:
                return

    def _safe_emit(self, on_event, path, action):
        """回调是热点路径：任何异常都吞掉并计入 errors，不能杀掉监控线程。"""
        try:
            on_event(path, action)
        except Exception as exc:
            self._watcher._note_error("callback error on %s: %r" % (path, exc))
            if self._watcher.debug:
                try:
                    sys.stderr.write("[rtguard.watcher] callback error: %r\n" % (exc,))
                except Exception:
                    pass


# --------------------------------------------------------------------------
# 公开 API
# --------------------------------------------------------------------------


class DirWatcher:
    """多根目录变更监控器。

    参数
    ----
    on_event:
        回调 ``on_event(path: str, action: str) -> None``，在监控线程上调用。
        ``action`` ∈ ``{"added", "modified", "renamed", "removed"}``。
        回调内抛出的异常不会中断监控，只会计入 ``stats["errors"]``。
    dirs:
        要监控的根目录列表；``None`` 时用 ``DEFAULT_ROOTS``
        （用户 Desktop / Downloads / %TEMP% / %APPDATA%，仅取存在者）。
        重复路径（大小写/尾部分隔符不同）会自动去重。

    线程模型
    --------
    每个根目录一条 daemon 线程 + 一个手动复位事件；``start()``/``stop()``
    幂等，可反复 start/stop 复用同一实例。
    """

    def __init__(self, on_event, dirs=None):
        if not callable(on_event):
            raise TypeError("on_event must be callable as on_event(path, action)")
        self._on_event = on_event
        self._lock = threading.RLock()
        self._workers = []
        self._started = False
        self._events = 0
        self._errors = 0
        self._dropped = 0          # 队列溢出时丢弃的未知 action 计数
        self._root_errors = {}     # 每个根的 last error 文本
        self.debug = False
        self._buffer_size = DEFAULT_BUFFER_SIZE
        self._subtree = DEFAULT_SUBTREE

        roots = _default_roots() if dirs is None else list(dirs)
        self._roots = self._normalize_roots(roots)

    # -- 内部 -------------------------------------------------------------
    @staticmethod
    def _normalize_roots(roots):
        out, seen = [], set()
        for root in roots:
            if not root:
                continue
            try:
                full = os.path.normpath(
                    _strip_long_prefix(os.path.expandvars(os.fspath(root)))
                )
            except Exception:
                continue
            key = _dir_key(full)
            if key in seen:      # 不要对同一路径重复订阅
                continue
            seen.add(key)
            out.append(full)
        return out

    def _note_error(self, message):
        with self._lock:
            self._errors += 1
            self._root_errors[message] = self._root_errors.get(message, 0) + 1
        if self.debug:
            try:
                sys.stderr.write("[rtguard.watcher] %s\n" % (message,))
            except Exception:
                pass

    def _emit(self, path, action):
        """线程侧调用：先计数再回调。"""
        with self._lock:
            self._events += 1
            on_event = self._on_event
        try:
            on_event(path, action)
        except Exception as exc:
            self._note_error("callback error on %s: %r" % (path, exc))

    # -- 公开接口 ---------------------------------------------------------
    def start(self) -> None:
        """启动监控（幂等）。已在运行时不重复起线程。"""
        with self._lock:
            if self._started:
                return
            # 为每个根包一层 _emit，保证计数/异常隔离统一在 _RootWorker 里完成
            self._workers = [
                _RootWorker(self, root, self._emit, self._buffer_size, self._subtree)
                for root in self._roots
            ]
            self._started = True
            workers = list(self._workers)

        for worker in workers:
            try:
                worker.start()
            except Exception as exc:
                self._note_error("%s: failed to start worker: %r" % (worker.root, exc))

    def stop(self, timeout: float = 3.0) -> None:
        """停止监控（幂等）。``timeout`` 是等待所有线程退出的总预算（秒）。"""
        with self._lock:
            if not self._started:
                return
            self._started = False
            workers = list(self._workers)
            self._workers = []

        deadline = time.monotonic() + max(0.0, float(timeout))

        # 1) 置位所有 stop 事件
        for worker in workers:
            worker.signal_stop()

        # 2) 自写"零字节事件"兜底：某些情况下目录读取可能长时间不返回，
        #    对每个根做一次能触发 FILE_NOTIFY_CHANGE_* 的写操作（创建+删除
        #    临时文件），把线程从阻塞的读取里弹出来。
        for worker in workers:
            if worker.is_alive():
                self._poke(worker.root)

        # 3) 限时 join；仍不退出则关句柄强制解除阻塞（不阻塞调用方）
        for worker in workers:
            worker.join(deadline)
        for worker in workers:
            if worker.is_alive():
                worker._close_directory()
        for worker in workers:
            worker.join(deadline)
            worker.close()

    def running(self) -> bool:
        """是否处于监控状态（start 已调用且有线程存活）。"""
        with self._lock:
            if not self._started:
                return False
            workers = list(self._workers)
        return any(worker.is_alive() for worker in workers)

    @property
    def stats(self) -> dict:
        """运行统计快照：``{"events", "roots", "errors"}`` 外加若干诊断字段。"""
        with self._lock:
            workers = list(self._workers)
            started = self._started
            return {
                "events": self._events,
                "roots": len(self._roots),
                "errors": self._errors,
                "running": bool(started and any(w.is_alive() for w in workers)),
                "threads_alive": sum(1 for w in workers if w.is_alive()),
                "dropped": self._dropped,
                "queued": 0,  # 本模块不做内部排队（回调即消费），保留字段以稳定 schema
                "last_errors": dict(self._root_errors),
            }

    # 便于测试/诊断
    @property
    def roots(self):
        return list(self._roots)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

    def __repr__(self):  # pragma: no cover - 调试用
        state = "running" if self.running() else "stopped"
        return "<DirWatcher %s roots=%d events=%d errors=%d>" % (
            state,
            len(self._roots),
            self._events,
            self._errors,
        )

    # -- 唤醒辅助 ---------------------------------------------------------
    @staticmethod
    def _poke(root):
        """对根目录做一次零字节的自写事件，用于打断阻塞中的同步读取。"""
        probe = os.path.join(
            root, ".rtguard-wake-%d-%d.tmp" % (os.getpid(), int(time.time() * 1000) % 100000)
        )
        try:
            with open(probe, "wb"):
                pass
        except Exception:
            return
        try:
            os.remove(probe)
        except Exception:
            pass


# --------------------------------------------------------------------------
# 可选：把 win32 事件泵接到 queue.Queue（调用方要异步消费时用）
# --------------------------------------------------------------------------


class QueueWatcher(DirWatcher):
    """把事件写入 ``queue.Queue`` 的便捷封装（可选，不影响主接口）。"""

    def __init__(self, dirs=None, maxsize: int = 4096):
        super().__init__(self._put, dirs=dirs)
        self.queue = queue.Queue(maxsize=maxsize)

    def _put(self, path, action):
        try:
            self.queue.put_nowait((path, action))
        except queue.Full:
            with self._lock:
                self._dropped += 1

    def drain(self, limit: int = 256):
        out = []
        while len(out) < limit:
            try:
                out.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return out
