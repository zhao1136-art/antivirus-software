"""
Windows directory watcher built on ReadDirectoryChangesW (overlapped I/O).

Why overlapped I/O: ReadDirectoryChangesW blocks indefinitely when called
synchronously. To stop the watcher cleanly we need to cancel the pending
read — that requires overlapped I/O + CancelIoEx.

Public API:
    DirectoryWatcher(root, on_event, excludes=[], debounce_ms=500)
        .start() / .stop() / .is_running

`on_event(path)` is invoked from a worker thread once per file, with
multiple rapid writes coalesced into one call thanks to the debouncer.
"""
from __future__ import annotations

import os
import threading
from typing import Callable, Iterable

import win32con
import win32event
import win32file
import pywintypes


# File-change actions emitted by ReadDirectoryChangesW.
FILE_ACTION_ADDED = 1
FILE_ACTION_REMOVED = 2
FILE_ACTION_MODIFIED = 3
FILE_ACTION_RENAMED_FROM = 4
FILE_ACTION_RENAMED_TO = 5

WATCH_ACTIONS = {FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_RENAMED_TO}

# pywin32 doesn't expose all FILE_NOTIFY_CHANGE_* constants on win32con —
# use the raw values from winnt.h.
_FN_FILE_NAME  = 0x0001
_FN_DIR_NAME   = 0x0002
_FN_ATTRIBUTES = 0x0004
_FN_SIZE       = 0x0008
_FN_LAST_WRITE = 0x0010
_FN_CREATION   = 0x0040
WATCH_FLAGS = _FN_FILE_NAME | _FN_LAST_WRITE | _FN_SIZE | _FN_CREATION

# Buffer must be DWORD-aligned and <= 64 KB for network drives.
BUFFER_SIZE = 64 * 1024
WAIT_POLL_MS = 200


class _Debouncer:
    """Per-path debouncer: a fresh event resets the path's timer.

    The callback fires `delay` seconds after the LAST event for that path —
    so a flurry of write/modify events while a file is being copied yields
    exactly one scan call at the end.
    """

    def __init__(self, callback: Callable[[str], None], delay_seconds: float = 0.5):
        self._cb = callback
        self._delay = delay_seconds
        self._timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()
        self._stopped = False

    def trigger(self, path: str) -> None:
        with self._lock:
            if self._stopped:
                return
            t = self._timers.get(path)
            if t is not None:
                t.cancel()
            t = threading.Timer(self._delay, self._fire, args=[path])
            t.daemon = True
            self._timers[path] = t
            t.start()

    def _fire(self, path: str) -> None:
        with self._lock:
            self._timers.pop(path, None)
        try:
            self._cb(path)
        except Exception as exc:  # don't kill the watcher on a bad scan
            print(f"[watcher] callback error for {path}: {exc}")

    def cancel_all(self) -> None:
        with self._lock:
            self._stopped = True
            for t in list(self._timers.values()):
                t.cancel()
            self._timers.clear()


class DirectoryWatcher:
    def __init__(self,
                 root: str,
                 on_event: Callable[[str], None],
                 excludes: Iterable[str] = (),
                 debounce_ms: int = 500):
        self.root = os.path.abspath(root)
        if not os.path.isdir(self.root):
            raise ValueError(f"watch root is not a directory: {self.root}")
        self._on_event = on_event
        self._excludes = [os.path.abspath(e) for e in excludes]
        self._debouncer = _Debouncer(self._dispatch, debounce_ms / 1000.0)
        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None
        self._dir_handle = None

    # ---- public ---------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_running:
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name=f"DirWatcher({self.root})")
        self._thread.start()

    def stop(self, join_timeout: float = 2.0) -> None:
        if not self.is_running:
            return
        self._stop_evt.set()
        # Unblock the pending ReadDirectoryChangesW. Older pywin32 builds
        # don't expose CancelIoEx; closing the directory handle works on all
        # versions (the worker's pending I/O then fails and the loop exits).
        if self._dir_handle is not None:
            cancel = getattr(win32file, "CancelIoEx", None)
            try:
                if cancel is not None:
                    cancel(self._dir_handle, None)
                else:
                    win32file.CloseHandle(self._dir_handle)
                    self._dir_handle = None
            except pywintypes.error:
                pass
        if self._thread is not None:
            self._thread.join(timeout=join_timeout)
        self._debouncer.cancel_all()

    # ---- internals ------------------------------------------------------

    def _is_excluded(self, abs_path: str) -> bool:
        for e in self._excludes:
            try:
                if abs_path == e or abs_path.startswith(e + os.sep):
                    return True
            except ValueError:
                continue
        return False

    def _dispatch(self, path: str) -> None:
        if not os.path.isfile(path):
            return
        if self._is_excluded(os.path.abspath(path)):
            return
        self._on_event(path)

    def _run(self) -> None:
        # Top-level guard: anything that escapes the worker prints a full
        # traceback instead of being silently swallowed by the daemon thread.
        try:
            self._run_impl()
        except Exception:
            import traceback
            print(f"[watcher] worker thread crashed for {self.root}:",
                  file=__import__("sys").stderr)
            traceback.print_exc()

    def _run_impl(self) -> None:
        try:
            self._dir_handle = win32file.CreateFile(
                self.root,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS | win32con.FILE_FLAG_OVERLAPPED,
                None,
            )
        except pywintypes.error as e:
            print(f"[watcher] CreateFile failed for {self.root}: {e}")
            return

        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
        buf = win32file.AllocateReadBuffer(BUFFER_SIZE)

        try:
            while not self._stop_evt.is_set():
                win32event.ResetEvent(overlapped.hEvent)
                try:
                    win32file.ReadDirectoryChangesW(
                        self._dir_handle, buf, True, WATCH_FLAGS, overlapped, None
                    )
                except pywintypes.error as e:
                    if not self._stop_evt.is_set():
                        print(f"[watcher] ReadDirectoryChangesW failed: {e}")
                    break

                # Wait in short slices so we notice _stop_evt.
                got_data = False
                while not self._stop_evt.is_set():
                    rc = win32event.WaitForSingleObject(overlapped.hEvent, WAIT_POLL_MS)
                    if rc == win32event.WAIT_OBJECT_0:
                        got_data = True
                        break

                if self._stop_evt.is_set():
                    # CloseHandle in the finally clause cancels the pending I/O.
                    break
                if not got_data:
                    continue

                try:
                    nbytes = win32file.GetOverlappedResult(self._dir_handle, overlapped, False)
                except pywintypes.error as e:
                    if not self._stop_evt.is_set():
                        print(f"[watcher] GetOverlappedResult: {e}")
                    break
                if nbytes == 0:
                    continue

                results = win32file.FILE_NOTIFY_INFORMATION(buf, nbytes)
                for action, fn in results:
                    if action not in WATCH_ACTIONS:
                        continue
                    full = os.path.join(self.root, fn)
                    abs_full = os.path.abspath(full)
                    if self._is_excluded(abs_full):
                        continue
                    # Skip directory events — file detection happens later.
                    if os.path.isdir(abs_full):
                        continue
                    self._debouncer.trigger(abs_full)
        finally:
            try:
                win32file.CloseHandle(overlapped.hEvent)
            except pywintypes.error:
                pass
            try:
                win32file.CloseHandle(self._dir_handle)
            except pywintypes.error:
                pass
            self._dir_handle = None
