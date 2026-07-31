"""
Realtime monitor: glue between DirectoryWatcher, Scanner, and quarantine/log.

Headless CLI:
    python -m src.monitor --watch <dir>            # blocks until Ctrl+C
    python -m src.monitor --watch <dir> --duration 60  # exits after 60s

Used by:
    src/tray.py    (starts/stops a Monitor on tray commands)
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scan_api import Scanner, ScanResult  # noqa: E402
from watcher import DirectoryWatcher  # noqa: E402
from quarantine import (  # noqa: E402
    quarantine_file, log_scan,
    DEFAULT_QUARANTINE_DIR, DEFAULT_LOG_DIR, SCAN_LOG_NAME,
)
from process_monitor import ProcessMonitor, ProcessEvent  # noqa: E402
from behavior_rules import SequenceDetector, RuleMatch  # noqa: E402
from behavior_alert import log_behavior, BEHAVIOR_LOG_NAME  # noqa: E402


# ---------- Monitor ---------------------------------------------------------

class Monitor:
    """Combined filesystem + behavioral monitor with a single start/stop."""

    def __init__(self,
                 watch_dir: str | None,
                 quarantine_dir: str = DEFAULT_QUARANTINE_DIR,
                 log_dir: str = DEFAULT_LOG_DIR,
                 extra_excludes: tuple[str, ...] = (),
                 on_event: Callable[[ScanResult, str | None], None] | None = None,
                 enable_filesystem: bool = True,
                 enable_behavior: bool = False,
                 procmon_backend: str = "psutil",
                 procmon_poll: float = 0.3,
                 verbose: bool = True):
        self.quarantine_dir = os.path.abspath(quarantine_dir)
        self.log_dir = os.path.abspath(log_dir)
        self.scanner = Scanner()
        self.on_event = on_event
        self.verbose = verbose

        self.watcher: DirectoryWatcher | None = None
        self.watch_dir: str | None = None
        if enable_filesystem and watch_dir:
            self.watch_dir = os.path.abspath(watch_dir)
            excludes = [self.quarantine_dir, self.log_dir, *extra_excludes]
            self.watcher = DirectoryWatcher(
                self.watch_dir,
                on_event=self._handle_path,
                excludes=excludes,
            )

        self.procmon: ProcessMonitor | None = None
        self.detector: SequenceDetector | None = None
        if enable_behavior:
            self.detector = SequenceDetector(on_match=self._handle_match)
            self.procmon = ProcessMonitor(
                on_event=self._handle_proc_event,
                backend=procmon_backend,
                poll_interval=procmon_poll,
            )

        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

    # ---- lifecycle -----------------------------------------------------

    @property
    def is_running(self) -> bool:
        fs_running = self.watcher is not None and self.watcher.is_running
        beh_running = self.procmon is not None and self.procmon._backend._thread is not None and self.procmon._backend._thread.is_alive()
        return fs_running or beh_running

    def start(self) -> None:
        import traceback
        if self.watcher is not None:
            try:
                self.watcher.start()
            except Exception:
                print("[monitor] ERROR starting DirectoryWatcher:", file=sys.stderr)
                traceback.print_exc()
            else:
                if self.verbose:
                    print(f"[monitor] FS watching: {self.watch_dir}")
                    print(f"[monitor] quarantine: {self.quarantine_dir}")
                    print(f"[monitor] scan log:   {os.path.join(self.log_dir, SCAN_LOG_NAME)}")
                # Cheap liveness check: the worker thread should be alive
                # right after start(). A dead thread here means _run crashed
                # before its main loop even began.
                thr = self.watcher._thread
                if thr is None or not thr.is_alive():
                    print("[monitor] WARNING: DirectoryWatcher worker thread "
                          "is NOT alive after start()", file=sys.stderr)
                elif self.verbose:
                    print(f"[monitor] watcher thread '{thr.name}' alive=True")
        if self.procmon is not None:
            try:
                self.procmon.start()
            except Exception:
                print("[monitor] ERROR starting ProcessMonitor:", file=sys.stderr)
                traceback.print_exc()
            else:
                if self.verbose:
                    print(f"[monitor] behavior monitor: backend={self.procmon.backend_name}")
                    print(f"[monitor] behavior log:    {os.path.join(self.log_dir, BEHAVIOR_LOG_NAME)}")
        # One-shot retrain-pressure warning at startup.
        try:
            from feedback import maybe_warn_about_feedback
            maybe_warn_about_feedback()
        except Exception:
            pass

    def stop(self) -> None:
        if self.procmon is not None:
            self.procmon.stop()
        if self.watcher is not None:
            self.watcher.stop()
        if self.verbose:
            print("[monitor] stopped")

    # ---- behavioral plumbing ------------------------------------------

    def _handle_proc_event(self, ev: ProcessEvent) -> None:
        if self.detector is not None:
            self.detector.on_event(ev)

    def _handle_match(self, match: RuleMatch) -> None:
        try:
            log_behavior(match, log_dir=self.log_dir)
        except Exception as e:
            if self.verbose:
                print(f"[monitor] behavior log write failed: {e}")
            return
        if self.verbose:
            print(f"[monitor] BEHAVIOR  rule={match.rule_id}  sev={match.severity}  "
                  f"pid={match.process.pid}  name={match.process.name}  "
                  f"parent={match.parent.name if match.parent else '?'}")
            print(f"[monitor]    desc: {match.description}")
            if match.process.cmdline:
                snippet = (match.process.cmdline[:120] +
                           ("..." if len(match.process.cmdline) > 120 else ""))
                print(f"[monitor]    cmd : {snippet}")

    # ---- event handling ------------------------------------------------

    def _handle_path(self, path: str) -> None:
        if self.verbose:
            print(f"[monitor] event: {path}")
        try:
            result = self.scanner.scan(path)
        except Exception as e:
            if self.verbose:
                print(f"[monitor] scan error for {path}: {e}")
            return

        quar_path: str | None = None
        if result.verdict == "MALICIOUS":
            try:
                meta = quarantine_file(result, quarantine_dir=self.quarantine_dir)
                quar_path = meta["quarantine_path"]
            except Exception as e:
                if self.verbose:
                    print(f"[monitor] quarantine failed for {path}: {e}")
        try:
            log_scan(result, log_dir=self.log_dir, quarantine_path=quar_path)
        except Exception as e:
            if self.verbose:
                print(f"[monitor] log write failed: {e}")

        if self.verbose:
            tag = "QUARANTINED" if quar_path else result.verdict
            print(f"[monitor] -> {tag}  conf={result.confidence*100:.2f}%  "
                  f"type={result.file_type}  path={path}")
            if quar_path:
                print(f"[monitor]    quarantined to: {quar_path}")
            for r in result.reasons[:3]:
                print(f"[monitor]    reason: {r}")

        if self.on_event is not None:
            try:
                self.on_event(result, quar_path)
            except Exception:
                pass


# ---------- Headless CLI -----------------------------------------------------

_STOP_EVT = threading.Event()


def _install_sigint():
    def _handler(signum, frame):
        _STOP_EVT.set()
    try:
        signal.signal(signal.SIGINT, _handler)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description="Realtime PE/PS1/Office/PDF scanner + behavior monitor.")
    ap.add_argument("--watch", default=None, help="directory to watch (filesystem half)")
    ap.add_argument("--no-fs", action="store_true", help="disable filesystem monitor")
    ap.add_argument("--behavior", action="store_true", help="enable behavioral monitor")
    ap.add_argument("--procmon-backend", default="psutil", choices=["psutil", "wmi", "etw", "auto"])
    ap.add_argument("--procmon-poll", type=float, default=0.3)
    ap.add_argument("--quarantine-dir", default=DEFAULT_QUARANTINE_DIR)
    ap.add_argument("--log-dir", default=DEFAULT_LOG_DIR)
    ap.add_argument("--duration", type=float, default=0.0,
                    help="exit after this many seconds (0 = wait for Ctrl+C)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    enable_fs = not args.no_fs and bool(args.watch)
    enable_behavior = args.behavior
    if not enable_fs and not enable_behavior:
        ap.error("must enable at least one of filesystem (--watch) or --behavior")

    monitor = Monitor(
        watch_dir=args.watch,
        quarantine_dir=args.quarantine_dir,
        log_dir=args.log_dir,
        enable_filesystem=enable_fs,
        enable_behavior=enable_behavior,
        procmon_backend=args.procmon_backend,
        procmon_poll=args.procmon_poll,
        verbose=not args.quiet,
    )
    _install_sigint()
    monitor.start()

    try:
        if args.duration > 0:
            deadline = time.monotonic() + args.duration
            while not _STOP_EVT.is_set() and time.monotonic() < deadline:
                _STOP_EVT.wait(timeout=0.5)
        else:
            while not _STOP_EVT.is_set():
                _STOP_EVT.wait(timeout=0.5)
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()
