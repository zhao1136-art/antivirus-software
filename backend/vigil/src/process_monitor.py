"""
Process-creation event source.

Two backends in order of preference:
  1. WMI   - Win32_ProcessStartTrace via the `wmi` package. True event push,
             no polling jitter. Requires the `wmi` package + COM. We treat
             this as opt-in (set --etw on CLI) because COM threading from
             Python can be brittle and the default test path uses psutil.
  2. psutil - portable polling. Sample every N ms, diff PID sets, emit a
             ProcessEvent for each new PID. Misses very short-lived
             processes (< poll interval) but reliably catches anything
             that lives ~200 ms or longer — which is the typical case for
             interactive shells, PowerShell, and macro-spawned commands.

Note on ETW directly: Microsoft-Windows-Kernel-Process events would be the
ideal source (zero polling, kernel-level granularity) but require admin and
a real ETW consumer library (`pywintrace` or a thin C extension). Out of
scope for this phase; psutil polling is sufficient for the in-scope rules.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Callable, Optional


@dataclass
class ProcessEvent:
    timestamp: datetime
    event_type: str            # "create" | "exit"
    pid: int
    ppid: Optional[int] = None
    name: str = ""             # exe basename, lowercase
    exe_path: Optional[str] = None
    cmdline: Optional[str] = None
    user: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


# ---------- psutil polling backend ------------------------------------------

class _PsutilBackend:
    """Diff-based process tracker. Holds a per-pid cache so the rule engine
    can resolve parents even after the parent dies."""

    def __init__(self, on_create: Callable[[ProcessEvent], None],
                 poll_interval: float = 0.3,
                 seed_existing: bool = True):
        import psutil  # late import so module loads on systems without psutil
        self._psutil = psutil
        self._on_create = on_create
        self._poll = poll_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: dict[int, float] = {}   # pid -> create time
        self._seed_existing = seed_existing

    @property
    def backend_name(self) -> str:
        return "psutil"

    def _snapshot_event(self, pid: int) -> ProcessEvent | None:
        """Build a ProcessEvent for `pid` by querying psutil directly.

        Called per *new* pid only, so the per-call cost of username/cmdline
        resolution is paid at most once per process. Returns None if the
        process has already exited or we can't read it.
        """
        ps = self._psutil
        try:
            p = ps.Process(pid)
        except (ps.NoSuchProcess, ps.AccessDenied):
            return None

        # Pull each field with its own try/except. username() in particular
        # can fail with AccessDenied on protected processes; we still want
        # the rest of the fields in that case.
        def _safe(fn, default=None):
            try:
                return fn()
            except (ps.NoSuchProcess, ps.AccessDenied, Exception):
                return default

        name = (_safe(p.name, "") or "").lower()
        ppid = _safe(p.ppid, None)
        exe = _safe(p.exe, None)
        cmd_list = _safe(p.cmdline, []) or []
        cmd = " ".join(cmd_list) if isinstance(cmd_list, list) else str(cmd_list)
        user = _safe(p.username, None)

        return ProcessEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="create",
            pid=pid,
            ppid=ppid,
            name=name,
            exe_path=exe,
            cmdline=cmd,
            user=user,
        )

    def _loop(self):
        ps = self._psutil
        # Cheap seed: just PIDs. We claim the new pid in _seen BEFORE
        # snapshotting so a slow snapshot can't cause the same pid to be
        # queued twice on the next iteration.
        if self._seed_existing:
            try:
                for pid in ps.pids():
                    self._seen[pid] = time.monotonic()
            except Exception:
                pass

        while not self._stop.is_set():
            try:
                current_pids = ps.pids()
            except Exception:
                current_pids = []

            # First pass: claim every new pid in _seen immediately. This is
            # the "fast" loop -- no per-pid syscalls. Short-lived processes
            # are guaranteed to be detected here even if their attrs are
            # gone by the time we snapshot them below.
            new_pids = []
            now = time.monotonic()
            for pid in current_pids:
                if pid in self._seen:
                    continue
                self._seen[pid] = now
                new_pids.append(pid)

            # Second pass: snapshot each new pid (this is the slow part).
            # Done inline but per-pid, with broad exception tolerance so one
            # protected process can't stall the rest of the batch.
            for pid in new_pids:
                try:
                    ev = self._snapshot_event(pid)
                except Exception:
                    ev = None
                if ev is None:
                    # Best-effort minimal event so callers at least see the
                    # pid existed -- rules will likely not match an empty
                    # cmdline but parent-cache entries still get populated.
                    ev = ProcessEvent(
                        timestamp=datetime.now(timezone.utc),
                        event_type="create",
                        pid=pid,
                    )
                try:
                    self._on_create(ev)
                except Exception as exc:
                    print(f"[procmon] callback error: {exc}")

            self._stop.wait(self._poll)

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ProcMon-psutil")
        self._thread.start()

    def stop(self, join_timeout: float = 2.0):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=join_timeout)


# ---------- WMI backend (opt-in) --------------------------------------------

class _WMIBackend:
    """Win32_ProcessStartTrace consumer. Push-based, no polling latency."""

    def __init__(self, on_create: Callable[[ProcessEvent], None]):
        self._on_create = on_create
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def backend_name(self) -> str:
        return "wmi"

    def _loop(self):
        # COM must be initialized on this thread for wmi.
        import pythoncom
        pythoncom.CoInitialize()
        try:
            import wmi
            c = wmi.WMI()
            watcher = c.watch_for(notification_type="creation",
                                  wmi_class="Win32_Process")
            while not self._stop.is_set():
                try:
                    proc = watcher(timeout_ms=400)  # short timeout so stop is responsive
                except wmi.x_wmi_timed_out:
                    continue
                except Exception:
                    break
                try:
                    ev = ProcessEvent(
                        timestamp=datetime.now(timezone.utc),
                        event_type="create",
                        pid=int(proc.ProcessId),
                        ppid=int(proc.ParentProcessId) if proc.ParentProcessId else None,
                        name=(os.path.basename(proc.ExecutablePath or "") or proc.Name or "").lower(),
                        exe_path=proc.ExecutablePath,
                        cmdline=proc.CommandLine,
                        user=None,  # Win32_Process doesn't expose username directly
                    )
                    self._on_create(ev)
                except Exception:
                    continue
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ProcMon-wmi")
        self._thread.start()

    def stop(self, join_timeout: float = 2.0):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=join_timeout)


# ---------- Public ProcessMonitor -------------------------------------------

class ProcessMonitor:
    """Front-door: tries WMI if requested, else falls back to psutil."""

    def __init__(self,
                 on_event: Callable[[ProcessEvent], None],
                 backend: str = "auto",
                 poll_interval: float = 0.3,
                 seed_existing: bool = True):
        self.on_event = on_event
        self._backend = None
        self._chose: str = ""

        if backend == "wmi" or backend == "etw":
            try:
                import wmi  # noqa: F401
                self._backend = _WMIBackend(self.on_event)
                self._chose = "wmi"
            except Exception as e:
                print(f"[procmon] WMI backend unavailable ({e}); falling back to psutil")
                self._backend = _PsutilBackend(self.on_event, poll_interval, seed_existing)
                self._chose = "psutil"
        else:
            self._backend = _PsutilBackend(self.on_event, poll_interval, seed_existing)
            self._chose = "psutil"

    @property
    def backend_name(self) -> str:
        return self._chose

    def start(self):
        self._backend.start()

    def stop(self):
        self._backend.stop()
