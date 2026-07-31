"""
Behavioral rule engine.

Stateless per-event rules over a small in-memory process cache, so a
child's rule can look up its parent's recorded name even after the parent
has exited. Each rule produces a RuleMatch with severity.

Rules:
  OFFICE_SPAWN_SHELL    - Office app spawned cmd/powershell/wscript/mshta
  POWERSHELL_ENCODED    - PowerShell launched with -EncodedCommand / -enc
  POWERSHELL_HIDDEN     - PowerShell launched with -WindowStyle Hidden
  STARTUP_FOLDER_WRITE  - cmdline writes to %APPDATA%\Start Menu\...\Startup\
  PROCESS_INJECTION     - not yet implemented; needs ETW kernel hooks
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional, List, Dict, Any

from process_monitor import ProcessEvent


OFFICE_EXES = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msaccess.exe", "mspub.exe", "visio.exe",
}
SHELL_EXES = {
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe",
}

# A relaxed match for -enc / -en / -encoded / -EncodedCommand (and variants).
RE_PS_ENCODED = re.compile(
    r"\s-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b",
    re.IGNORECASE,
)
RE_PS_HIDDEN = re.compile(
    r"-w(?:indowstyle)?\s+hidden\b",
    re.IGNORECASE,
)
RE_STARTUP_PATH = re.compile(
    r"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    re.IGNORECASE,
)


@dataclass
class RuleMatch:
    rule_id: str
    severity: str               # "low" | "medium" | "high"
    description: str
    process: ProcessEvent
    parent: Optional[ProcessEvent] = None
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.process.timestamp.isoformat(),
            "rule_id": self.rule_id,
            "severity": self.severity,
            "description": self.description,
            "pid": self.process.pid,
            "ppid": self.process.ppid,
            "process_name": self.process.name,
            "process_path": self.process.exe_path,
            "cmdline": self.process.cmdline,
            "user": self.process.user,
            "parent_name": self.parent.name if self.parent else None,
            "parent_path": self.parent.exe_path if self.parent else None,
            "parent_pid": self.parent.pid if self.parent else None,
            "context": self.context,
        }


class SequenceDetector:
    """Runs each ProcessEvent through the rules and emits RuleMatches."""

    def __init__(self,
                 on_match: Callable[[RuleMatch], None],
                 cache_ttl: timedelta = timedelta(minutes=10)):
        self._on_match = on_match
        self._cache: dict[int, ProcessEvent] = {}
        self._lock = threading.Lock()
        self._ttl = cache_ttl

    def _gc(self) -> None:
        cutoff = datetime.now(timezone.utc) - self._ttl
        # Caller holds lock.
        stale = [pid for pid, ev in self._cache.items() if ev.timestamp < cutoff]
        for pid in stale:
            self._cache.pop(pid, None)

    def on_event(self, ev: ProcessEvent) -> None:
        with self._lock:
            self._cache[ev.pid] = ev
            self._gc()
            parent = self._cache.get(ev.ppid) if ev.ppid else None

        for m in self._check(ev, parent):
            try:
                self._on_match(m)
            except Exception as exc:
                print(f"[rules] on_match failed: {exc}")

    # ---- rule definitions ----------------------------------------------

    def _check(self, ev: ProcessEvent, parent: Optional[ProcessEvent]) -> List[RuleMatch]:
        out: List[RuleMatch] = []
        name = (ev.name or "").lower()
        cmd = ev.cmdline or ""

        # Rule 1: office app spawned a shell.
        if name in SHELL_EXES and parent is not None and parent.name in OFFICE_EXES:
            out.append(RuleMatch(
                rule_id="OFFICE_SPAWN_SHELL",
                severity="high",
                description=f"{parent.name} spawned {name} (classic macro->shell chain)",
                process=ev, parent=parent,
            ))

        # Rule 2: PowerShell with -EncodedCommand.
        if name in ("powershell.exe", "pwsh.exe") and RE_PS_ENCODED.search(cmd):
            out.append(RuleMatch(
                rule_id="POWERSHELL_ENCODED",
                severity="high",
                description="PowerShell launched with -EncodedCommand",
                process=ev, parent=parent,
            ))

        # Rule 3: PowerShell with hidden window.
        if name in ("powershell.exe", "pwsh.exe") and RE_PS_HIDDEN.search(cmd):
            out.append(RuleMatch(
                rule_id="POWERSHELL_HIDDEN",
                severity="medium",
                description="PowerShell launched with -WindowStyle Hidden",
                process=ev, parent=parent,
            ))

        # Rule 4: write to user Startup folder (detected via cmdline content).
        if RE_STARTUP_PATH.search(cmd):
            out.append(RuleMatch(
                rule_id="STARTUP_FOLDER_WRITE",
                severity="medium",
                description="process command line targets user Startup folder",
                process=ev, parent=parent,
                context={"matched_substring": "Start Menu\\Programs\\Startup"},
            ))

        return out
