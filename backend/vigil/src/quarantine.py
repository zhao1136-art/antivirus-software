"""
Quarantine + scan log.

quarantine_file(): move a malicious file into quarantine/, append .quar to
the basename, and write a JSON sidecar with verdict metadata.

log_scan(): append every scan result (clean or malicious) to
logs/scan_log.jsonl, one JSON object per line.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
from datetime import datetime, timezone
from typing import Any

from scan_api import ScanResult


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_QUARANTINE_DIR = os.path.join(HERE, "quarantine")
DEFAULT_LOG_DIR = os.path.join(HERE, "logs")
SCAN_LOG_NAME = "scan_log.jsonl"


# Single global lock for log append — multiple watcher worker threads could
# race on the file otherwise.
_LOG_LOCK = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _unique_path(path: str) -> str:
    """Append (1), (2), ... to the *stem* if path already exists."""
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    n = 1
    while True:
        cand = f"{base} ({n}){ext}"
        if not os.path.exists(cand):
            return cand
        n += 1


def quarantine_file(result: ScanResult,
                    quarantine_dir: str = DEFAULT_QUARANTINE_DIR,
                    retries: int = 5, retry_delay: float = 0.2) -> dict[str, Any]:
    """Move `result.path` to quarantine and write a sidecar JSON.

    Retries the move briefly because Windows may still have the file open
    by another process when the watcher event fires.

    Returns the sidecar metadata dict.
    """
    os.makedirs(quarantine_dir, exist_ok=True)
    src = result.path
    base = os.path.basename(src)
    dest = _unique_path(os.path.join(quarantine_dir, base + ".quar"))

    last_exc: Exception | None = None
    for _ in range(retries):
        try:
            shutil.move(src, dest)
            last_exc = None
            break
        except (PermissionError, OSError) as e:
            last_exc = e
            time.sleep(retry_delay)
    if last_exc is not None:
        raise last_exc

    sidecar_path = dest + ".json"
    metadata: dict[str, Any] = {
        "timestamp": _now_iso(),
        "original_path": os.path.abspath(src),
        "quarantine_path": os.path.abspath(dest),
        "file_type": result.file_type,
        "verdict": result.verdict,
        "confidence": result.confidence,
        "raw_prob": result.raw_prob,
        "score": result.score,
        "reasons": list(result.reasons),
        "top_features": [
            {"name": t.name, "value": t.value, "contrib": t.contrib}
            for t in result.top_features
        ],
    }
    if result.vt_result is not None:
        metadata["vt_result"] = result.vt_result
    with open(sidecar_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    return metadata


def log_scan(result: ScanResult, log_dir: str = DEFAULT_LOG_DIR,
             quarantine_path: str | None = None) -> None:
    """Append a single JSON line summarizing the scan to scan_log.jsonl."""
    os.makedirs(log_dir, exist_ok=True)
    entry: dict[str, Any] = {
        "timestamp": _now_iso(),
        "path": os.path.abspath(result.path) if os.path.exists(result.path) else result.path,
        "file_type": result.file_type,
        "verdict": result.verdict,
        "confidence": result.confidence,
        "raw_prob": result.raw_prob,
        "score": result.score,
        "reasons": list(result.reasons),
    }
    if quarantine_path is not None:
        entry["quarantine_path"] = os.path.abspath(quarantine_path)
    if result.error:
        entry["error"] = result.error
    if result.vt_result is not None:
        entry["vt_result"] = result.vt_result

    log_path = os.path.join(log_dir, SCAN_LOG_NAME)
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    with _LOG_LOCK:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line)
