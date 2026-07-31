"""
Append-only JSONL writer for behavioral alerts.
"""
from __future__ import annotations

import json
import os
import threading

from behavior_rules import RuleMatch
from quarantine import DEFAULT_LOG_DIR


BEHAVIOR_LOG_NAME = "behavior_log.jsonl"
_LOCK = threading.Lock()


def log_behavior(match: RuleMatch, log_dir: str = DEFAULT_LOG_DIR) -> str:
    """Append one JSON-encoded line for `match`. Returns the log path."""
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, BEHAVIOR_LOG_NAME)
    line = json.dumps(match.to_dict(), ensure_ascii=False) + "\n"
    with _LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
    return path
