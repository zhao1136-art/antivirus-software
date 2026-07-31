"""
User-feedback storage + bookkeeping.

Submitting feedback:
    scan.py feedback <path> <clean|malicious>
        - Re-runs the relevant scanner on `path` to capture the *current*
          model verdict, confidence, and feature vector.
        - Appends one JSON line to data/feedback/feedback.jsonl with the
          full record including the user-supplied correct label.
        - Prints a warning if 50+ feedback entries have accumulated for
          this file type since the last retrain.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scan_api import Scanner, ScanResult


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEEDBACK_DIR = os.path.join(HERE, "data", "feedback")
FEEDBACK_PATH = os.path.join(FEEDBACK_DIR, "feedback.jsonl")
CHANGELOG_PATH = os.path.join(HERE, "models", "changelog.json")

AUTO_RETRAIN_THRESHOLD = 50

_LOCK = threading.Lock()


# ---------- feature-vector extraction --------------------------------------

def _extract_feature_vector(path: str, file_type: str) -> Optional[list[float]]:
    """Return the same numeric vector the model would have predicted on,
    or None for rule-based pipelines (office/pdf)."""
    if file_type == "ps1":
        from ps1_extractor import extract_path as ps1_extract
        return [float(x) for x in ps1_extract(path).vector()]
    if file_type == "pe":
        from features_ember import PEFeatureExtractor
        with open(path, "rb") as f:
            bytez = f.read()
        return [float(x) for x in PEFeatureExtractor().feature_vector(bytez)]
    return None  # rule-based — no vector to store


# ---------- public API ------------------------------------------------------

def submit_feedback(path: str, correct_label: str,
                    scanner: Optional[Scanner] = None) -> int:
    """Run a scan, store the result + correct label as a feedback record.
    Returns 0 on success, non-zero on error."""
    if correct_label not in ("clean", "malicious"):
        print(f"error: correct_label must be 'clean' or 'malicious' (got {correct_label!r})",
              file=sys.stderr)
        return 2
    if not os.path.isfile(path):
        print(f"error: {path} not found", file=sys.stderr)
        return 2

    s = scanner if scanner is not None else Scanner()
    result = s.scan(path)
    if result.verdict == "ERROR":
        print(f"error: scan failed: {result.error}", file=sys.stderr)
        return 2

    vector = _extract_feature_vector(path, result.file_type)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": os.path.abspath(path),
        "file_type": result.file_type,
        "model_verdict": result.verdict,
        "correct_label": correct_label,
        "label_int": 1 if correct_label == "malicious" else 0,
        "confidence": result.confidence,
        "raw_prob": result.raw_prob,
        "score": result.score,
        "feature_vector": vector,
    }

    os.makedirs(FEEDBACK_DIR, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    with _LOCK:
        with open(FEEDBACK_PATH, "a", encoding="utf-8") as f:
            f.write(line)

    disagrees = result.verdict.lower() != ("malicious" if correct_label == "malicious" else "clean")
    tag = "CORRECTION" if disagrees else "CONFIRMATION"
    print(f"[feedback] {tag}  type={result.file_type}  "
          f"model={result.verdict}  user={correct_label}  "
          f"conf={result.confidence*100:.2f}%  path={path}")
    print(f"[feedback] appended -> {FEEDBACK_PATH}")

    maybe_warn_about_feedback(file_type=result.file_type)
    return 0


def _load_changelog() -> dict:
    if not os.path.isfile(CHANGELOG_PATH):
        return {}
    try:
        with open(CHANGELOG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _last_retrain_timestamp(file_type: str) -> Optional[str]:
    cl = _load_changelog()
    versions = cl.get(f"{file_type}_model", [])
    return versions[-1]["timestamp"] if versions else None


def feedback_count_since_last_retrain(file_type: str) -> int:
    """Count feedback entries for `file_type` newer than the last logged retrain."""
    if not os.path.isfile(FEEDBACK_PATH):
        return 0
    last_ts = _last_retrain_timestamp(file_type)
    count = 0
    try:
        with open(FEEDBACK_PATH, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("file_type") != file_type:
                    continue
                if last_ts is None or e.get("timestamp", "") > last_ts:
                    count += 1
    except OSError:
        return 0
    return count


def maybe_warn_about_feedback(file_type: Optional[str] = None,
                              threshold: int = AUTO_RETRAIN_THRESHOLD) -> None:
    """Print a one-line warning per file type that's over the retrain threshold."""
    types = [file_type] if file_type else ["pe", "ps1"]
    for t in types:
        n = feedback_count_since_last_retrain(t)
        if n >= threshold:
            print(f"[retrain] {n} new feedback samples available for {t} - "
                  f"run python -m src.retrain --type {t} to update the model")
