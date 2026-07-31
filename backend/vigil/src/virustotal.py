"""
VirusTotal API v3 hash lookup.

Opt-in lookup for files Vigil has already flagged MALICIOUS. The integration
is community-result only — we never upload bytes, only the SHA256.

API key comes from the environment variable VIGIL_VT_API_KEY. If unset, the
lookup is silently skipped. The key is never logged or stored.

Rate limits on the free tier are 4 req/min; on a 429 we log a single line
and return None — no retries, no queueing.
"""
from __future__ import annotations

import hashlib
import os
import sys
from typing import Any

import requests


VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
VT_GUI_URL = "https://www.virustotal.com/gui/file/{hash}"
ENV_VAR = "VIGIL_VT_API_KEY"
TIMEOUT_SECONDS = 15


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def lookup_hash(sha256: str, api_key: str) -> dict[str, Any] | None:
    """Query VT for a SHA256. Returns a parsed dict, or None on failure.

    Shape on success (found):
        {"found": True, "detected_by": int, "total_engines": int,
         "community_score": int | None, "permalink": str, "sha256": str}

    Shape when the file isn't in the VT corpus:
        {"found": False, "sha256": str, "permalink": str}

    None means a network/auth/quota failure — the caller should treat this
    as "no signal" rather than "clean".
    """
    url = VT_API_URL.format(hash=sha256)
    headers = {"x-apikey": api_key, "accept": "application/json"}
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT_SECONDS)
    except requests.RequestException as e:
        print(f"[virustotal] request failed: {type(e).__name__}", file=sys.stderr)
        return None

    if resp.status_code == 404:
        return {
            "found": False,
            "sha256": sha256,
            "permalink": VT_GUI_URL.format(hash=sha256),
        }
    if resp.status_code == 429:
        print("[virustotal] rate limited (HTTP 429) — skipping lookup", file=sys.stderr)
        return None
    if resp.status_code == 401:
        print("[virustotal] unauthorized (HTTP 401) — check VIGIL_VT_API_KEY", file=sys.stderr)
        return None
    if resp.status_code != 200:
        print(f"[virustotal] unexpected HTTP {resp.status_code}", file=sys.stderr)
        return None

    try:
        payload = resp.json()
    except ValueError:
        print("[virustotal] invalid JSON in response", file=sys.stderr)
        return None

    attrs = (payload.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    detected = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values() if isinstance(v, int))
    reputation = attrs.get("reputation")
    score = int(reputation) if isinstance(reputation, int) else None

    return {
        "found": True,
        "detected_by": detected,
        "total_engines": total,
        "community_score": score,
        "permalink": VT_GUI_URL.format(hash=sha256),
        "sha256": sha256,
    }


def maybe_lookup_for_path(path: str) -> dict[str, Any] | None:
    """Hash `path` and look it up if VIGIL_VT_API_KEY is set.

    Returns None when the env var is missing, the file can't be hashed, or
    the API call failed. The caller treats None as "no VT signal" and shows
    nothing.
    """
    key = os.environ.get(ENV_VAR)
    if not key:
        return None
    try:
        digest = sha256_file(path)
    except OSError:
        return None
    return lookup_hash(digest, key)


def render_cli_block(vt: dict[str, Any]) -> str:
    """Format a vt_result dict as the CLI block printed after a MALICIOUS verdict."""
    lines = ["-" * 60]
    if not vt.get("found"):
        lines.append(f"  VirusTotal:  hash not in database yet")
        lines.append(f"  Report: {vt['permalink']}")
    else:
        lines.append(f"  VirusTotal:  {vt['detected_by']} / {vt['total_engines']} engines flagged this file")
        if vt.get("community_score") is not None:
            lines.append(f"  Community score: {vt['community_score']}")
        lines.append(f"  Report: {vt['permalink']}")
    lines.append("-" * 60)
    return "\n".join(lines)
