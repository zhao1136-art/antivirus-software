"""
Office / VBA-macro scanner.

oletools.olevba handles .doc/.docm/.docx/.xls/.xlsm/.xlsx/.ppt/.pptm and
raw VBA modules (.bas/.cls/.frm). Detection layers per-bucket weights on
top of olevba.analyze_macros(), which already classifies tokens as
AutoExec / Suspicious / IOC / Hex String / Base64 String / Dridex String /
VBA string.

The 'confidence' returned is a normalized score, not a probability.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Any

from oletools.olevba import VBA_Parser


# Bucket → per-hit weight. Tuned to push obvious "downloader+autoexec" docs
# above the threshold while keeping bare auto-open below it.
_BUCKET_WEIGHTS = {
    "AutoExec": 15.0,
    "Suspicious": 10.0,
    "IOC": 5.0,
    "Hex String": 2.0,
    "Base64 String": 4.0,
    "Dridex String": 8.0,
    "VBA string": 1.5,
}

# Per-keyword bumps for the highest-signal items inside the Suspicious bucket.
_KEYWORD_BUMP = {
    "Shell": 5.0,
    "WScript.Shell": 8.0,
    "Run": 4.0,
    "ShellExecute": 8.0,
    "powershell": 12.0,
    "cmd.exe": 6.0,
    "URLDownloadToFile": 12.0,
    "Microsoft.XMLHTTP": 10.0,
    "MSXML2.XMLHTTP": 10.0,
    "MSXML2.ServerXMLHTTP": 10.0,
    "Adodb.Stream": 10.0,
    "CreateObject": 3.0,
    "Environ": 2.0,
    "Open": 2.0,
    "Write": 1.0,
    "Chr": 1.0,
    "Xor": 2.0,
    "Base64": 4.0,
    "savetofile": 6.0,
}

MALICIOUS_THRESHOLD = 50.0
MAX_SCORE_FOR_CONFIDENCE = 150.0  # ≥150 → 100% confident malicious


@dataclass
class OfficeResult:
    path: str
    has_macros: bool
    score: float
    verdict: str
    confidence: float
    reasons: list[str] = field(default_factory=list)
    autoexec: list[str] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    n_modules: int = 0
    error: str | None = None


def _categorize(results) -> dict[str, list[tuple[str, str]]]:
    """olevba.analyze_macros() returns list of (type, keyword, description)."""
    buckets: dict[str, list[tuple[str, str]]] = {}
    for entry in results:
        kind, keyword, desc = entry
        buckets.setdefault(kind, []).append((keyword, desc))
    return buckets


def scan_file(path: str) -> OfficeResult:
    res = OfficeResult(path=path, has_macros=False, score=0.0,
                       verdict="CLEAN", confidence=0.0)
    try:
        vp = VBA_Parser(path)
    except Exception as e:
        res.error = f"VBA_Parser failed: {e}"
        return res

    try:
        if not vp.detect_vba_macros():
            res.reasons.append("no VBA macros present")
            res.confidence = 99.0
            return res
        res.has_macros = True

        modules = list(vp.extract_macros())  # iterator of (file, stream, vba_filename, vba_code)
        res.n_modules = len(modules)

        analysis = vp.analyze_macros(show_decoded_strings=True)
        buckets = _categorize(analysis)

        for kind, hits in buckets.items():
            base = _BUCKET_WEIGHTS.get(kind, 1.0)
            for keyword, _desc in hits:
                bump = _KEYWORD_BUMP.get(keyword, 0.0)
                res.score += base + bump

        for kw, desc in buckets.get("AutoExec", []):
            res.autoexec.append(kw)
            res.reasons.append(f"auto-exec trigger: {kw} ({desc})")
        for kw, desc in buckets.get("Suspicious", [])[:10]:
            res.suspicious.append(kw)
            res.reasons.append(f"suspicious call: {kw} ({desc})")
        for kw, desc in buckets.get("IOC", [])[:5]:
            res.iocs.append(kw)
            res.reasons.append(f"IOC: {kw} ({desc})")
        if buckets.get("Base64 String"):
            res.reasons.append(f"{len(buckets['Base64 String'])} base64 string(s) in macro source")
        if buckets.get("Hex String"):
            res.reasons.append(f"{len(buckets['Hex String'])} hex-encoded string(s)")
        if buckets.get("Dridex String"):
            res.reasons.append(f"{len(buckets['Dridex String'])} Dridex-style obfuscated string(s)")

        # No macros but file parses → still possible but rare; default safe.
        if not buckets:
            res.reasons.append("macros present but no suspicious indicators detected")

    finally:
        try:
            vp.close()
        except Exception:
            pass

    res.verdict = "MALICIOUS" if res.score >= MALICIOUS_THRESHOLD else "CLEAN"
    if res.verdict == "MALICIOUS":
        res.confidence = min(100.0, 50.0 + (res.score - MALICIOUS_THRESHOLD) /
                             max(1.0, MAX_SCORE_FOR_CONFIDENCE - MALICIOUS_THRESHOLD) * 50.0)
    else:
        # Clean confidence falls as score approaches threshold.
        res.confidence = max(50.0, 100.0 - (res.score / MALICIOUS_THRESHOLD) * 50.0)
    return res


def render(res: OfficeResult) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append(f"  verdict     : {res.verdict}")
    lines.append(f"  confidence  : {res.confidence:.2f}%   (rule-based score = {res.score:.1f})")
    lines.append(f"  threshold   : {MALICIOUS_THRESHOLD:.0f}")
    lines.append(f"  has macros  : {res.has_macros}  (modules: {res.n_modules})")
    if res.error:
        lines.append(f"  ERROR       : {res.error}")
    lines.append("-" * 60)
    lines.append("  top reasons:")
    for r in res.reasons[:8]:
        lines.append(f"    - {r}")
    lines.append("=" * 60)
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    args = ap.parse_args()
    print(render(scan_file(args.path)))
