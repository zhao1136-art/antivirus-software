"""
PDF rule-based scanner.

Two passes:
  - pdfminer.six structural parse for page + object counts.
  - Raw byte regex for the trigger markers (/JavaScript, /JS, /Launch,
    /OpenAction, /AA, /EmbeddedFile, /SubmitForm, /FlateDecode +
    /ASCIIHexDecode chains).

Trigger markers live in the unencoded object dictionaries, so we can scan
raw bytes instead of inflating every stream.
"""
from __future__ import annotations

import argparse
import io
import re
from dataclasses import dataclass, field
from typing import Any

from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfpage import PDFPage


# Marker → (weight, reason). Tuned so a PDF with /JS + /OpenAction crosses
# the threshold but a PDF with a single benign /URI does not.
_MARKERS = [
    (re.compile(rb"/JavaScript\b"),        25, "/JavaScript action"),
    (re.compile(rb"/JS\b"),                25, "/JS key (embedded JavaScript)"),
    (re.compile(rb"/Launch\b"),            30, "/Launch action (can run external programs)"),
    (re.compile(rb"/OpenAction\b"),        20, "/OpenAction (auto-trigger on open)"),
    (re.compile(rb"/AA\b"),                15, "/AA (additional actions, can auto-trigger)"),
    (re.compile(rb"/SubmitForm\b"),        15, "/SubmitForm action (exfil potential)"),
    (re.compile(rb"/EmbeddedFile\b"),      15, "/EmbeddedFile (file payload embedded)"),
    (re.compile(rb"/RichMedia\b"),         10, "/RichMedia (Flash legacy attack surface)"),
    (re.compile(rb"/XFA\b"),               10, "/XFA forms (historic CVE surface)"),
    (re.compile(rb"/GoToR\b"),              5, "/GoToR (remote document jump)"),
    (re.compile(rb"/URI\s*\(\s*https?://"),   2, "/URI external link"),
]

_FILTER_CHAIN = re.compile(
    rb"/Filter\s*\[\s*(/[A-Za-z]+\s*){2,}\]"
)
_DOUBLE_FILTER_FLATE_ASCII = re.compile(
    rb"/Filter\s*\[\s*/FlateDecode\s+/ASCIIHexDecode\s*\]|"
    rb"/Filter\s*\[\s*/ASCIIHexDecode\s+/FlateDecode\s*\]"
)

_OBJ_DEF = re.compile(rb"\b\d+\s+\d+\s+obj\b")

MALICIOUS_THRESHOLD = 35.0
MAX_SCORE_FOR_CONFIDENCE = 100.0


@dataclass
class PDFResult:
    path: str
    score: float = 0.0
    verdict: str = "CLEAN"
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    page_count: int = 0
    object_count: int = 0
    error: str | None = None


def _structural_stats(data: bytes) -> tuple[int, int]:
    """Return (page_count, object_count). Falls back to regex if pdfminer fails."""
    page_count = 0
    object_count = len(_OBJ_DEF.findall(data))
    try:
        with io.BytesIO(data) as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            page_count = sum(1 for _ in PDFPage.create_pages(doc))
    except Exception:
        pass
    return page_count, object_count


def scan_file(path: str) -> PDFResult:
    res = PDFResult(path=path)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        res.error = f"read failed: {e}"
        return res

    if not data.startswith(b"%PDF"):
        res.error = "not a PDF (no %PDF header)"
        return res

    res.page_count, res.object_count = _structural_stats(data)

    for rx, weight, reason in _MARKERS:
        hits = len(rx.findall(data))
        if hits:
            # Multiple hits add diminishing returns but still scale.
            add = weight * (1.0 + 0.5 * (hits - 1))
            res.score += add
            res.reasons.append(f"{reason} (x{hits}, +{add:.0f})")

    # Chained filter is a strong signal for obfuscated payloads.
    if _DOUBLE_FILTER_FLATE_ASCII.search(data):
        res.score += 20
        res.reasons.append("FlateDecode + ASCIIHexDecode chained (+20)")
    chained = len(_FILTER_CHAIN.findall(data))
    if chained:
        res.score += min(15, chained * 5)
        res.reasons.append(f"{chained} chained-filter stream(s) (+{min(15, chained*5)})")

    if res.page_count > 0:
        ratio = res.object_count / max(1, res.page_count)
        if ratio >= 50:
            res.score += 10
            res.reasons.append(f"high object/page ratio: {res.object_count}/{res.page_count} (+10)")
    elif res.object_count > 0 and res.page_count == 0:
        # PDF with objects but pdfminer reports 0 pages — often suspicious.
        res.score += 5
        res.reasons.append("pdfminer found 0 pages despite present objects (+5)")

    res.verdict = "MALICIOUS" if res.score >= MALICIOUS_THRESHOLD else "CLEAN"
    if res.verdict == "MALICIOUS":
        res.confidence = min(100.0, 50.0 + (res.score - MALICIOUS_THRESHOLD) /
                             max(1.0, MAX_SCORE_FOR_CONFIDENCE - MALICIOUS_THRESHOLD) * 50.0)
    else:
        res.confidence = max(50.0, 100.0 - (res.score / MALICIOUS_THRESHOLD) * 50.0)

    if not res.reasons:
        res.reasons.append("no suspicious PDF markers found")

    return res


def render(res: PDFResult) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append(f"  verdict     : {res.verdict}")
    lines.append(f"  confidence  : {res.confidence:.2f}%   (rule-based score = {res.score:.1f})")
    lines.append(f"  threshold   : {MALICIOUS_THRESHOLD:.0f}")
    lines.append(f"  pages       : {res.page_count}, objects: {res.object_count}")
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
