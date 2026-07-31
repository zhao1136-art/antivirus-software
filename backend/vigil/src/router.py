"""
File-type router. Maps a path to one of: pe | ps1 | office | pdf | unknown.

Detection: peek at the first 8 bytes (magic) and fall back to extension.
Magic wins when it disagrees with extension (e.g. a PowerShell script saved
as .txt is still PowerShell-shaped — but our heuristics only catch clear
cases; extension is the practical signal for text formats).
"""
from __future__ import annotations

import os


FILE_PE = "pe"
FILE_PS1 = "ps1"
FILE_OFFICE = "office"
FILE_PDF = "pdf"
FILE_UNKNOWN = "unknown"


_OFFICE_OOXML_EXTS = {".docm", ".docx", ".xlsm", ".xlsx", ".pptm", ".pptx"}
_OFFICE_OLE_EXTS = {".doc", ".xls", ".ppt"}
_VBA_TEXT_EXTS = {".bas", ".cls", ".frm", ".vba"}  # raw VBA modules, scanned same as office


def detect_file_type(path: str) -> str:
    """Return one of FILE_PE / FILE_PS1 / FILE_OFFICE / FILE_PDF / FILE_UNKNOWN."""
    if not os.path.isfile(path):
        return FILE_UNKNOWN

    with open(path, "rb") as f:
        head = f.read(8)

    # --- Magic-byte detection ---
    # PE: MZ
    if head.startswith(b"MZ"):
        return FILE_PE
    # PDF: %PDF
    if head.startswith(b"%PDF"):
        return FILE_PDF
    # OOXML (zip): PK\x03\x04 — could be .docm/.xlsm, but also any .zip.
    # We disambiguate via extension below.
    is_zip = head.startswith(b"PK\x03\x04")
    # OLE compound document: D0 CF 11 E0 A1 B1 1A E1 — .doc/.xls/.ppt
    is_ole = head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")

    ext = os.path.splitext(path)[1].lower()

    if is_ole and ext in _OFFICE_OLE_EXTS:
        return FILE_OFFICE
    if is_zip and ext in _OFFICE_OOXML_EXTS:
        return FILE_OFFICE
    # Raw VBA module → also goes through the office pipeline (olevba accepts it).
    if ext in _VBA_TEXT_EXTS:
        return FILE_OFFICE

    # PowerShell is text — magic doesn't help. Use extension.
    if ext == ".ps1" or ext == ".psm1":
        return FILE_PS1

    # Fallback: extension-only PE / PDF / Office (e.g. files without magic).
    if ext == ".exe" or ext == ".dll" or ext == ".sys":
        return FILE_PE
    if ext == ".pdf":
        return FILE_PDF
    if ext in _OFFICE_OLE_EXTS or ext in _OFFICE_OOXML_EXTS:
        return FILE_OFFICE

    return FILE_UNKNOWN
