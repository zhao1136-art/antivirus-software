"""
PowerShell (.ps1) feature extractor.

Pulls numeric features for a classifier + a human-readable rationale.
No PowerShell tokenizer dependency — regex is sufficient for the patterns
we care about (we are looking for shape, not semantics).

Features split into three buckets:
  1. shape/entropy  — script length, line count, byte entropy, etc.
  2. obfuscation    — base64 runs, char concatenation, hex escapes, backticks
  3. dangerous APIs — IEX, DownloadString, AMSI bypass, etc.

Returned as a dict + a fixed-order numeric vector (see FEATURE_NAMES).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any


# --- Pattern definitions -----------------------------------------------------

# Obfuscation indicators
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/=]{40,}")
_HEX_LITERAL = re.compile(r"0x[0-9A-Fa-f]{2,}")
_HEX_ESCAPE = re.compile(r"\\x[0-9A-Fa-f]{2}")
_CHAR_CALL = re.compile(r"\[char\]\s*0?x?\d+|\[Convert\]::ToChar", re.IGNORECASE)
_BACKTICK = re.compile(r"`")
_REVERSED_STR = re.compile(r"\[array\]::Reverse|-join.*?\[char\]", re.IGNORECASE)
_FORMAT_OBFUSC = re.compile(r'"\s*\{[0-9,\s]+\}\s*"\s*-f', re.IGNORECASE)  # "{0}{1}" -f
_STRING_CONCAT = re.compile(r"'[^']*'\s*\+\s*'[^']*'")

# Encoded command / execution policy bypass
_ENCODED_CMD = re.compile(r"-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\b", re.IGNORECASE)
_BYPASS_POLICY = re.compile(r"-(?:ep|exec(?:utionpolicy)?)\s+bypass", re.IGNORECASE)
_HIDDEN_WINDOW = re.compile(r"-windowstyle\s+hidden", re.IGNORECASE)
_NOPROFILE = re.compile(r"-(?:nop|noprofile)\b", re.IGNORECASE)
_NONINTERACTIVE = re.compile(r"-(?:noni|noninteractive)\b", re.IGNORECASE)

# Dangerous primitives
_IEX = re.compile(r"\b(?:iex|Invoke-Expression)\b", re.IGNORECASE)
_DOWNLOAD_STRING = re.compile(r"\.DownloadString\(", re.IGNORECASE)
_DOWNLOAD_FILE = re.compile(r"\.DownloadFile\(", re.IGNORECASE)
_WEBCLIENT = re.compile(r"New-Object\s+(?:Net\.|System\.Net\.)?WebClient", re.IGNORECASE)
_INVOKE_WEBREQ = re.compile(r"\bInvoke-(?:WebRequest|RestMethod)\b", re.IGNORECASE)
_START_PROCESS = re.compile(r"\bStart-Process\b", re.IGNORECASE)
_ADD_TYPE = re.compile(r"\bAdd-Type\b", re.IGNORECASE)
_REFLECTION_LOAD = re.compile(r"\[Reflection\.Assembly\]::Load|\[System\.Reflection\.Assembly\]::Load", re.IGNORECASE)
_AMSI_BYPASS = re.compile(
    r"AmsiUtils|amsiInitFailed|System\.Management\.Automation\.AmsiUtils",
    re.IGNORECASE,
)
_MIMIKATZ = re.compile(r"mimikatz|sekurlsa|lsadump|invoke-mimi", re.IGNORECASE)
_REG_RUN = re.compile(
    r"HKCU:?\\?Software\\?Microsoft\\?Windows\\?CurrentVersion\\?Run|"
    r"HKLM:?\\?Software\\?Microsoft\\?Windows\\?CurrentVersion\\?Run",
    re.IGNORECASE,
)
_SCHED_TASK = re.compile(r"\b(?:Register-ScheduledTask|schtasks)\b", re.IGNORECASE)
_WMI_PERSIST = re.compile(
    r"Register-WmiEvent|__EventFilter|CommandLineEventConsumer",
    re.IGNORECASE,
)
_SET_EXECPOLICY = re.compile(r"Set-ExecutionPolicy", re.IGNORECASE)
_FROM_BASE64 = re.compile(r"FromBase64String", re.IGNORECASE)
_DEFLATESTREAM = re.compile(r"DeflateStream|GzipStream", re.IGNORECASE)
_DOWNLOAD_TO_FILE = re.compile(r"Invoke-WebRequest[^;\n]*?-OutFile", re.IGNORECASE)
_SHELLCODE_KEYWORDS = re.compile(r"VirtualAlloc|CreateRemoteThread|WriteProcessMemory", re.IGNORECASE)


# Numeric features, fixed order — also the column order of the training matrix.
FEATURE_NAMES = [
    "length",
    "line_count",
    "entropy",
    "comment_ratio",
    "longest_b64_run",
    "base64_count",
    "hex_literal_count",
    "hex_escape_count",
    "char_call_count",
    "backtick_count",
    "reversed_str_count",
    "format_obfusc_count",
    "string_concat_count",
    "encoded_cmd_count",
    "bypass_policy_count",
    "hidden_window_count",
    "noprofile_count",
    "noninteractive_count",
    "iex_count",
    "download_string_count",
    "download_file_count",
    "webclient_count",
    "invoke_webreq_count",
    "start_process_count",
    "add_type_count",
    "reflection_load_count",
    "amsi_bypass_count",
    "mimikatz_count",
    "reg_run_count",
    "sched_task_count",
    "wmi_persist_count",
    "set_execpolicy_count",
    "from_base64_count",
    "deflatestream_count",
    "download_to_file_count",
    "shellcode_keyword_count",
    "var_count",
    "function_count",
    "uppercase_ratio",
    "non_ascii_ratio",
]

DIM = len(FEATURE_NAMES)


@dataclass
class PS1Features:
    path: str
    feature_dict: dict[str, float]
    reasons: list[str] = field(default_factory=list)

    def vector(self) -> list[float]:
        return [float(self.feature_dict[k]) for k in FEATURE_NAMES]


def _byte_entropy(s: bytes) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_text(text: str, path: str = "<memory>") -> PS1Features:
    """Run all regex feature extractors and assemble the vector + reasons."""
    raw = text.encode("utf-8", errors="ignore")
    length = len(text)
    lines = text.splitlines()
    line_count = max(1, len(lines))

    # Shape / entropy
    entropy = _byte_entropy(raw)
    comment_lines = sum(1 for ln in lines if ln.strip().startswith("#"))
    comment_ratio = comment_lines / line_count

    # Obfuscation
    b64_matches = _BASE64_RUN.findall(text)
    longest_b64 = max((len(m) for m in b64_matches), default=0)

    def n(rx, t=text):
        return len(rx.findall(t))

    feats = {
        "length": length,
        "line_count": line_count,
        "entropy": entropy,
        "comment_ratio": comment_ratio,
        "longest_b64_run": longest_b64,
        "base64_count": len(b64_matches),
        "hex_literal_count": n(_HEX_LITERAL),
        "hex_escape_count": n(_HEX_ESCAPE),
        "char_call_count": n(_CHAR_CALL),
        "backtick_count": n(_BACKTICK),
        "reversed_str_count": n(_REVERSED_STR),
        "format_obfusc_count": n(_FORMAT_OBFUSC),
        "string_concat_count": n(_STRING_CONCAT),
        "encoded_cmd_count": n(_ENCODED_CMD),
        "bypass_policy_count": n(_BYPASS_POLICY),
        "hidden_window_count": n(_HIDDEN_WINDOW),
        "noprofile_count": n(_NOPROFILE),
        "noninteractive_count": n(_NONINTERACTIVE),
        "iex_count": n(_IEX),
        "download_string_count": n(_DOWNLOAD_STRING),
        "download_file_count": n(_DOWNLOAD_FILE),
        "webclient_count": n(_WEBCLIENT),
        "invoke_webreq_count": n(_INVOKE_WEBREQ),
        "start_process_count": n(_START_PROCESS),
        "add_type_count": n(_ADD_TYPE),
        "reflection_load_count": n(_REFLECTION_LOAD),
        "amsi_bypass_count": n(_AMSI_BYPASS),
        "mimikatz_count": n(_MIMIKATZ),
        "reg_run_count": n(_REG_RUN),
        "sched_task_count": n(_SCHED_TASK),
        "wmi_persist_count": n(_WMI_PERSIST),
        "set_execpolicy_count": n(_SET_EXECPOLICY),
        "from_base64_count": n(_FROM_BASE64),
        "deflatestream_count": n(_DEFLATESTREAM),
        "download_to_file_count": n(_DOWNLOAD_TO_FILE),
        "shellcode_keyword_count": n(_SHELLCODE_KEYWORDS),
        "var_count": len(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", text)),
        "function_count": len(re.findall(r"^\s*function\s+\w", text, re.MULTILINE | re.IGNORECASE)),
        "uppercase_ratio": (sum(1 for c in text if c.isupper()) / length) if length else 0.0,
        "non_ascii_ratio": (sum(1 for c in text if ord(c) > 127) / length) if length else 0.0,
    }

    # Build human-readable reasons (highest-value signals first).
    reasons = []
    if feats["iex_count"] and (feats["download_string_count"] or feats["webclient_count"]):
        reasons.append("classic downloader+IEX pattern: WebClient/DownloadString fed to Invoke-Expression")
    if feats["encoded_cmd_count"]:
        reasons.append(f"uses -EncodedCommand parameter ({feats['encoded_cmd_count']}x)")
    if feats["from_base64_count"]:
        reasons.append(f"FromBase64String decode call(s): {feats['from_base64_count']}")
    if feats["longest_b64_run"] >= 200:
        reasons.append(f"long base64 blob ({feats['longest_b64_run']} chars)")
    if feats["amsi_bypass_count"]:
        reasons.append("AMSI bypass identifiers present")
    if feats["mimikatz_count"]:
        reasons.append("Mimikatz/sekurlsa references present")
    if feats["bypass_policy_count"]:
        reasons.append("execution-policy bypass requested")
    if feats["hidden_window_count"]:
        reasons.append("hidden window flag (-WindowStyle Hidden)")
    if feats["reflection_load_count"]:
        reasons.append("reflective assembly load")
    if feats["shellcode_keyword_count"]:
        reasons.append("Win32 process-injection API names present")
    if feats["reg_run_count"] or feats["sched_task_count"] or feats["wmi_persist_count"]:
        reasons.append("persistence primitive (Run key / scheduled task / WMI consumer)")
    if feats["char_call_count"] + feats["format_obfusc_count"] + feats["string_concat_count"] >= 5:
        reasons.append("string obfuscation: chr-build / format-string / concat")

    return PS1Features(path=path, feature_dict=feats, reasons=reasons)


def extract_path(path: str) -> PS1Features:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    return extract_text(text, path=path)


if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    args = ap.parse_args()
    r = extract_path(args.path)
    print(json.dumps(r.feature_dict, indent=2))
    print("\nreasons:")
    for x in r.reasons:
        print(" -", x)
