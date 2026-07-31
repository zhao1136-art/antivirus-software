"""
Human-readable PE feature extractor.

Sections (count, names, sizes, per-section entropy), imports (DLL +
function names), entry point, image base, file size, overall byte
entropy, suspicious-import flags. Returned as a plain dict.

Separate from the EMBER 2381-dim vector in features_ember.py: the EMBER
vector drives prediction, this extractor drives the explanation shown
to the user.
"""
from __future__ import annotations

import math
import os
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Any

import pefile


SUSPICIOUS_APIS = {
    # Process injection / shellcode
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "CreateRemoteThreadEx", "NtCreateThreadEx", "QueueUserAPC",
    "SetThreadContext", "GetThreadContext", "ResumeThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    # Dynamic resolution / unhooking
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
    # Anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "OutputDebugStringA", "GetTickCount", "QueryPerformanceCounter",
    # Persistence / privilege
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
    # Networking
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
    "InternetReadFile", "HttpSendRequestA", "HttpSendRequestW",
    "WSAStartup", "WSASocketA", "WSASocketW", "connect", "send", "recv",
    # Crypto (ransomware-ish)
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
    "BCryptEncrypt", "BCryptDecrypt",
    # File / shadow copies
    "DeleteFileA", "DeleteFileW", "MoveFileExA", "MoveFileExW",
    "SetFileAttributesA", "SetFileAttributesW",
    # Keylogging / surveillance
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
    "GetForegroundWindow", "GetKeyboardState",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@dataclass
class SectionFeatures:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: int


@dataclass
class PEFeatures:
    path: str
    file_size: int
    overall_entropy: float
    is_pe: bool
    error: str | None = None

    # Header
    entry_point: int = 0
    image_base: int = 0
    machine: int = 0
    timestamp: int = 0
    subsystem: int = 0
    characteristics: int = 0
    dll_characteristics: int = 0

    # Sections
    section_count: int = 0
    sections: list[SectionFeatures] = field(default_factory=list)

    # Imports
    imported_dlls: list[str] = field(default_factory=list)
    imported_functions: list[str] = field(default_factory=list)  # "dll!func"
    suspicious_imports: list[str] = field(default_factory=list)
    suspicious_count: int = 0

    # Derived flags useful for explanation
    has_high_entropy_section: bool = False
    has_writable_executable_section: bool = False
    no_imports: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["sections"] = [asdict(s) for s in self.sections]
        return d


def extract(path: str) -> PEFeatures:
    file_size = os.path.getsize(path)
    with open(path, "rb") as f:
        raw = f.read()
    overall_entropy = shannon_entropy(raw)

    feats = PEFeatures(
        path=os.path.abspath(path),
        file_size=file_size,
        overall_entropy=overall_entropy,
        is_pe=False,
    )

    try:
        pe = pefile.PE(data=raw, fast_load=False)
    except pefile.PEFormatError as e:
        feats.error = f"not a valid PE: {e}"
        return feats

    feats.is_pe = True
    feats.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    feats.image_base = pe.OPTIONAL_HEADER.ImageBase
    feats.machine = pe.FILE_HEADER.Machine
    feats.timestamp = pe.FILE_HEADER.TimeDateStamp
    feats.subsystem = pe.OPTIONAL_HEADER.Subsystem
    feats.characteristics = pe.FILE_HEADER.Characteristics
    feats.dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    feats.section_count = pe.FILE_HEADER.NumberOfSections

    IMAGE_SCN_MEM_WRITE = 0x80000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000

    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", errors="replace")
        section_bytes = s.get_data()
        ent = shannon_entropy(section_bytes)
        chars = s.Characteristics
        feats.sections.append(SectionFeatures(
            name=name,
            virtual_size=s.Misc_VirtualSize,
            raw_size=s.SizeOfRawData,
            entropy=ent,
            characteristics=chars,
        ))
        if ent >= 7.2:
            feats.has_high_entropy_section = True
        if (chars & IMAGE_SCN_MEM_WRITE) and (chars & IMAGE_SCN_MEM_EXECUTE):
            feats.has_writable_executable_section = True

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin-1", errors="replace") if entry.dll else ""
            feats.imported_dlls.append(dll)
            for imp in entry.imports:
                fname = ""
                if imp.name:
                    fname = imp.name.decode("latin-1", errors="replace")
                elif imp.ordinal is not None:
                    fname = f"ord_{imp.ordinal}"
                feats.imported_functions.append(f"{dll}!{fname}")
                if fname in SUSPICIOUS_APIS:
                    feats.suspicious_imports.append(f"{dll}!{fname}")
    feats.suspicious_count = len(feats.suspicious_imports)
    feats.no_imports = len(feats.imported_functions) == 0

    pe.close()
    return feats


if __name__ == "__main__":
    import argparse
    import json

    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    args = ap.parse_args()
    print(json.dumps(extract(args.path).to_dict(), indent=2, default=str))
