"""
EMBER 2018 (v2) compatible PE feature extractor — 2381-dim vector.

Vendored from elastic/ember (MIT) with patches for modern LIEF (0.14):
  - np.int -> int  (numpy deprecation)
  - replaced removed lief error classes with broad Exception catch
  - tolerant accessors for renamed header attrs (time_date_stamp[s], etc.)
  - lief.PE.parse() now takes bytes directly

Feature dims (sum = 2381):
  ByteHistogram        256
  ByteEntropyHistogram 256
  StringExtractor      104
  GeneralFileInfo       10
  HeaderFileInfo        62
  SectionInfo          255
  ImportsInfo         1280
  ExportsInfo          128
  DataDirectories       30
"""
from __future__ import annotations

import re
import hashlib
import numpy as np
import lief
from sklearn.feature_extraction import FeatureHasher


def _get(obj, *names, default=0):
    """Try a list of attribute names, return the first one that exists."""
    for n in names:
        if hasattr(obj, n):
            return getattr(obj, n)
    return default


class FeatureType:
    name = ""
    dim = 0

    def raw_features(self, bytez, lief_binary):
        raise NotImplementedError

    def process_raw_features(self, raw_obj):
        raise NotImplementedError

    def feature_vector(self, bytez, lief_binary):
        return self.process_raw_features(self.raw_features(bytez, lief_binary))


class ByteHistogram(FeatureType):
    name = "histogram"
    dim = 256

    def raw_features(self, bytez, lief_binary):
        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
        return counts.tolist()

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        s = counts.sum()
        return counts / s if s > 0 else counts


class ByteEntropyHistogram(FeatureType):
    name = "byteentropy"
    dim = 256

    def __init__(self, step=1024, window=2048):
        self.window = window
        self.step = step

    def _entropy_bin_counts(self, block):
        c = np.bincount(block >> 4, minlength=16)
        p = c.astype(np.float32) / self.window
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh])) * 2
        Hbin = int(H * 2)
        if Hbin == 16:
            Hbin = 15
        return Hbin, c

    def raw_features(self, bytez, lief_binary):
        output = np.zeros((16, 16), dtype=int)
        a = np.frombuffer(bytez, dtype=np.uint8)
        if a.shape[0] < self.window:
            Hbin, c = self._entropy_bin_counts(a)
            output[Hbin, :] += c
        else:
            shape = a.shape[:-1] + (a.shape[-1] - self.window + 1, self.window)
            strides = a.strides + (a.strides[-1],)
            blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::self.step, :]
            for block in blocks:
                Hbin, c = self._entropy_bin_counts(block)
                output[Hbin, :] += c
        return output.flatten().tolist()

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        s = counts.sum()
        return counts / s if s > 0 else counts


class SectionInfo(FeatureType):
    name = "section"
    dim = 5 + 50 * 5

    @staticmethod
    def _properties(s):
        chars = _get(s, "characteristics_lists", "characteristics_list", default=[])
        return [str(c).split(".")[-1] for c in chars]

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return {"entry": "", "sections": []}

        entry_section = ""
        try:
            ep = lief_binary.entrypoint - lief_binary.imagebase
            section = None
            if hasattr(lief_binary, "section_from_rva"):
                section = lief_binary.section_from_rva(ep)
            if section is not None:
                entry_section = section.name
        except Exception:
            pass

        if not entry_section:
            for s in lief_binary.sections:
                props = self._properties(s)
                if "MEM_EXECUTE" in props:
                    entry_section = s.name
                    break

        raw_obj = {"entry": entry_section}
        raw_obj["sections"] = [{
            "name": s.name,
            "size": s.size,
            "entropy": s.entropy,
            "vsize": s.virtual_size,
            "props": self._properties(s),
        } for s in lief_binary.sections]
        return raw_obj

    def process_raw_features(self, raw_obj):
        sections = raw_obj["sections"]
        general = [
            len(sections),
            sum(1 for s in sections if s["size"] == 0),
            sum(1 for s in sections if s["name"] == ""),
            sum(1 for s in sections if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"]),
            sum(1 for s in sections if "MEM_WRITE" in s["props"]),
        ]
        section_sizes = [(s["name"], s["size"]) for s in sections]
        section_sizes_h = FeatureHasher(50, input_type="pair").transform([section_sizes]).toarray()[0]
        section_entropy = [(s["name"], s["entropy"]) for s in sections]
        section_entropy_h = FeatureHasher(50, input_type="pair").transform([section_entropy]).toarray()[0]
        section_vsize = [(s["name"], s["vsize"]) for s in sections]
        section_vsize_h = FeatureHasher(50, input_type="pair").transform([section_vsize]).toarray()[0]
        entry_name_h = FeatureHasher(50, input_type="string").transform([[raw_obj["entry"]]]).toarray()[0]
        characteristics = [p for s in sections for p in s["props"] if s["name"] == raw_obj["entry"]]
        characteristics_h = FeatureHasher(50, input_type="string").transform([characteristics]).toarray()[0]

        return np.hstack([
            general, section_sizes_h, section_entropy_h, section_vsize_h,
            entry_name_h, characteristics_h,
        ]).astype(np.float32)


class ImportsInfo(FeatureType):
    name = "imports"
    dim = 1280

    def raw_features(self, bytez, lief_binary):
        imports = {}
        if lief_binary is None:
            return imports
        for lib in lief_binary.imports:
            if lib.name not in imports:
                imports[lib.name] = []
            for entry in lib.entries:
                if entry.is_ordinal:
                    imports[lib.name].append("ordinal" + str(entry.ordinal))
                else:
                    imports[lib.name].append(entry.name[:10000])
        return imports

    def process_raw_features(self, raw_obj):
        libraries = list(set([l.lower() for l in raw_obj.keys()]))
        libraries_h = FeatureHasher(256, input_type="string").transform([libraries]).toarray()[0]
        imports = [lib.lower() + ":" + e for lib, elist in raw_obj.items() for e in elist]
        imports_h = FeatureHasher(1024, input_type="string").transform([imports]).toarray()[0]
        return np.hstack([libraries_h, imports_h]).astype(np.float32)


class ExportsInfo(FeatureType):
    name = "exports"
    dim = 128

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return []
        out = []
        for export in lief_binary.exported_functions:
            name = export.name if hasattr(export, "name") else export
            out.append(name[:10000])
        return out

    def process_raw_features(self, raw_obj):
        return FeatureHasher(128, input_type="string").transform([raw_obj]).toarray()[0].astype(np.float32)


class GeneralFileInfo(FeatureType):
    name = "general"
    dim = 10

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return {
                "size": len(bytez), "vsize": 0, "has_debug": 0, "exports": 0, "imports": 0,
                "has_relocations": 0, "has_resources": 0, "has_signature": 0, "has_tls": 0, "symbols": 0,
            }
        has_sig = _get(lief_binary, "has_signatures", "has_signature", default=False)
        return {
            "size": len(bytez),
            "vsize": lief_binary.virtual_size,
            "has_debug": int(lief_binary.has_debug),
            "exports": len(lief_binary.exported_functions),
            "imports": len(lief_binary.imported_functions),
            "has_relocations": int(lief_binary.has_relocations),
            "has_resources": int(lief_binary.has_resources),
            "has_signature": int(bool(has_sig)),
            "has_tls": int(lief_binary.has_tls),
            "symbols": len(lief_binary.symbols),
        }

    def process_raw_features(self, raw_obj):
        return np.asarray([
            raw_obj["size"], raw_obj["vsize"], raw_obj["has_debug"], raw_obj["exports"],
            raw_obj["imports"], raw_obj["has_relocations"], raw_obj["has_resources"],
            raw_obj["has_signature"], raw_obj["has_tls"], raw_obj["symbols"],
        ], dtype=np.float32)


class HeaderFileInfo(FeatureType):
    name = "header"
    dim = 62

    def raw_features(self, bytez, lief_binary):
        raw_obj = {
            "coff": {"timestamp": 0, "machine": "", "characteristics": []},
            "optional": {
                "subsystem": "", "dll_characteristics": [], "magic": "",
                "major_image_version": 0, "minor_image_version": 0,
                "major_linker_version": 0, "minor_linker_version": 0,
                "major_operating_system_version": 0, "minor_operating_system_version": 0,
                "major_subsystem_version": 0, "minor_subsystem_version": 0,
                "sizeof_code": 0, "sizeof_headers": 0, "sizeof_heap_commit": 0,
            },
        }
        if lief_binary is None:
            return raw_obj

        h = lief_binary.header
        raw_obj["coff"]["timestamp"] = _get(h, "time_date_stamps", "time_date_stamp", default=0)
        raw_obj["coff"]["machine"] = str(h.machine).split(".")[-1]
        chars = _get(h, "characteristics_list", "characteristics_lists", default=[])
        raw_obj["coff"]["characteristics"] = [str(c).split(".")[-1] for c in chars]

        oh = lief_binary.optional_header
        raw_obj["optional"]["subsystem"] = str(oh.subsystem).split(".")[-1]
        dll_chars = _get(oh, "dll_characteristics_lists", "dll_characteristics_list", default=[])
        raw_obj["optional"]["dll_characteristics"] = [str(c).split(".")[-1] for c in dll_chars]
        raw_obj["optional"]["magic"] = str(oh.magic).split(".")[-1]
        raw_obj["optional"]["major_image_version"] = oh.major_image_version
        raw_obj["optional"]["minor_image_version"] = oh.minor_image_version
        raw_obj["optional"]["major_linker_version"] = oh.major_linker_version
        raw_obj["optional"]["minor_linker_version"] = oh.minor_linker_version
        raw_obj["optional"]["major_operating_system_version"] = oh.major_operating_system_version
        raw_obj["optional"]["minor_operating_system_version"] = oh.minor_operating_system_version
        raw_obj["optional"]["major_subsystem_version"] = oh.major_subsystem_version
        raw_obj["optional"]["minor_subsystem_version"] = oh.minor_subsystem_version
        raw_obj["optional"]["sizeof_code"] = oh.sizeof_code
        raw_obj["optional"]["sizeof_headers"] = oh.sizeof_headers
        raw_obj["optional"]["sizeof_heap_commit"] = oh.sizeof_heap_commit
        return raw_obj

    def process_raw_features(self, raw_obj):
        return np.hstack([
            raw_obj["coff"]["timestamp"],
            FeatureHasher(10, input_type="string").transform([[raw_obj["coff"]["machine"]]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([raw_obj["coff"]["characteristics"]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[raw_obj["optional"]["subsystem"]]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([raw_obj["optional"]["dll_characteristics"]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[raw_obj["optional"]["magic"]]]).toarray()[0],
            raw_obj["optional"]["major_image_version"],
            raw_obj["optional"]["minor_image_version"],
            raw_obj["optional"]["major_linker_version"],
            raw_obj["optional"]["minor_linker_version"],
            raw_obj["optional"]["major_operating_system_version"],
            raw_obj["optional"]["minor_operating_system_version"],
            raw_obj["optional"]["major_subsystem_version"],
            raw_obj["optional"]["minor_subsystem_version"],
            raw_obj["optional"]["sizeof_code"],
            raw_obj["optional"]["sizeof_headers"],
            raw_obj["optional"]["sizeof_heap_commit"],
        ]).astype(np.float32)


class StringExtractor(FeatureType):
    name = "strings"
    dim = 1 + 1 + 1 + 96 + 1 + 1 + 1 + 1 + 1

    def __init__(self):
        self._allstrings = re.compile(b"[\x20-\x7f]{5,}")
        self._paths = re.compile(b"c:\\\\", re.IGNORECASE)
        self._urls = re.compile(b"https?://", re.IGNORECASE)
        self._registry = re.compile(b"HKEY_")
        self._mz = re.compile(b"MZ")

    def raw_features(self, bytez, lief_binary):
        allstrings = self._allstrings.findall(bytez)
        if allstrings:
            string_lengths = [len(s) for s in allstrings]
            avlength = sum(string_lengths) / len(string_lengths)
            as_shifted_string = [b - 0x20 for b in b"".join(allstrings)]
            c = np.bincount(as_shifted_string, minlength=96)
            csum = c.sum()
            p = c.astype(np.float32) / csum if csum > 0 else c.astype(np.float32)
            wh = np.where(c)[0]
            H = np.sum(-p[wh] * np.log2(p[wh])) if csum > 0 else 0
        else:
            avlength = 0
            c = np.zeros((96,), dtype=np.float32)
            H = 0
            csum = 0
        return {
            "numstrings": len(allstrings),
            "avlength": avlength,
            "printabledist": c.tolist(),
            "printables": int(csum),
            "entropy": float(H),
            "paths": len(self._paths.findall(bytez)),
            "urls": len(self._urls.findall(bytez)),
            "registry": len(self._registry.findall(bytez)),
            "MZ": len(self._mz.findall(bytez)),
        }

    def process_raw_features(self, raw_obj):
        hist_divisor = float(raw_obj["printables"]) if raw_obj["printables"] > 0 else 1.0
        return np.hstack([
            raw_obj["numstrings"], raw_obj["avlength"], raw_obj["printables"],
            np.asarray(raw_obj["printabledist"]) / hist_divisor,
            raw_obj["entropy"], raw_obj["paths"], raw_obj["urls"],
            raw_obj["registry"], raw_obj["MZ"],
        ]).astype(np.float32)


class DataDirectories(FeatureType):
    name = "datadirectories"
    dim = 15 * 2

    _name_order = [
        "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE",
        "CERTIFICATE_TABLE", "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE",
        "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE", "BOUND_IMPORT",
        "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER",
    ]

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return []
        out = []
        for dd in lief_binary.data_directories:
            out.append({
                "name": str(dd.type).replace("DATA_DIRECTORY.", ""),
                "size": dd.size,
                "virtual_address": dd.rva,
            })
        return out

    def process_raw_features(self, raw_obj):
        features = np.zeros(2 * len(self._name_order), dtype=np.float32)
        for i in range(len(self._name_order)):
            if i < len(raw_obj):
                features[2 * i] = raw_obj[i]["size"]
                features[2 * i + 1] = raw_obj[i]["virtual_address"]
        return features


class PEFeatureExtractor:
    """EMBER v2 — 2381-dim vector."""

    def __init__(self, feature_version=2):
        self.features = [
            ByteHistogram(),
            ByteEntropyHistogram(),
            StringExtractor(),
            GeneralFileInfo(),
            HeaderFileInfo(),
            SectionInfo(),
            ImportsInfo(),
            ExportsInfo(),
        ]
        if feature_version == 2:
            self.features.append(DataDirectories())
        self.dim = sum(f.dim for f in self.features)

    def _parse(self, bytez):
        try:
            return lief.PE.parse(list(bytez))
        except Exception:
            try:
                return lief.PE.parse(bytez)
            except Exception:
                return None

    def raw_features(self, bytez):
        lief_binary = self._parse(bytez)
        features = {"sha256": hashlib.sha256(bytez).hexdigest()}
        features.update({fe.name: fe.raw_features(bytez, lief_binary) for fe in self.features})
        return features

    def process_raw_features(self, raw_obj):
        feature_vectors = [fe.process_raw_features(raw_obj[fe.name]) for fe in self.features]
        return np.hstack(feature_vectors).astype(np.float32)

    def feature_vector(self, bytez):
        return self.process_raw_features(self.raw_features(bytez))


# (group_name, lo, hi) slices into the flat 2381-dim vector.
def feature_group_index() -> list[tuple[str, int, int]]:
    extractor = PEFeatureExtractor()
    out = []
    start = 0
    for f in extractor.features:
        out.append((f.name, start, start + f.dim))
        start += f.dim
    return out


# Sub-layouts within each group. FeatureHasher outputs can't be reversed
# to the original string, so those buckets are labeled by purpose + slot.

_STRINGS_FIELDS = (
    [("numstrings", 1), ("avlength", 1), ("printables", 1)]
    + [(f"printable_dist[char=0x{0x20 + i:02x}]", 1) for i in range(96)]
    + [("strings_entropy", 1), ("paths_count", 1), ("urls_count", 1),
       ("registry_count", 1), ("MZ_count", 1)]
)

_GENERAL_FIELDS = [
    ("size", 1), ("vsize", 1), ("has_debug", 1), ("exports_count", 1),
    ("imports_count", 1), ("has_relocations", 1), ("has_resources", 1),
    ("has_signature", 1), ("has_tls", 1), ("symbols_count", 1),
]

_HEADER_FIELDS = (
    [("coff.timestamp", 1)]
    + [(f"coff.machine_hash[{i}]", 1) for i in range(10)]
    + [(f"coff.characteristics_hash[{i}]", 1) for i in range(10)]
    + [(f"optional.subsystem_hash[{i}]", 1) for i in range(10)]
    + [(f"optional.dll_characteristics_hash[{i}]", 1) for i in range(10)]
    + [(f"optional.magic_hash[{i}]", 1) for i in range(10)]
    + [("optional.major_image_version", 1), ("optional.minor_image_version", 1),
       ("optional.major_linker_version", 1), ("optional.minor_linker_version", 1),
       ("optional.major_os_version", 1), ("optional.minor_os_version", 1),
       ("optional.major_subsystem_version", 1), ("optional.minor_subsystem_version", 1),
       ("optional.sizeof_code", 1), ("optional.sizeof_headers", 1),
       ("optional.sizeof_heap_commit", 1)]
)

_SECTION_FIELDS = (
    [("section.count", 1), ("section.zero_size_count", 1), ("section.empty_name_count", 1),
     ("section.RX_count", 1), ("section.W_count", 1)]
    + [(f"section.size_hash[{i}]", 1) for i in range(50)]
    + [(f"section.entropy_hash[{i}]", 1) for i in range(50)]
    + [(f"section.vsize_hash[{i}]", 1) for i in range(50)]
    + [(f"section.entry_name_hash[{i}]", 1) for i in range(50)]
    + [(f"section.entry_chars_hash[{i}]", 1) for i in range(50)]
)

_IMPORTS_FIELDS = (
    [(f"imports.lib_hash[{i}]", 1) for i in range(256)]
    + [(f"imports.lib_func_hash[{i}]", 1) for i in range(1024)]
)

_EXPORTS_FIELDS = [(f"exports.name_hash[{i}]", 1) for i in range(128)]

_DD_NAMES = [
    "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE",
    "CERTIFICATE_TABLE", "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE",
    "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE", "BOUND_IMPORT",
    "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER",
]
_DD_FIELDS = []
for _n in _DD_NAMES:
    _DD_FIELDS.append((f"datadir.{_n}.size", 1))
    _DD_FIELDS.append((f"datadir.{_n}.vaddr", 1))


_GROUP_LAYOUTS: dict[str, list[tuple[str, int]] | None] = {
    "histogram": None,           # 256 byte-value bins — handled below
    "byteentropy": None,         # 16x16 (entropy_bin, byte_high_nibble) — handled below
    "strings": _STRINGS_FIELDS,
    "general": _GENERAL_FIELDS,
    "header": _HEADER_FIELDS,
    "section": _SECTION_FIELDS,
    "imports": _IMPORTS_FIELDS,
    "exports": _EXPORTS_FIELDS,
    "datadirectories": _DD_FIELDS,
}


def feature_name(idx: int) -> str:
    """Map a flat 2381-dim feature index to a human-readable name."""
    for group, lo, hi in feature_group_index():
        if not (lo <= idx < hi):
            continue
        local = idx - lo
        if group == "histogram":
            return f"byte_hist[0x{local:02x}]"
        if group == "byteentropy":
            entropy_bin = local // 16
            byte_bin = local % 16
            lo_byte = byte_bin * 16
            hi_byte = lo_byte + 15
            # entropy bin width = 0.5 bits (Hbin = int(H*2), max 16)
            e_lo = entropy_bin * 0.5
            e_hi = e_lo + 0.5
            return (f"byte_entropy[entropy={e_lo:.1f}-{e_hi:.1f}bits, "
                    f"byte=0x{lo_byte:02x}-0x{hi_byte:02x}]")
        layout = _GROUP_LAYOUTS[group]
        return layout[local][0] if layout else f"{group}[{local}]"
    return f"feat[{idx}]"
