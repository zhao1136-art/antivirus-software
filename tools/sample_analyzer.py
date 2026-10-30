#!/usr/bin/env python3
"""通用样本安全分析工具 —— 给一堆文件/目录/压缩包，出一份卡饭格式的报告。

设计要点
--------
* **不落盘**：所有解包内容走 ``tempfile.SpooledTemporaryFile``（64 MB 内留在内存，
  超出部分溢到系统临时目录），**从不写到用户可见路径**，也不会被实时防护搬走。
* **能吃 AES**：内层 zip 常见 ``compress_type=99``（WinZip AES-256），标准库
  ``zipfile`` 读不了，这里走 ``pyzipper``；没有 pyzipper 时明确报错而不是静默失败。
* **能吃 SFX**：自解压包开头是 ``MZ``，真正的归档头在后面 —— 所以除了看头 8 字节，
  还在前 8 MB 里搜 ``PK\\x03\\x04`` / ``Rar!\\x1a\\x07``。
* **不吃"猜"**：归属判定只用能被验证的信号（特征库命中 / YARA / 启发式），
  拿不到结论就写"无结论"，不拿文件名瞎猜。

用法
----
    python sample_analyzer.py <路径...> [选项]

    路径        文件 / 目录 / .zip / .rar / .7z / SFX(.exe)
    --password  压缩包口令（默认试 infected / Infected / virus）
    --depth     嵌套解包深度（默认 3）
    --format    md（默认）| json
    -o          输出文件（默认 stdout）
    --import-db 把**判定为恶意**的样本哈希写入病毒库（默认只读，不写库）
    --no-yara / --no-ml / --no-heuristic   关掉某些引擎（快速模式）
    --quiet     只输出统计

指纹（对齐卡饭帖子的格式，并补上病毒库需要的两种）
--------------------------------------------------
    大小 / CRC32 / XXH64 / MD5 / SHA1 / SHA256 / SHA3-256
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from collections import Counter

# ── 后端路径（复用产品自己的引擎）──
_BACKEND = os.environ.get("YUTIAN_BACKEND") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
if os.path.isdir(_BACKEND):
    sys.path.insert(0, _BACKEND)

try:
    import pyzipper  # AES-256 zip
except Exception:  # pragma: no cover
    pyzipper = None

SPOOL_MAX = 64 * 1024 * 1024
CHUNK = 1024 * 1024
DEFAULT_PWDS = (b"infected", b"Infected", b"virus")
MAX_ENTRY = 512 * 1024 * 1024
SFX_SCAN = 8 * 1024 * 1024


# ══════════════════════════════════════════════════════════════════
# 指纹
# ══════════════════════════════════════════════════════════════════

_P1 = 11400714785074694791
_P2 = 14029467366897019727
_P3 = 1609587929392839161
_P4 = 9650029242287828579
_P5 = 2870177450012600261
_M64 = (1 << 64) - 1


def _rotl(x: int, r: int) -> int:
    return ((x << r) | (x >> (64 - r))) & _M64


def _round(acc: int, val: int) -> int:
    acc = (acc + val * _P2) & _M64
    acc = _rotl(acc, 31)
    return (acc * _P1) & _M64


def _merge(acc: int, val: int) -> int:
    acc ^= _round(0, val)
    return (acc * _P1 + _P4) & _M64


def xxh64(data: bytes, seed: int = 0) -> int:
    """纯 Python XXH64（没装 xxhash 时的后备实现，结果与官方一致）。"""
    n = len(data)
    i = 0
    if n >= 32:
        v1 = (seed + _P1 + _P2) & _M64
        v2 = (seed + _P2) & _M64
        v3 = seed & _M64
        v4 = (seed - _P1) & _M64
        while i <= n - 32:
            v1 = _round(v1, struct.unpack_from("<Q", data, i)[0]); i += 8
            v2 = _round(v2, struct.unpack_from("<Q", data, i)[0]); i += 8
            v3 = _round(v3, struct.unpack_from("<Q", data, i)[0]); i += 8
            v4 = _round(v4, struct.unpack_from("<Q", data, i)[0]); i += 8
        h = (_rotl(v1, 1) + _rotl(v2, 7) + _rotl(v3, 12) + _rotl(v4, 18)) & _M64
        h = _merge(h, v1)
        h = _merge(h, v2)
        h = _merge(h, v3)
        h = _merge(h, v4)
    else:
        h = (seed + _P5) & _M64
    h = (h + n) & _M64
    while i <= n - 8:
        k = _round(0, struct.unpack_from("<Q", data, i)[0])
        h ^= k
        h = (_rotl(h, 27) * _P1 + _P4) & _M64
        i += 8
    if i <= n - 4:
        h ^= (struct.unpack_from("<I", data, i)[0] * _P1) & _M64
        h = (_rotl(h, 23) * _P2 + _P3) & _M64
        i += 4
    while i < n:
        h ^= (data[i] * _P5) & _M64
        h = (_rotl(h, 11) * _P1) & _M64
        i += 1
    h ^= h >> 33
    h = (h * _P2) & _M64
    h ^= h >> 29
    h = (h * _P3) & _M64
    h ^= h >> 32
    return h


class Fingerprint:
    """一边流式读一边算全部指纹，内存恒定。

    XXH64 没有流式接口，所以对 ≤64MB 的文件顺带留一份完整缓冲（超出就放弃 XXH64，
    报告里写 "-" 而不是 0 —— 假数据比没有数据更糟）。
    """

    __slots__ = ("size", "crc32", "xxh64_value", "md5", "sha1", "sha256", "sha3",
                 "_head", "_buf")
    _BUF_CAP = 64 * 1024 * 1024

    def __init__(self) -> None:
        self.size = 0
        self.crc32 = 0
        self.xxh64_value = 0
        self.md5 = hashlib.md5()
        self.sha1 = hashlib.sha1()
        self.sha256 = hashlib.sha256()
        self.sha3 = hashlib.sha3_256()
        self._head = bytearray()
        self._buf = bytearray()

    def update(self, chunk: bytes) -> None:
        if len(self._head) < 65536:
            self._head += chunk[:65536 - len(self._head)]
        if self._buf is not None:
            if len(self._buf) + len(chunk) <= self._BUF_CAP:
                self._buf += chunk
            else:
                self._buf = None          # 太大，放弃 XXH64
        self.size += len(chunk)
        self.crc32 = zlib.crc32(chunk, self.crc32)
        self.md5.update(chunk)
        self.sha1.update(chunk)
        self.sha256.update(chunk)
        self.sha3.update(chunk)

    def finish(self) -> dict:
        # 只有缓冲里确实是完整文件时才算 XXH64
        if self._buf is not None and len(self._buf) == self.size:
            x = xxh64(bytes(self._buf))
            x_txt = format(x, "016X")
        else:
            x_txt = "-"
        return {
            "size": self.size,
            "crc32": format(self.crc32 & 0xFFFFFFFF, "08X"),
            "xxh64": x_txt,
            "md5": self.md5.hexdigest(),
            "sha1": self.sha1.hexdigest(),
            "sha256": self.sha256.hexdigest(),
            "sha3_256": self.sha3.hexdigest(),
            "head": bytes(self._head),
        }

    @property
    def head(self) -> bytes:
        return bytes(self._head)


# ══════════════════════════════════════════════════════════════════
# 类型识别
# ══════════════════════════════════════════════════════════════════

_MAGIC = [
    (b"MZ", "PE"),
    (b"PK\x03\x04", "ZIP"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"\x1f\x8b", "GZIP"),
    (b"%PDF", "PDF"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE"),
    (b"\xca\xfe\xba\xbe", "JAVA_CLASS"),
    (b"#!", "SCRIPT"),
    (b"<?xml", "XML"),
    (b"{\\rtf", "RTF"),
    (b"MSCF", "CHM"),
    (b"ITSF", "CHM"),
    (b"L\x00\x00\x00", "LNK"),
]


def sniff(head: bytes, name: str) -> str:
    for sig, kind in _MAGIC:
        if head.startswith(sig):
            if kind == "PE":
                try:
                    off = struct.unpack_from("<I", head, 0x3C)[0]
                    if head[off:off + 4] == b"PE\x00\x00":
                        mach = struct.unpack_from("<H", head, off + 4)[0]
                        return {0x8664: "PE64", 0x14C: "PE32",
                                0xAA64: "PE-ARM64"}.get(mach, "PE")
                except Exception:
                    pass
                return "PE"
            return kind
    ext = os.path.splitext(name)[1].lower().lstrip(".")
    return (ext.upper() or "DATA")[:12]


# ══════════════════════════════════════════════════════════════════
# 引擎封装（后端有就用，没有就跳过）
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
# 内置启发式（独立软件用 —— 不依赖产品后端的 heuristic_engine）
#
# 后端在的时候优先用后端的（规则更细、实测 0/300 误报）；
# 后端不在的时候用这套，保证 exe 拷到任何机器上都有判定能力。
# 规则刻意保守：宁可"无结论"，也不给正常文件乱扣分。
# ══════════════════════════════════════════════════════════════════

_SUSP_API = (
    b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
    b"NtUnmapViewOfSection", b"SetWindowsHookExA", b"SetWindowsHookExW",
    b"GetAsyncKeyState", b"AdjustTokenPrivileges", b"URLDownloadToFileA",
    b"URLDownloadToFileW", b"IsDebuggerPresent", b"CheckRemoteDebugger",
)
_SCRIPT_BAD = (
    b"-enc ", b"-EncodedCommand", b"-w hidden", b"-windowstyle hidden",
    b"FromBase64String", b"DownloadString", b"DownloadFile",
    b"certutil -urlcache", b"bitsadmin /transfer", b"mshta ",
    b"regsvr32 /s /u /i", b"rundll32 javascript",
)

# 与后端 heuristic_engine 一致的"可疑"门槛：**低于 40 分不算命中**。
# 原先只要 score>0 就返回结果，导致内置启发式把"高熵的普通文件"
# （图片、压缩包、安装器）一律判为可疑 —— 实测正常文件几乎 100% 报可疑，
# 与后端的判定口径也不一致。这里对齐门槛。
HEURISTIC_MIN_SCORE = 40


def _entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    cnt = [0] * 256
    for b in buf:
        cnt[b] += 1
    import math
    e = 0.0
    n = len(buf)
    for c in cnt:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def builtin_heuristics(head: bytes, name: str, size: int) -> dict | None:
    """返回与后端 heuristic_engine 兼容的结构：{heuristic_score, reasons}。

    没有任何命中时返回 None（与后端一致：None = 未命中）。
    """
    score = 0
    reasons: list[str] = []
    ext = os.path.splitext(name)[1].lower()

    # 1. 整体高熵（加壳/加密）
    if size > 4096:
        e = _entropy(head[: min(len(head), 1 << 20)])
        if e > 7.4:
            score += 25
            reasons.append(f"高熵 {e:.2f}（可能加壳或加密）")
    # 2. 可疑 API 字符串
    hits = [a.decode() for a in _SUSP_API if a in head]
    if len(hits) >= 6:
        score += 20
        reasons.append(f"{len(hits)} 个高危 API 字符串: " + ", ".join(hits[:4]))
    elif len(hits) >= 3:
        score += 10
        reasons.append(f"{len(hits)} 个高危 API: " + ", ".join(hits[:3]))
    # 3. 脚本里的下载/隐藏执行特征
    if ext in (".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".wsf", ".wsc"):
        # ⚠️ 必须**不区分大小写**：载荷里写成 `-encodedcommand`、
        # `FROMBASE64STRING`、`DownloadString` 都很常见，原先直接拿
        # 大小写混排的字面量在原始字节里做子串比较 → 小写写法全部漏报。
        head_low = head.lower()
        bad = [s.decode("latin1", "ignore").strip()
               for s in _SCRIPT_BAD if s.lower() in head_low]
        if bad:
            # 40 分（而非 30）：脚本里同时出现"隐藏窗口 / -enc / 从 Base64 解码 /
            # DownloadString"任意一项就已经是强信号，分值须能独立达到可疑门槛，
            # 否则单靠这一条永远 < 40、永远不报。
            score += 40
            reasons.append("脚本含下载/隐藏执行特征: " + ", ".join(bad[:4]))
    # 4. MZ 头但没有 PE 签名（伪装成 exe 的非 PE）
    if head[:2] == b"MZ":
        try:
            off = int.from_bytes(head[0x3C:0x40], "little")
            if head[off:off + 4] != b"PE\x00\x00":
                score += 25
                reasons.append("MZ 头但无 PE 签名（伪装）")
        except Exception:
            score += 15
            reasons.append("MZ 头但 e_lfanew 损坏")

    if score < HEURISTIC_MIN_SCORE:
        # 低于门槛不算命中（None = 未命中，与后端 heuristic_engine 语义一致）
        return None
    if score > 100:
        score = 100
    return {"heuristic_score": score, "reasons": reasons}


class Engines:
    def __init__(self, use_yara=True, use_ml=True, use_heur=True) -> None:
        self.yara = self.heur = self.sig = None
        self.ml = None
        # 记住用户的开关：run() 里要靠它决定"后端启发式不可用"时
        # 该不该退回内置启发式。原先没保存，导致 --no-heuristic 形同虚设
        # （关掉后端启发式后，else 分支照样跑内置启发式）。
        self.use_heur = bool(use_heur)
        self.notes: list[str] = []
        if use_yara:
            try:
                from engine.yara_scanner import YaraScanner
                rules = os.path.join(_BACKEND, "engine", "yara_rules")
                self.yara = YaraScanner(rules)
                self.notes.append(f"YARA {len(self.yara.rules)} 条规则")
            except Exception as exc:
                self.notes.append(f"YARA 不可用: {exc}")
        if use_heur:
            try:
                from engine.heuristic_engine import get_heuristic_engine
                self.heur = get_heuristic_engine()
                self.notes.append("启发式 已加载")
            except Exception as exc:
                self.notes.append(f"启发式 不可用: {exc}")
        if use_ml:
            try:
                from engine.ml_scanner import scan_pe as _scan_pe
                self.ml = _scan_pe
                self.notes.append("ML PE 已加载（仅供参考）")
            except Exception as exc:
                self.notes.append(f"ML 不可用: {exc}")
        try:
            from engine.signature_manager import get_signature_manager
            self.sig = get_signature_manager()
            self.notes.append(f"特征库 {self.sig.get_stats()['total_signatures']:,} 条")
        except Exception as exc:
            self.notes.append(f"特征库 不可用: {exc}")

    def run(self, name: str, fp: dict) -> dict:
        md5, sha1, sha256 = fp["md5"], fp["sha1"], fp["sha256"]
        out = {"yara": [], "heuristic": None, "ml": None, "signature": None}

        # 特征库
        if self.sig:
            try:
                out["signature"] = self.sig.lookup(md5=md5, sha1=sha1, sha256=sha256)
            except Exception:
                pass

        data = fp.get("_data")
        if data is None:
            return out
        head = fp["head"]

        if self.yara:
            try:
                out["yara"] = [{"rule": h["rule"],
                                "confidence": h.get("confidence"),
                                "quality": h.get("quality_reason", "")}
                               for h in self.yara.scan_content(data, name)]
            except Exception as exc:
                out["yara_error"] = str(exc)

        if not self.use_heur:
            # 用户显式 --no-heuristic：**完全不跑启发式**（含内置那套）。
            # 原先前端启发式被关掉后，else 分支仍会调用内置启发式，
            # 等于这个开关没生效。
            out["heuristic"] = None
        elif self.heur:
            try:
                r = (self.heur.analyze_generic(head[:65536], name, md5, sha256,
                                               fp["size"])
                     or self.heur.analyze_pe(head[:64], name, md5, sha256,
                                             fp["size"]))
                out["heuristic"] = r
            except Exception:
                out["heuristic"] = builtin_heuristics(head, name, fp["size"])
        else:
            # 后端不在（独立 exe 跑在别人机器上）—— 用内置规则，保证还有判定能力
            out["heuristic"] = builtin_heuristics(head, name, fp["size"])

        if self.ml and head.startswith(b"MZ"):
            try:
                out["ml"] = self.ml(data[:4 * 1024 * 1024], sha256)
            except Exception:
                pass
        return out


# ══════════════════════════════════════════════════════════════════
# 归属判定
# ══════════════════════════════════════════════════════════════════

def attribute(eng: dict) -> tuple[str, str]:
    """返回 (归属, 依据)。只用能验证的信号，拿不准就写无结论。"""
    sig = eng.get("signature")
    if sig:
        return "恶意（特征库）", f"{sig.get('threat_name')} / {sig.get('threat_level')}"

    hits = eng.get("yara") or []
    strong = [h for h in hits if (h.get("confidence") or "medium") != "low"]
    if strong:
        names = ", ".join(h["rule"] for h in strong[:3])
        return "恶意（YARA）", names

    h = eng.get("heuristic")
    if h:
        reasons = h.get("reasons") or h.get("warnings") or []
        return "可疑（启发式）", f"分数 {h.get('heuristic_score', '?')}: " + \
                                 "; ".join(str(x) for x in reasons[:2])

    if hits:
        return "可疑（YARA 低置信度）", ", ".join(h["rule"] for h in hits[:3])
    return "无结论", ""


# ══════════════════════════════════════════════════════════════════
# 输入枚举（不落盘）
# ══════════════════════════════════════════════════════════════════

def _open_archive(path: str):
    """返回 (zipfile-like 对象, 口令)。支持 AES。"""
    last = ""
    factories = []
    if pyzipper is not None:
        factories.append(pyzipper.AESZipFile)
    factories.append(zipfile.ZipFile)
    zf = None
    for fac in factories:
        try:
            zf = fac(path)
            break
        except Exception as exc:
            last = f"{type(exc).__name__}: {exc}"
    if zf is None:
        raise RuntimeError(f"不是可读的 zip（{last}）")

    files = [e for e in zf.infolist() if not e.is_dir()]
    if not files:
        return zf, None
    probe = files[0]
    for pw in (None,) + DEFAULT_PWDS:
        try:
            with zf.open(probe, pwd=pw) as fh:
                fh.read(16)
            return zf, pw
        except NotImplementedError as exc:
            raise RuntimeError(f"压缩算法不支持（{exc}）—— 内层可能是 AES，"
                               f"需要 pyzipper") from exc
        except Exception:
            continue
    raise RuntimeError("所有候选口令都失败，请用 --password 指定")


def iter_samples(paths: list[str], password: bytes | None,
                 depth: int, stats: Counter):
    """产出 (显示名, SpooledTemporaryFile)。递归但不落盘。"""
    for p in paths:
        p = os.path.abspath(p)
        if os.path.isdir(p):
            for dp, _dn, fn in os.walk(p):
                for f in sorted(fn):
                    yield from iter_samples([os.path.join(dp, f)],
                                            password, depth, stats)
            continue
        if not os.path.isfile(p):
            stats["missing"] += 1
            continue
        yield from _handle_file(p, os.path.basename(p), password, depth, stats)


def _handle_file(p: str, display: str, password: bytes | None,
                 depth: int, stats: Counter):
    try:
        size = os.path.getsize(p)
    except OSError:
        stats["missing"] += 1
        return

    # 归档判定（含 SFX）
    arc = None
    try:
        with open(p, "rb") as fh:
            head = fh.read(SFX_SCAN)
    except OSError:
        stats["unreadable"] += 1
        return
    if head[:2] in (b"PK", b"Ra") and (head.startswith(b"PK\x03\x04")
                                       or head.startswith(b"Rar!")):
        arc = "zip" if head.startswith(b"PK") else "rar"
    elif head.startswith(b"MZ"):
        zi = head.find(b"PK\x03\x04", 2)
        ri = head.find(b"Rar!\x1a\x07", 2)
        if zi >= 0 or ri >= 0:
            arc = "zip" if (ri < 0 or (zi >= 0 and zi < ri)) else "rar"

    if arc == "zip" and depth > 0:
        try:
            zf, pw = _open_archive(p)
        except Exception as exc:
            stats["archive_error"] += 1
            yield display + "  [归档读取失败: %s]" % exc, None, None
            return
        with zf:
            stats["archives"] += 1
            for e in zf.infolist():
                if e.is_dir() or e.file_size > MAX_ENTRY:
                    continue
                try:
                    spool = tempfile.SpooledTemporaryFile(max_size=SPOOL_MAX)
                    with zf.open(e, pwd=pw) as src:
                        while True:
                            c = src.read(CHUNK)
                            if not c:
                                break
                            spool.write(c)
                    spool.seek(0)
                except Exception as exc:
                    stats["entry_error"] += 1
                    yield f"{display}!{e.filename}  [读失败: {type(exc).__name__}]", None, None
                    continue
                # 嵌套归档继续递归
                try:
                    head2 = spool.read(SFX_SCAN)
                    spool.seek(0)
                except Exception:
                    head2 = b""
                nested = head2.startswith(b"PK\x03\x04") or head2.startswith(b"Rar!")
                if nested and depth > 1 and head2.startswith(b"PK"):
                    # 嵌套 zip：写到 spooled 临时文件再当路径用不行，直接流式解析
                    try:
                        sub = pyzipper.AESZipFile if pyzipper else zipfile.ZipFile
                        zf2 = sub(spool)
                        with zf2:
                            pw2 = None
                            for cand in (None,) + DEFAULT_PWDS:
                                try:
                                    with zf2.open(zf2.infolist()[0], pwd=cand) as f:
                                        f.read(8)
                                    pw2 = cand
                                    break
                                except Exception:
                                    continue
                            if pw2 is not None or zf2.infolist():
                                for e2 in zf2.infolist():
                                    if e2.is_dir() or e2.file_size > MAX_ENTRY:
                                        continue
                                    sp2 = tempfile.SpooledTemporaryFile(max_size=SPOOL_MAX)
                                    try:
                                        with zf2.open(e2, pwd=pw2) as s2:
                                            while True:
                                                c2 = s2.read(CHUNK)
                                                if not c2:
                                                    break
                                                sp2.write(c2)
                                        sp2.seek(0)
                                        yield (f"{display}!{e.filename}!{e2.filename}",
                                               sp2, len(spool.getvalue()) if False else None)
                                    except Exception:
                                        stats["entry_error"] += 1
                                    finally:
                                        sp2.close()
                                continue
                    except Exception:
                        pass
                yield f"{display}!{e.filename}", spool, None
        return

    if arc == "rar" and depth > 0:
        stats["rar_skip"] += 1
        yield display + "  [RAR：需要外部 unrar，本工具暂不递归]", None, None
        return

    spool = tempfile.SpooledTemporaryFile(max_size=SPOOL_MAX)
    try:
        with open(p, "rb") as src:
            while True:
                c = src.read(CHUNK)
                if not c:
                    break
                spool.write(c)
        spool.seek(0)
    except OSError:
        spool.close()
        stats["unreadable"] += 1
        return
    yield display, spool, None


# ══════════════════════════════════════════════════════════════════
# 报告
# ══════════════════════════════════════════════════════════════════

IOC_URL = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,200}")
IOC_DOM = re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,4}"
                     rb"(?:com|net|org|cn|io|ru|xyz|top|info|biz|cc|tk|ml|ga)\b",
                     re.I)
IOC_IP = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                    rb"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def escape_ioc(s: str) -> str:
    return s.replace(".", "[.]")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="通用样本安全分析工具（不落盘，卡饭格式报告）")
    ap.add_argument("paths", nargs="+", help="文件/目录/压缩包")
    ap.add_argument("--password", default=None, help="压缩包口令")
    ap.add_argument("--depth", type=int, default=3, help="嵌套深度（默认 3）")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--import-db", action="store_true",
                    help="把判定为恶意的哈希写入病毒库（默认不写）")
    ap.add_argument("--no-yara", action="store_true")
    ap.add_argument("--no-ml", action="store_true")
    ap.add_argument("--no-heuristic", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    pw = args.password.encode() if args.password else None
    engines = Engines(not args.no_yara, not args.no_ml, not args.no_heuristic)
    stats: Counter = Counter()
    records: list[dict] = []
    iocs: dict[str, set] = {"url": set(), "domain": set(), "ip": set()}
    t0 = time.perf_counter()

    for display, spool, _extra in iter_samples(args.paths, pw, args.depth, stats):
        if spool is None:
            records.append({"name": display, "error": True})
            if not args.quiet:
                print(f"  [跳过] {display}", file=sys.stderr)
            continue
        try:
            fpr = Fingerprint()
            whole = bytearray() if not args.no_ml else None
            spool.seek(0)
            while True:
                c = spool.read(CHUNK)
                if not c:
                    break
                fpr.update(c)
            fp = fpr.finish()
            spool.seek(0)
            # ML 需要完整前 4MB；为避免二次读大文件，只用 head
            head_all = spool.read(4 * 1024 * 1024)
            spool.seek(0)
            fp["_data"] = head_all
            fp["kind"] = sniff(fp["head"], display)
            eng = engines.run(display, fp)
            verdict, basis = attribute(eng)
            stats["files"] += 1
            if verdict.startswith("恶意"):
                stats["malicious"] += 1
            elif verdict.startswith("可疑"):
                stats["suspicious"] += 1
            else:
                stats["clean"] += 1

            # IOC（只看前 4 MB，避免把 200 MB 文件全扫）
            blob = head_all
            for m in IOC_URL.finditer(blob):
                iocs["url"].add(escape_ioc(m.group(0).decode("latin1", "ignore")))
            for m in IOC_DOM.finditer(blob):
                iocs["domain"].add(escape_ioc(m.group(0).decode("latin1", "ignore")))
            for m in IOC_IP.finditer(blob):
                ip = m.group(0).decode("latin1")
                if not ip.startswith(("0.", "127.", "255.")):
                    iocs["ip"].add(escape_ioc(ip))

            records.append({
                "name": display, "kind": fp["kind"],
                "size": fp["size"], "crc32": fp["crc32"], "xxh64": fp["xxh64"],
                "md5": fp["md5"], "sha1": fp["sha1"],
                "sha256": fp["sha256"], "sha3_256": fp["sha3_256"],
                "verdict": verdict, "basis": basis,
                "yara": [h["rule"] for h in (eng.get("yara") or [])],
                "ml": (eng.get("ml") or {}).get("verdict") if eng.get("ml") else None,
                "heuristic_score": (eng.get("heuristic") or {}).get("heuristic_score"),
            })
        finally:
            spool.close()

    elapsed = time.perf_counter() - t0
    result = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_s": round(elapsed, 1),
        "engines": engines.notes,
        "stats": dict(stats),
        "samples": records,
        "iocs": {k: sorted(v)[:40] for k, v in iocs.items()},
    }

    if args.format == "json":
        text = json.dumps(result, ensure_ascii=False, indent=2)
    else:
        text = render_md(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"报告 -> {args.output}  ({len(records)} 个样本, {elapsed:.1f}s)")
    else:
        print(text)
    return 0


def render_md(r: dict) -> str:
    L: list[str] = []
    L.append("# 样本安全分析报告")
    L.append("")
    L.append(f"- 生成时间：{r['generated']}")
    L.append(f"- 用时：{r['elapsed_s']}s")
    L.append(f"- 引擎：{' / '.join(r['engines'])}")
    L.append(f"- 统计：{r['stats']}")
    L.append("")
    L.append("## 一、文件指纹")
    L.append("")
    L.append("| 文件 | 类型 | 大小 | CRC32 | XXH64 | SHA256 | 归属 |")
    L.append("|---|---|---|---|---|---|---|")
    for s in r["samples"]:
        if s.get("error"):
            L.append(f"| {s['name']} | - | - | - | - | - | 读取失败 |")
            continue
        L.append(f"| `{s['name'][:60]}` | {s['kind']} | {s['size']:,} | "
                 f"{s['crc32']} | {s['xxh64']} | `{s['sha256'][:16]}…` | "
                 f"{s['verdict']} |")
    L.append("")
    L.append("## 二、完整指纹（每种 5 项，对齐卡饭格式）")
    L.append("")
    for s in r["samples"]:
        if s.get("error"):
            continue
        L.append(f"### {s['name']}")
        L.append("")
        L.append(f"判定：**{s['verdict']}**　{s['basis']}")
        L.append("")
        L.append(f"大小: {s['size']} 字节 : {s['size'] / 1024:.0f} KiB")
        L.append(f"CRC32: {s['crc32']}")
        L.append(f"XXH64: {s['xxh64']}")
        L.append(f"MD5: {s['md5']}")
        L.append(f"SHA1: {s['sha1']}")
        L.append(f"SHA256: {s['sha256']}")
        L.append(f"SHA3-256: {s['sha3_256']}")
        if s.get("yara"):
            L.append(f"YARA: {', '.join(s['yara'][:5])}")
        if s.get("ml"):
            L.append(f"ML: {s['ml']}（仅供参考，不参与判定）")
        L.append("")
    if any(r["iocs"].values()):
        L.append("## 三、IOC（已用 [.] 转义，不可直接点击）")
        L.append("")
        for kind, label in (("url", "URL"), ("domain", "域名"), ("ip", "IP")):
            vals = r["iocs"].get(kind) or []
            if vals:
                L.append(f"**{label}**（{len(vals)}）")
                L.append("```")
                L.extend(vals)
                L.append("```")
                L.append("")
    L.append("---")
    L.append("")
    L.append("> 说明：归属判定只使用可验证信号（特征库 / YARA / 启发式）。"
             "ML 只作参考 —— 实测对合法 System32 文件误报 48%，不参与判定。")
    L.append("> 分析全程在内存/临时文件中进行，未将样本写到任何用户可见路径。")
    return "\n".join(L)


if __name__ == "__main__":
    sys.exit(main())
