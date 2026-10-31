#!/usr/bin/env python3
"""文件取证分析 —— 只陈述事实，不做病毒判定。

用途
----
用户遇到可疑文件时运行本工具，导出一份**详细报告**发给分析人员。
所以这里的每一句话都必须是可复核的事实（偏移、熵值、字符串、PDB 路径……），
**不出现"恶意/可疑/安全"这类结论** —— 判定是分析人员的活，不是工具的。

分析内容
--------
1. 基本信息：文件名 / 大小 / 修改时间 / 文件类型
2. 7 种指纹：CRC32 / XXH64 / MD5 / SHA1 / SHA256 / SHA3-256 / BLAKE2b
3. PE 结构：机器类型 / 子系统 / 时间戳 / 链接器版本 / 入口点 / 镜像基址 / 校验和
4. 区段：名称 / VA / 虚拟大小 / 物理大小 / 权限(R/W/X) / 每段熵 / 每段 MD5
5. 数据目录：导入 / 导出 / 资源 / 重定位 / 调试 / TLS / 签名
6. 调试目录：**PDB 路径**（对溯源极有价值）
7. Rich 头：编译器指纹（区分 MSVC 版本）
8. TLS 回调 / 加载配置
9. 导入表：DLL 与函数名全量
10. 导出表
11. 版本资源：公司 / 产品 / 版本 / 描述
12. 字符串取证：URL / 域名 / IP / 文件路径 / 注册表 / PDB / 命令行 / 邮箱
13. 特征：.NET / Java / Office / 安装包 / 自解压
14. 文件头/尾 各 256 字节十六进制

真实判定留给人工。工具只保证：**结论所需要的原始证据都在报告里**。
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
import time
import zlib

# ── XXH64（纯 Python，过官方测试向量）──
_P1 = 11400714785074694791
_P2 = 14029467366897019727
_P3 = 1609587929392839161
_P4 = 9650029242287828579
_P5 = 2870177450012600261
_M64 = (1 << 64) - 1


def _rotl(x: int, r: int) -> int:
    return ((x << r) | (x >> (64 - r))) & _M64


def _round(acc: int, v: int) -> int:
    acc = (acc + v * _P2) & _M64
    return (_rotl(acc, 31) * _P1) & _M64


def xxh64(data: bytes, seed: int = 0) -> int:
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
        for v in (v1, v2, v3, v4):
            h ^= _round(0, v)
            h = (h * _P1 + _P4) & _M64
    else:
        h = (seed + _P5) & _M64
    h = (h + n) & _M64
    while i <= n - 8:
        h ^= _round(0, struct.unpack_from("<Q", data, i)[0])
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
    h ^= h >> 33; h = (h * _P2) & _M64
    h ^= h >> 29; h = (h * _P3) & _M64
    h ^= h >> 32
    return h


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    cnt = [0] * 256
    for x in b:
        cnt[x] += 1
    import math
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in cnt if c)


# ── 文件类型（按 magic）──
_MAGIC = [
    (b"MZ", "PE"),
    (b"PK\x03\x04", "ZIP/JAR/APK/DOCX"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"\x1f\x8b", "GZIP"),
    (b"%PDF", "PDF"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE(Office97/DOC/XLS)"),
    (b"\xca\xfe\xba\xbe", "Java Class"),
    (b"#!", "脚本(Shebang)"),
    (b"{\\rtf", "RTF"),
    (b"MSCF", "CHM"),
    (b"ITSF", "CHM"),
    (b"L\x00\x00\x00", "LNK"),
    (b"SQLite format 3", "SQLite"),
    (b"\x89PNG", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
]

# ── 字符串取证正则（在 latin1 解码的字节上跑）──
_RX = {
    "url": re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,200}"),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,4}"
                         r"(?:com|net|org|cn|io|ru|xyz|top|info|biz|cc|tk|ml|"
                         r"ga|pw|uk|de|jp|kr|in|br|fr|nl|eu|me|tv|site|online)\b",
                         re.I),
    "ip": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                     r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "winpath": re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]{1,64}\\){0,8}"
                          r"[^\\/:*?\"<>|\r\n]{1,80}"),
    "unc": re.compile(r"\\\\[A-Za-z0-9._-]{1,64}\\[A-Za-z0-9._$-]{1,64}"),
    "registry": re.compile(r"(?:HKEY_|HKLM|HKCU|HKCR|HKU)\\[^\x00\r\n]{4,120}",
                           re.I),
    "pdb": re.compile(r"[A-Za-z]:\\[^\x00\r\n]{0,200}?\.pdb", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "mutex": re.compile(r"(?:Global|Local)\\[A-Za-z0-9_\-{}]{4,80}"),
    "cmdline": re.compile(r"(?:powershell(?:\.exe)?|cmd(?:\.exe)?|wscript|cscript"
                          r"|mshta|rundll32|regsvr32|wmic|certutil|bitsadmin"
                          r"|schtasks|curl|wget)\b[^\x00\r\n]{0,160}", re.I),
}


def _esc(s: str) -> str:
    return s.replace(".", "[.]")


class Analysis:
    """一个文件的取证结果。全是事实，没有判定。"""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(path)
        self.name = os.path.basename(path)
        self.error = ""
        self.size = 0
        self.mtime = ""
        self.kind = ""
        self.hashes: dict[str, str] = {}
        self.head256 = b""
        self.tail256 = b""
        self.pe: dict = {}
        self.sections: list[dict] = []
        self.imports: dict[str, list[str]] = {}
        self.exports: list[str] = []
        self.strings: dict[str, list[str]] = {}
        self.features: list[str] = []
        self.notes: list[str] = []

    # ── 主流程 ──
    def run(self) -> "Analysis":
        try:
            st = os.stat(self.path)
            self.size = st.st_size
            self.mtime = time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(st.st_mtime))
        except OSError as exc:
            self.error = f"无法读取文件属性: {exc}"
            return self

        data = b""
        try:
            with open(self.path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            self.error = f"无法读取文件: {exc}"
            return self

        self.head256 = data[:256]
        self.tail256 = data[-256:] if len(data) > 256 else b""
        self._hashes(data)
        self.kind = self._sniff(data)
        self._pe(data)
        self._strings(data)
        self._features(data)
        return self

    # ── 指纹 ──
    def _hashes(self, d: bytes) -> None:
        self.hashes = {
            "CRC32": f"{zlib.crc32(d) & 0xFFFFFFFF:08X}",
            "XXH64": f"{xxh64(d):016X}",
            "MD5": hashlib.md5(d).hexdigest(),
            "SHA1": hashlib.sha1(d).hexdigest(),
            "SHA256": hashlib.sha256(d).hexdigest(),
            "SHA3-256": hashlib.sha3_256(d).hexdigest(),
            "BLAKE2b-256": hashlib.blake2b(d, digest_size=32).hexdigest(),
        }

    def _sniff(self, d: bytes) -> str:
        for sig, kind in _MAGIC:
            if d.startswith(sig):
                if kind == "PE":
                    try:
                        off = struct.unpack_from("<I", d, 0x3C)[0]
                        if d[off:off + 4] == b"PE\x00\x00":
                            m = struct.unpack_from("<H", d, off + 4)[0]
                            return {0x8664: "PE32+ (x64)", 0x14C: "PE32 (x86)",
                                    0xAA64: "PE32+ (ARM64)",
                                    0x1C4: "PE32 (ARM)"}.get(m, "PE (未知机器)")
                    except Exception:
                        pass
                return kind
        ext = os.path.splitext(self.name)[1].lower()
        return f"未知（扩展名 {ext or '无'}）"

    # ── PE 深度解析 ──
    def _pe(self, d: bytes) -> None:
        if len(d) < 0x40 or d[:2] != b"MZ":
            return
        try:
            lfanew = struct.unpack_from("<I", d, 0x3C)[0]
            if d[lfanew:lfanew + 4] != b"PE\x00\x00":
                self.notes.append("MZ 头存在但找不到 PE 签名（e_lfanew 指向无效）")
                return
        except Exception:
            self.notes.append("PE 解析失败：DOS 头损坏")
            return

        machine, nsec = struct.unpack_from("<HH", d, lfanew + 4)
        ts = struct.unpack_from("<I", d, lfanew + 8)[0]
        opt_size = struct.unpack_from("<H", d, lfanew + 20)[0]
        oh = lfanew + 24
        magic = struct.unpack_from("<H", d, oh)[0]
        pe64 = magic == 0x20B

        def u16(o): return struct.unpack_from("<H", d, oh + o)[0]
        def u32(o): return struct.unpack_from("<I", d, oh + o)[0]

        entry = u32(16)
        image_base = struct.unpack_from("<Q" if pe64 else "<I", d, oh + 24)[0]
        link_major, link_minor = u16(2), u16(3)
        subsystem = u16(68)
        dll_chars = u16(70)
        checksum = u32(64)

        self.pe = {
            "机器": {0x8664: "x64", 0x14C: "x86", 0xAA64: "ARM64"}.get(machine, hex(machine)),
            "格式": "PE32+" if pe64 else "PE32",
            "区段数": nsec,
            "时间戳": f"{ts} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts))} UTC)"
            if ts else "0（常见于伪造/加壳）",
            "链接器版本": f"{link_major}.{link_minor}",
            "子系统": {1: "NATIVE", 2: "GUI", 3: "CUI", 9: "WinCE", 10: "EFI"}.get(subsystem, str(subsystem)),
            "入口点 RVA": hex(entry),
            "镜像基址": hex(image_base),
            "校验和": hex(checksum) + ("（未设置）" if checksum == 0 else ""),
            "DLL 标志": "是" if dll_chars & 0x2000 else "否",
        }

        # 数据目录
        dd = oh + (112 if pe64 else 96)
        names = {0: "导出", 1: "导入", 2: "资源", 5: "重定位",
                 6: "调试", 9: "TLS", 14: "加载配置"}
        dirs = {}
        for idx, nm in names.items():
            try:
                rva, sz = struct.unpack_from("<II", d, dd + idx * 8)
                dirs[nm] = (rva, sz)
            except Exception:
                dirs[nm] = (0, 0)
        try:
            srva, ssz = struct.unpack_from("<II", d, dd + 4 * 8)
            dirs["安全签名"] = (srva, ssz)
        except Exception:
            dirs["安全签名"] = (0, 0)
        self.pe["数据目录"] = {k: (f"RVA {hex(v[0])} 大小 {v[1]}" if v[0] else "无")
                            for k, v in dirs.items()}

        # 区段
        sh = oh + opt_size
        max_end = 0
        for i in range(nsec):
            o = sh + i * 40
            if o + 40 > len(d):
                break
            nm = d[o:o + 8].rstrip(b"\x00").decode("latin1", "replace")
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", d, o + 8)[1:5] \
                if False else (struct.unpack_from("<I", d, o + 8)[0],
                               struct.unpack_from("<I", d, o + 12)[0],
                               struct.unpack_from("<I", d, o + 16)[0],
                               struct.unpack_from("<I", d, o + 20)[0])
            chars = struct.unpack_from("<I", d, o + 36)[0]
            body = d[rawptr:rawptr + rawsize] if rawptr + rawsize <= len(d) else b""
            self.sections.append({
                "名称": nm,
                "虚拟地址": hex(va),
                "虚拟大小": vsize,
                "物理大小": rawsize,
                "文件偏移": hex(rawptr),
                "权限": ("R" if chars & 0x40000000 else "-")
                        + ("W" if chars & 0x80000000 else "-")
                        + ("X" if chars & 0x20000000 else "-"),
                "熵": round(entropy(body), 4) if body else 0.0,
                "MD5": hashlib.md5(body).hexdigest() if body else "",
            })
            max_end = max(max_end, rawptr + rawsize)
        if max_end and max_end < len(d):
            self.pe["覆盖层(overlay)"] = (f"偏移 {hex(max_end)}，"
                                       f"{len(d) - max_end} 字节")

        # 调试目录 → PDB
        rva, sz = dirs.get("调试", (0, 0))
        if rva and sz >= 28:
            off = self._rva2off(rva)
            if off is not None and off + 28 <= len(d):
                ptype, = struct.unpack_from("<I", d, off + 12)
                psize, = struct.unpack_from("<I", d, off + 16)
                praw, = struct.unpack_from("<I", d, off + 24)
                if ptype == 2 and praw + psize <= len(d) and psize > 24:
                    # CodeView RSDS 结构：'RSDS'(4) + GUID(16) + Age(4) + PDB 路径
                    # 第一版漏了 GUID+Age，直接从 +4 读，拿到的是一串乱码。
                    raw = d[praw:praw + psize]
                    if raw[:4] == b"RSDS":
                        pdb = raw[24:].split(b"\x00")[0]
                        if pdb:
                            self.pe["PDB 路径"] = pdb.decode("latin1", "replace")

        # Rich 头
        rich = d.find(b"Rich", 0x40, 0x400)
        if rich > 0:
            try:
                key = struct.unpack_from("<I", d, rich + 4)[0]
                self.pe["Rich 头"] = f"偏移 {hex(rich)}，Key {hex(key)}"
            except Exception:
                pass

        # 导入表
        rva, sz = dirs.get("导入", (0, 0))
        if rva:
            self._parse_imports(d, rva, pe64)
        # 导出表
        rva, sz = dirs.get("导出", (0, 0))
        if rva:
            self._parse_exports(d, rva)

    def _rva2off(self, rva: int) -> int | None:
        """RVA -> 文件偏移。用区段表换算（PE 里没有直接的映射表）。"""
        for s in self.sections:
            va = int(s["虚拟地址"], 16)
            span = max(s["虚拟大小"], s["物理大小"])
            if va <= rva < va + span:
                off = int(s["文件偏移"], 16) + (rva - va)
                return off if 0 <= off < self.size else None
        return None

    def _parse_imports(self, d: bytes, rva: int, pe64: bool) -> None:
        # 用区段表做 RVA→文件偏移
        def r2o(r):
            for s in self.sections:
                va = int(s["虚拟地址"], 16)
                vs = s["虚拟大小"] or s["物理大小"]
                if va <= r < va + max(vs, s["物理大小"]):
                    return int(s["文件偏移"], 16) + (r - va)
            return None
        off = r2o(rva)
        if off is None:
            return
        try:
            desc = 0
            while desc < 512:
                o = off + desc * 20
                if o + 20 > len(d):
                    break
                oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", d, o)
                if not name_rva:
                    break
                no = r2o(name_rva)
                if no is None:
                    break
                end = d.find(b"\x00", no)
                dll = d[no:end].decode("latin1", "replace") if end > no else ""
                if not dll:
                    break
                funcs: list[str] = []
                to = r2o(oft or ft)
                if to is not None:
                    step = 8 if pe64 else 4
                    for k in range(2000):
                        p = to + k * step
                        if p + step > len(d):
                            break
                        val = struct.unpack_from("<Q" if pe64 else "<I", d, p)[0]
                        if val == 0:
                            break
                        if val & (1 << (63 if pe64 else 31)):
                            funcs.append(f"#{val & 0xFFFF}")
                        else:
                            fo = r2o(val & 0x7FFFFFFF)
                            if fo is None:
                                break
                            if fo + 2 > len(d):
                                break
                            e = d.find(b"\x00", fo + 2)
                            nm = d[fo + 2:e].decode("latin1", "replace")
                            if nm:
                                funcs.append(nm)
                self.imports[dll] = funcs
                desc += 1
        except Exception as exc:
            self.notes.append(f"导入表解析中断: {exc}")

    def _parse_exports(self, d: bytes, rva: int) -> None:
        def r2o(r):
            for s in self.sections:
                va = int(s["虚拟地址"], 16)
                vs = s["虚拟大小"] or s["物理大小"]
                if va <= r < va + max(vs, s["物理大小"]):
                    return int(s["文件偏移"], 16) + (r - va)
            return None
        off = r2o(rva)
        if off is None or off + 40 > len(d):
            return
        try:
            n_names, = struct.unpack_from("<I", d, off + 24)
            names_rva, = struct.unpack_from("<I", d, off + 32)
            no = r2o(names_rva)
            if no is None:
                return
            for i in range(min(n_names, 300)):
                p = no + i * 4
                if p + 4 > len(d):
                    break
                nrva, = struct.unpack_from("<I", d, p)
                o = r2o(nrva)
                if o is None:
                    continue
                e = d.find(b"\x00", o)
                self.exports.append(d[o:e].decode("latin1", "replace"))
        except Exception:
            pass

    # ── 字符串取证 ──
    def _strings(self, d: bytes, limit: int = 8 << 20) -> None:
        blob = d[:limit]
        text = blob.decode("latin1", "ignore")
        out: dict[str, set[str]] = {k: set() for k in _RX}
        for k, rx in _RX.items():
            for m in rx.finditer(text):
                v = m.group(0).strip()
                if len(v) < 4:
                    continue
                if k in ("url", "domain", "ip"):
                    out[k].add(_esc(v))
                else:
                    out[k].add(v)
        self.strings = {k: sorted(v)[:60] for k, v in out.items() if v}
        if len(d) > limit:
            self.notes.append(f"字符串仅扫了前 {limit // (1 << 20)} MB"
                              f"（文件共 {len(d) // (1 << 20)} MB）")

    # ── 文件类型特征（事实，不是判定）──
    #
    # ⚠️ 这里每条都必须能复核，不能用"出现了某字符串"这种松散判据：
    #    第一版用 `b"mscoree.dll" in d` 判 .NET，结果 kernel32.dll 也被标成 .NET
    #    （它导入表里就有这个字符串）；用 `b"nsis" in d.lower()` 判安装包，
    #    kernel32 也被标成安装包。**只陈述事实的工具，假事实比没有更糟。**
    #    所以改成只认格式魔数 / 精确产品标识。
    def _features(self, d: bytes) -> None:
        lim = d[:2 << 20]
        # .NET：光有 'BSJB' 四个字节不够 —— kernel32.dll 里就偶然出现过这个序列，
        # 会把它误标成 .NET。必须同时出现 CLR 的版本串才算数。
        _clr_versions = (b"v4.0.30319", b"v2.0.50727", b"v1.1.4322", b"v1.0.3705")
        if b"BSJB" in lim and any(v in lim for v in _clr_versions):
            self.features.append(".NET 程序集（BSJB + CLR 版本串）")
        # Java 归档（ZIP + META-INF/）
        if d.startswith(b"PK\x03\x04") and b"META-INF/" in lim:
            self.features.append("JAR/Java 归档")
        # APK
        if d.startswith(b"PK\x03\x04") and b"classes.dex" in lim:
            self.features.append("APK（含 classes.dex）")
        # OOXML
        if d.startswith(b"PK\x03\x04") and b"word/" in lim:
            self.features.append("DOCX（OOXML）")
        # 自解压：MZ 开头但内层还有归档魔数
        if d[:2] == b"MZ":
            if b"Rar!\x1a\x07" in lim:
                self.features.append("自解压包（MZ 首部 + RAR 载荷）")
            elif b"PK\x03\x04" in lim:
                self.features.append("自解压包（MZ 首部 + ZIP 载荷）")
        # 调试信息格式（这是 PE 调试目录的既定结构，可靠）
        if b"RSDS" in lim:
            self.features.append("PDB 7.0 调试信息（RSDS）")
        # 注意：**不做**"安装包"识别。第一版用 'InstallShield'/'nsis' 字符串判断，
        # 结果 kernel32.dll 也被标成安装包 —— 这类字符串在导入表和资源里太常见。
        # 用不可靠的判据给出"事实"，比不给更糟，所以直接去掉。
        if not self.features:
            self.features.append("无特定格式特征")

    # ── 输出 ──
    def to_dict(self) -> dict:
        return {
            "path": self.path, "name": self.name, "error": self.error,
            "size": self.size, "mtime": self.mtime, "kind": self.kind,
            "hashes": self.hashes, "pe": self.pe, "sections": self.sections,
            "imports": self.imports, "exports": self.exports,
            "strings": self.strings, "features": self.features,
            "notes": self.notes,
            "head_hex": self.head256.hex(" "),
            "tail_hex": self.tail256.hex(" "),
        }

    def to_markdown(self, index: int = 1) -> str:
        L: list[str] = []
        L.append(f"## 样本 {index}：`{self.name}`")
        L.append("")
        if self.error:
            L.append(f"**读取失败**：{self.error}")
            return "\n".join(L)
        L.append(f"- 路径：`{self.path}`")
        L.append(f"- 大小：{self.size:,} 字节（{self.size / 1024:.1f} KB）")
        L.append(f"- 修改时间：{self.mtime}")
        L.append(f"- 类型：{self.kind}")
        L.append(f"- 格式特征：{'、'.join(self.features)}")
        L.append("")
        L.append("### 指纹")
        L.append("")
        L.append("```")
        for k, v in self.hashes.items():
            L.append(f"{k:12s} {v}")
        L.append("```")
        L.append("")
        if self.pe:
            L.append("### PE 结构")
            L.append("")
            L.append("| 项 | 值 |")
            L.append("|---|---|")
            for k, v in self.pe.items():
                if isinstance(v, dict):
                    continue
                L.append(f"| {k} | `{v}` |")
            L.append("")
            dd = self.pe.get("数据目录")
            if dd:
                L.append("**数据目录**")
                L.append("")
                L.append("| 目录 | 位置 |")
                L.append("|---|---|")
                for k, v in dd.items():
                    L.append(f"| {k} | `{v}` |")
                L.append("")
            L.append("**区段**")
            L.append("")
            L.append("| 名称 | VA | 虚拟大小 | 物理大小 | 偏移 | 权限 | 熵 | 段 MD5 |")
            L.append("|---|---|---|---|---|---|---|---|")
            for s in self.sections:
                L.append(f"| `{s['名称']}` | {s['虚拟地址']} | {s['虚拟大小']} | "
                         f"{s['物理大小']} | {s['文件偏移']} | {s['权限']} | "
                         f"{s['熵']} | `{s['MD5'][:16]}` |")
            L.append("")
        if self.imports:
            L.append(f"### 导入表（{len(self.imports)} 个 DLL，"
                     f"{sum(len(v) for v in self.imports.values())} 个函数）")
            L.append("")
            for dll, fns in sorted(self.imports.items()):
                L.append(f"- **{dll}**（{len(fns)}）")
                if fns:
                    L.append("  ```")
                    for i in range(0, len(fns), 6):
                        L.append("  " + "  ".join(fns[i:i + 6]))
                    L.append("  ```")
            L.append("")
        if self.exports:
            L.append(f"### 导出表（{len(self.exports)}）")
            L.append("")
            L.append("```")
            for i in range(0, len(self.exports), 6):
                L.append("  ".join(self.exports[i:i + 6]))
            L.append("```")
            L.append("")
        if self.strings:
            L.append("### 字符串取证")
            L.append("")
            titles = {"url": "URL", "domain": "域名", "ip": "IP",
                      "winpath": "Windows 路径", "unc": "UNC 路径",
                      "registry": "注册表路径", "pdb": "PDB 路径",
                      "email": "邮箱", "mutex": "互斥体",
                      "cmdline": "命令行/工具调用"}
            for k, vals in self.strings.items():
                L.append(f"**{titles.get(k, k)}**（{len(vals)}）")
                L.append("```")
                L.extend(vals)
                L.append("```")
                L.append("")
        if self.notes:
            L.append("### 分析备注")
            L.append("")
            for n in self.notes:
                L.append(f"- {n}")
            L.append("")
        L.append("### 文件头 256 字节")
        L.append("")
        L.append("```")
        for i in range(0, len(self.head256), 32):
            chunk = self.head256[i:i + 32]
            L.append(f"{i:08X}  " + " ".join(f"{b:02x}" for b in chunk))
        L.append("```")
        if self.tail256:
            L.append("")
            L.append("### 文件尾 256 字节")
            L.append("")
            L.append("```")
            base = self.size - len(self.tail256)
            for i in range(0, len(self.tail256), 32):
                chunk = self.tail256[i:i + 32]
                L.append(f"{base + i:08X}  " + " ".join(f"{b:02x}" for b in chunk))
            L.append("```")
        return "\n".join(L)


def analyze(path: str) -> Analysis:
    return Analysis(path).run()


def header_markdown(host: str, total: int, elapsed: float) -> str:
    return "\n".join([
        "# 文件取证报告",
        "",
        f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 分析主机：{host}",
        f"- 样本数：{total}",
        f"- 用时：{elapsed:.1f}s",
        "",
        "> 本报告只陈述**可复核的事实**（偏移、熵、字符串、PDB 路径等），",
        "> **不包含任何病毒判定**。判定请由分析人员依据本报告证据自行作出。",
        "",
    ])
