"""
扫描编排 —— 过滤 -> 哈希 -> 签名库 -> 字面量匹配 -> 启发式

设计原则
--------
1. **便宜的先做**：扩展名/大小过滤、哈希缓存命中，都在读盘和匹配之前。
2. **匹配交给原生引擎**：字面量匹配走 rtguard.matcher（Aho-Corasick，337 MB/s），
   不再使用纯 Python 的 YARA 复刻。
3. **无第三方依赖**：只用到标准库 + 本包模块。engine/ 里那套更重的扫描链路
   是另一个层次的东西，本模块刻意不依赖它，保证新版能独立跑起来。

已知取舍
--------
* YARA 的十六进制模式（`$a = { 4D 5A ?? }`）与正则模式（`$a = /re/`）**不参与匹配**，
  只提取双引号字面量。这两类模式在本规则集里占比很小。
* `nocase` 用「额外一组小写字面量 + 对 data.lower() 再扫一遍」实现，而不是
  去降低所有模式的大小写敏感度——后者会让全小写的普通规则误报。
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import time

from .matcher import PatternSet

__all__ = ["Scanner", "ScanResult", "RuleSet", "DEFAULT_EXTENSIONS"]

DEFAULT_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv",
    ".msi", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
    ".bat", ".cmd", ".jar", ".zip", ".7z", ".rar", ".doc", ".docm",
    ".xls", ".xlsm", ".pdf", ".lnk", ".py", ".php", ".asp",
}

# 内存/注入/持久化相关 API —— 只用字符串命中，不解析导入表
SUSPICIOUS_APIS = (
    b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
    b"NtUnmapViewOfSection", b"SetWindowsHookEx", b"QueueUserAPC",
    b"ZwMapViewOfSection", b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent",
    b"CryptEncrypt", b"WNetAddConnection2", b"ShellExecuteEx",
    b"RegSetValueEx", b"CreateProcessWithLogonW",
)

_STR_DEF = re.compile(r'\$(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"([^\n]*)')
_RULE_HDR = re.compile(r'(?:^|\n)\s*(?:private\s+|global\s+)?rule\s+(\w+)\s*(?::\s*[\w\s]+)?\{')
_META = re.compile(r'(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"')
_ESC = {"n": b"\n", "r": b"\r", "t": b"\t", "\\": b"\\", '"': b'"', "0": b"\x00"}


def _unescape(raw: str) -> bytes:
    """把 YARA 字符串字面量转成 bytes（处理 \\xNN \\n \\t \\\\ \\" ）"""
    out = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c != "\\" or i + 1 >= n:
            out += c.encode("utf-8", "ignore") if ord(c) < 128 else c.encode("utf-8")
            i += 1
            continue
        nxt = raw[i + 1]
        if nxt == "x" and i + 3 < n:
            try:
                out.append(int(raw[i + 2:i + 4], 16))
                i += 4
                continue
            except ValueError:
                pass
        out += _ESC.get(nxt, nxt.encode("ascii", "ignore"))
        i += 2
    return bytes(out)


class RuleSet:
    """从 .yar / .yara 目录抽取字面量，构建匹配集合

    min_literal_len
        丢弃长度小于该值的字面量。规则集里存在 `js` / `exe` / `ftp` / `vbs`
        这类 2~5 字节的短串（实测 1153 个字面量里有 51 个 <=4 字节），
        它们在任意数据上都会命中——8 MB 纯随机数据就能误报出
        `WinRAR_ADS_Traversal`、`AndroRAT_Version_Identity` 这类规则。
        默认 6 是经验值：再短就没有鉴别力，只会制造噪声。
    """

    def __init__(self, rules_dir: str, min_literal_len: int = 6):
        self.rules_dir = rules_dir
        self.min_literal_len = max(1, int(min_literal_len))
        self.rules = {}            # 规则名 -> {description, category, source}
        self.cs_patterns = []      # 大小写敏感字面量
        self.ci_patterns = []      # nocase 字面量（存小写形式）
        self.cs_owner = []         # 下标 -> 规则名
        self.ci_owner = []
        self.files = 0
        self.dropped = 0           # 因过短被丢弃的字面量数
        self.parse_errors = []
        self._load()
        self._cs = None
        self._ci = None

    def _load(self):
        for root, _dirs, files in os.walk(self.rules_dir):
            for fname in sorted(files):
                if not (fname.endswith(".yar") or fname.endswith(".yara")):
                    continue
                path = os.path.join(root, fname)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                except Exception as exc:
                    self.parse_errors.append("%s: %s" % (fname, exc))
                    continue
                self.files += 1
                self._parse(text, fname)

    def _parse(self, text: str, fname: str):
        headers = list(_RULE_HDR.finditer(text))
        for idx, m in enumerate(headers):
            name = m.group(1)
            start = m.end()
            end = headers[idx + 1].start() if idx + 1 < len(headers) else len(text)
            body = text[start:end]
            # 只取 strings: 段，避免把 condition 里的字符串常量当成模式
            sm = re.search(r'(?m)^\s*strings\s*:', body)
            if not sm:
                continue
            cm = re.search(r'(?m)^\s*condition\s*:', body)
            seg = body[sm.end(): cm.start() if cm else len(body)]
            meta = {}
            mm = re.search(r'(?m)^\s*meta\s*:', body)
            if mm:
                meta_seg = body[mm.end(): sm.start()]
                for k, v in _META.findall(meta_seg):
                    meta[k] = v
            self.rules[name] = {
                "description": meta.get("description", meta.get("malware", name)),
                "category": (meta.get("malware_type") or meta.get("category") or "unknown").lower(),
                "source": fname,
            }
            for _var, lit, flags in _STR_DEF.findall(seg):
                if not lit:
                    continue
                value = _unescape(lit)
                if not value:
                    continue
                # 过短的字面量没有鉴别力，只会制造误报
                if len(value) < self.min_literal_len:
                    self.dropped += 1
                    continue
                nocase = "nocase" in flags
                if nocase:
                    self.ci_patterns.append(value.lower())
                    self.ci_owner.append(name)
                else:
                    self.cs_patterns.append(value)
                    self.cs_owner.append(name)

    def build(self, prefer_native: bool = True):
        self._cs = PatternSet(self.cs_patterns, prefer_native=prefer_native) if self.cs_patterns else None
        self._ci = PatternSet(self.ci_patterns, prefer_native=prefer_native) if self.ci_patterns else None
        return self

    def backend(self) -> str:
        parts = []
        for ps in (self._cs, self._ci):
            if ps is not None:
                parts.append(ps.describe())
        return " | ".join(parts) if parts else "无模式"

    def scan(self, data: bytes):
        """返回 {规则名: [命中字面量数量]}"""
        hits = {}
        if self._cs is not None:
            for i in self._cs.scan(data):
                hits.setdefault(self.cs_owner[i], 0)
                hits[self.cs_owner[i]] += 1
        if self._ci is not None:
            lowered = data.lower()
            for i in self._ci.scan(lowered):
                hits.setdefault(self.ci_owner[i], 0)
                hits[self.ci_owner[i]] += 1
        return hits

    def close(self):
        for ps in (self._cs, self._ci):
            if ps is not None:
                ps.close()


class ScanResult:
    __slots__ = ("path", "size", "sha256", "verdict", "threats", "elapsed", "error", "layers")

    def __init__(self, path, size=0, sha256="", verdict="clean"):
        self.path = path
        self.size = size
        self.sha256 = sha256
        self.verdict = verdict         # clean | suspicious | malicious | error | skipped
        self.threats = []
        self.elapsed = 0.0
        self.error = ""
        self.layers = {}               # 各阶段耗时，便于诊断

    def to_dict(self):
        return {
            "path": self.path, "size": self.size, "sha256": self.sha256,
            "verdict": self.verdict, "threats": self.threats,
            "elapsed_ms": round(self.elapsed * 1000, 2),
            "error": self.error, "layers": self.layers,
        }

    def __repr__(self):
        return "<ScanResult %s %s threats=%d %.1fms>" % (
            os.path.basename(self.path or "?"), self.verdict, len(self.threats),
            self.elapsed * 1000)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


class Scanner:
    def __init__(self, rules_dir: str, extensions=None, max_bytes=64 * 1024 * 1024,
                 cache_size=20000, prefer_native=True, min_literal_len=6):
        self.rules_dir = rules_dir
        self.extensions = set(extensions) if extensions else set(DEFAULT_EXTENSIONS)
        self.max_bytes = max_bytes
        self.cache_size = cache_size
        self.ruleset = RuleSet(rules_dir, min_literal_len=min_literal_len).build(
            prefer_native=prefer_native)
        self._cache = {}               # sha256 -> verdict
        self.stats = {"scanned": 0, "skipped": 0, "cache_hits": 0, "malicious": 0,
                      "suspicious": 0, "errors": 0, "bytes": 0}

    # ── 对外 ──
    def scan_file(self, path: str) -> ScanResult:
        t0 = time.perf_counter()
        res = ScanResult(path)
        try:
            st = os.stat(path)
        except OSError as exc:
            res.verdict = "error"; res.error = str(exc)
            return res
        res.size = st.st_size

        ext = os.path.splitext(path)[1].lower()
        if self.extensions and ext not in self.extensions:
            res.verdict = "skipped"; res.error = "扩展名不在扫描范围"
            self.stats["skipped"] += 1
            return res
        if res.size == 0:
            res.verdict = "skipped"; res.error = "空文件"
            self.stats["skipped"] += 1
            return res
        if res.size > self.max_bytes:
            res.verdict = "skipped"; res.error = "超过大小上限 %d" % self.max_bytes
            self.stats["skipped"] += 1
            return res

        t = time.perf_counter()
        try:
            with open(path, "rb") as fh:
                data = fh.read(self.max_bytes)
        except OSError as exc:
            res.verdict = "error"; res.error = str(exc)
            self.stats["errors"] += 1
            return res
        res.layers["read_ms"] = round((time.perf_counter() - t) * 1000, 2)

        self._scan_data(data, res)
        res.elapsed = time.perf_counter() - t0
        self.stats["scanned"] += 1
        self.stats["bytes"] += len(data)
        return res

    def scan_bytes(self, data: bytes, path: str = "") -> ScanResult:
        t0 = time.perf_counter()
        res = ScanResult(path)
        res.size = len(data)
        self._scan_data(data[:self.max_bytes], res)
        res.elapsed = time.perf_counter() - t0
        return res

    # ── 内部分层 ──
    def _scan_data(self, data: bytes, res: ScanResult):
        t = time.perf_counter()
        res.sha256 = hashlib.sha256(data).hexdigest()
        res.layers["hash_ms"] = round((time.perf_counter() - t) * 1000, 2)

        cached = self._cache.get(res.sha256)
        if cached is not None:
            self.stats["cache_hits"] += 1
            res.verdict = cached
            res.layers["cache"] = True
            return

        t = time.perf_counter()
        hits = self.ruleset.scan(data)
        res.layers["match_ms"] = round((time.perf_counter() - t) * 1000, 2)

        for name, count in hits.items():
            info = self.ruleset.rules.get(name, {})
            res.threats.append({
                "rule": name,
                "category": info.get("category", "unknown"),
                "description": info.get("description", name),
                "source": info.get("source", ""),
                "matched_literals": count,
                "engine": "aho-corasick",
            })

        t = time.perf_counter()
        heur = self._heuristics(data, res)
        res.layers["heuristic_ms"] = round((time.perf_counter() - t) * 1000, 2)
        if heur:
            res.threats.append(heur)

        if any(x.get("severity") == "high" for x in res.threats):
            res.verdict = "malicious"
            self.stats["malicious"] += 1
        elif res.threats:
            res.verdict = "suspicious"
            self.stats["suspicious"] += 1
        else:
            res.verdict = "clean"

        if len(self._cache) >= self.cache_size:
            self._cache.clear()
        self._cache[res.sha256] = res.verdict

    def _heuristics(self, data: bytes, res: ScanResult):
        """无依赖启发式：PE 特征 + 熵 + 敏感 API 字符串"""
        if not data.startswith(b"MZ"):
            return None
        score = []
        # 直接找 PE 签名（比解析 e_lfanew 稳）
        pe_off = data.find(b"PE\x00\x00", 0, 4096)
        if pe_off < 0:
            return None
        score.append("PE 文件")
        ent = _entropy(data[:262144])
        if ent > 7.2:
            score.append("高熵头 %.2f（可能加壳）" % ent)
        found = [api.decode() for api in SUSPICIOUS_APIS if api in data]
        if found:
            score.append("敏感 API: " + ", ".join(found[:5]))
        if len(found) >= 3 or ent > 7.5:
            return {
                "rule": "HEUR.PE.Suspicious",
                "category": "suspicious",
                "description": "; ".join(score),
                "source": "heuristic",
                "matched_literals": len(found),
                "engine": "heuristic",
                "severity": "high" if len(found) >= 4 else "medium",
            }
        if found:
            return {
                "rule": "HEUR.PE.API",
                "category": "suspicious",
                "description": "; ".join(score),
                "source": "heuristic",
                "matched_literals": len(found),
                "engine": "heuristic",
                "severity": "low",
            }
        return None

    def close(self):
        self.ruleset.close()
