"""
御天 YARA 扫描器 —— **真 libyara 后端**（ctypes 绑定）

历史与动机
==========
本文件原来是**从零手写的 YARA 子集**（904 行，不依赖 libyara）。它把 condition
压缩成「类型 + N」的粗模型，导致大量语义偏差。用真 YARA 做对照实测，7 个用例里
错了 5 个：

    用例                          旧自制引擎      真 YARA
    "EvilMarker" nocase 全小写     漏报            命中
    "cat" fullword 对 concatenate  误报            不命中
    #a > 3 但只出现 1 次           误报            不命中
    "SecretKey" xor                漏报            命中
    { DE AD [4-6] BE EF }          漏报            命中
    /ab+c/ 对 abbbc                漏报            命中
    纯 filesize > 100              漏报            命中

其中**误报**对杀软最致命（用户看到的是"乱报毒"）。且项目 114 条规则里有
**70 条（61%）**用到了旧引擎未正确实现的特性。

现在改为调用自建的 `libyara.dll`（YARA 4.5.5，见 engine/native/yara/BUILD.md），
**匹配语义完全交给真 libyara**。

设计
====
* **匹配**：全部走 libyara（`yr_rules_scan_mem` / `yr_rules_scan_file`）。
* **元数据**：`YR_RULE` 只给规则名；`meta` 和字面量用一个轻量源码解析器抽取，
  **仅用于** `malware_type` / `description` / `rule_quality` 定档 / `matched_patterns`
  的报告 —— 不参与任何判定，所以它即使不完美也无害。
* **公开 API 与返回结构保持不变**，调用方（local_scanner / scheduler / sandbox /
  realtime_guard / deep_analyzer）无需改动。
"""

import os
import re
import sys
import ctypes
from ctypes import (POINTER, byref, cast, c_char_p, c_int, c_size_t, c_uint8,
                    c_void_p)

# ══════════════════════════════════════════════════════════════════════════
# libyara.dll 定位与加载
# ══════════════════════════════════════════════════════════════════════════

def _base_dir() -> str:
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # …/backend


def _libyara_candidates():
    base = _base_dir()
    here = os.path.dirname(os.path.abspath(__file__))
    return [
        os.path.join(base, "engine", "native", "yara", "libyara.dll"),
        os.path.join(here, "native", "yara", "libyara.dll"),
        os.path.join(base, "engine", "native_guard", "libyara.dll"),
        os.path.join(base, "libyara.dll"),
    ]


_lib = None
_lib_error = ""


def _load_lib():
    """加载 libyara.dll（进程内单例）。失败抛 RuntimeError。"""
    global _lib, _lib_error
    if _lib is not None:
        return _lib
    last = ""
    for p in _libyara_candidates():
        if not os.path.isfile(p):
            continue
        try:
            lib = ctypes.CDLL(p)
        except OSError as e:
            last = f"{p}: {e}"
            continue
        try:
            _declare(lib)
            if lib.yr_initialize() != 0:
                last = f"{p}: yr_initialize 失败"
                continue
        except Exception as e:
            last = f"{p}: {type(e).__name__}: {e}"
            continue
        _lib = lib
        _lib.LIBYARA_PATH = p
        return _lib
    _lib_error = last or "未找到 libyara.dll（期望在 engine/native/yara/ 下）"
    raise RuntimeError(_lib_error)


def _declare(lib):
    """声明用到的 C 函数签名。"""
    lib.yr_initialize.restype = c_int
    lib.yr_finalize.restype = c_int

    lib.yr_compiler_create.argtypes = [POINTER(c_void_p)]
    lib.yr_compiler_create.restype = c_int
    lib.yr_compiler_destroy.argtypes = [c_void_p]
    lib.yr_compiler_add_string.argtypes = [c_void_p, c_char_p, c_char_p]
    lib.yr_compiler_add_string.restype = c_int
    lib.yr_compiler_get_rules.argtypes = [c_void_p, POINTER(c_void_p)]
    lib.yr_compiler_get_rules.restype = c_int
    lib.yr_compiler_get_error_message.argtypes = [c_void_p, c_char_p, c_int]
    lib.yr_compiler_get_error_message.restype = c_int

    lib.yr_rules_destroy.argtypes = [c_void_p]
    lib.yr_rules_scan_mem.argtypes = [c_void_p, POINTER(c_uint8), c_size_t, c_int,
                                      c_void_p, c_void_p, c_int]
    lib.yr_rules_scan_mem.restype = c_int
    lib.yr_rules_scan_file.argtypes = [c_void_p, c_char_p, c_int,
                                       c_void_p, c_void_p, c_int]
    lib.yr_rules_scan_file.restype = c_int


# ── 常量（取自 libyara/rules.h、scan.h）──
CALLBACK_MSG_RULE_MATCHING = 1
CALLBACK_MSG_RULE_NOT_MATCHING = 2
CALLBACK_MSG_SCAN_FINISHED = 3

SCAN_FLAGS_FAST_MODE = 1
SCAN_FLAGS_PROCESS_MEMORY = 2

CALLBACK_CONTINUE = 0

# YR_SCAN_CONTEXT 的回调签名：int (*)(ctx, int message, void* message_data, void* user_data)
YR_CALLBACK_FUNC = ctypes.CFUNCTYPE(c_int, c_void_p, c_int, c_void_p, c_void_p)

# struct YR_RULE（64 位，DECLARE_REFERENCE 即普通指针）：
#   int32 flags; int32 num_atoms; uint32 required_strings; uint32 unused;
#   const char* identifier;  <- 偏移 16
YR_RULE_IDENTIFIER_OFFSET = 16

# 单次扫描最多返回多少条命中（防御性上限）
_MAX_MATCHES = 512
# scan_file 跳过的大小区间（与旧实现一致）
_MAX_FILE_SIZE = 200 * 1024 * 1024


# ══════════════════════════════════════════════════════════════════════════
# 规则模型（接口与旧版保持一致）
# ══════════════════════════════════════════════════════════════════════════

class YaraRule:
    """单条 YARA 规则（元数据视图；匹配由 libyara 负责）"""

    def __init__(self, name: str, source_file: str = ""):
        self.name = name
        self.source_file = source_file
        self.meta: dict = {}
        self.strings: list = []        # [(name, bytes, 'ascii'|'wide')]
        self.hex_patterns: list = []   # [(name, mask_bytes, pattern_bytes)]
        self.regexes: list = []        # [(name, pattern_str, flags_str)]
        self.condition_raw: str = ""
        self.condition_type: str = "any"   # any / all / N / custom
        self.condition_n: int = 1
        self.namespace: str = ""
        # {字符串名: 修饰符文本}，供 matched_patterns 报告用（载入时算一次，
        # 避免每次命中去重读规则源文件）
        self.flags_map: dict = {}
        # engine.rule_quality 的定档结果，load_rules 末尾统一算
        self.quality: dict | None = None

    @property
    def total_patterns(self) -> int:
        return len(self.strings) + len(self.hex_patterns) + len(self.regexes)

    @property
    def malware_type(self) -> str:
        mt = self.meta.get("malware_type", self.meta.get("category", "UNKNOWN"))
        return str(mt).upper()

    @property
    def description(self) -> str:
        return str(self.meta.get("description", self.meta.get("malware", self.name)))


# ══════════════════════════════════════════════════════════════════════════
# 规则源码轻量解析（**仅取元数据与字面量，不参与判定**）
# ══════════════════════════════════════════════════════════════════════════

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def _strip_comments(text: str) -> str:
    """去掉注释，但保护字符串字面量与正则里的 // 与 /*。"""
    out = []
    i, n = 0, len(text)
    in_str = in_re = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 2; continue
            if ch == '"':
                in_str = False
            i += 1; continue
        if in_re:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 2; continue
            if ch == "/":
                in_re = False
            i += 1; continue
        if ch == '"':
            in_str = True; out.append(ch); i += 1; continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        out.append(ch); i += 1
    return "".join(out)


def _iter_rule_blocks(text: str):
    """产出 (rule_name, body_text)。用花括号配平切块，跳过字符串/正则内容。"""
    for m in re.finditer(r"\brule\s+([A-Za-z_]\w*)", text):
        name = m.group(1)
        i = m.end()
        # 跳过 tags（`: tag1 tag2`）与空白，找第一个 '{'
        while i < len(text) and text[i] in " \t\r\n":
            i += 1
        if i < len(text) and text[i] == ":":
            j = text.find("{", i)
            if j < 0:
                continue
            i = j
        if i >= len(text) or text[i] != "{":
            continue
        depth, k = 0, i
        in_str = in_re = False
        while k < len(text):
            c = text[k]
            if in_str:
                if c == "\\":
                    k += 2; continue
                if c == '"':
                    in_str = False
            elif in_re:
                if c == "\\":
                    k += 2; continue
                if c == "/":
                    in_re = False
            else:
                if c == '"':
                    in_str = True
                elif c == "/":
                    in_re = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        yield name, text[i + 1:k]
                        break
            k += 1


def _section(body: str, start_kw: str, stop_kws) -> str:
    """取出 body 中 `start_kw:` 到下一个 stop 关键字之间的文本。"""
    m = re.search(r"\b" + start_kw + r"\s*:", body)
    if not m:
        return ""
    s = m.end()
    e = len(body)
    for kw in stop_kws:
        mm = re.search(r"\b" + kw + r"\s*:", body[s:])
        if mm:
            e = min(e, s + mm.start())
    return body[s:e]


def _parse_meta(body: str) -> dict:
    txt = _section(body, "meta", ("strings", "condition"))
    meta = {}
    for m in re.finditer(r'([A-Za-z_]\w*)\s*=\s*("(?:[^"\\]|\\.)*"|true|false|-?\d+)',
                         txt):
        k, v = m.group(1), m.group(2)
        if v.startswith('"'):
            v = v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        elif v == "true":
            v = True
        elif v == "false":
            v = False
        else:
            try:
                v = int(v)
            except ValueError:
                pass
        meta[k] = v
    return meta


_HEX_TOKEN = re.compile(r"\?\?|\?[0-9A-Fa-f]|[0-9A-Fa-f]{2}|\[[^\]]*\]|\(|\||\)")


def _parse_hex(hex_body: str):
    """编译期只做**报告用**的近似解析；匹配本身由 libyara 负责。

    跳过 `[n-m]` 跳转与 `(a|b)` 选择（把它们记为通配），仅供 matched_patterns 展示。
    """
    mask = bytearray()
    pat = bytearray()
    approx = False
    for tok in _HEX_TOKEN.findall(hex_body):
        if tok in ("(", "|", ")"):
            approx = True
            continue
        if tok.startswith("["):
            approx = True
            continue
        if tok == "??":
            mask.append(0); pat.append(0); continue
        if tok.startswith("?"):
            try:
                v = int(tok[1:], 16) & 0xF
            except ValueError:
                mask.append(0); pat.append(0); approx = True; continue
            mask.append(0xF0); pat.append(v << 4); continue
        try:
            mask.append(0xFF); pat.append(int(tok, 16))
        except ValueError:
            mask.append(0); pat.append(0); approx = True
    return bytes(mask), bytes(pat), approx


_ESC = {"n": 10, "t": 9, "r": 13, "\\": 92, '"': 34, "0": 0}


def _unescape_yara(s: str) -> bytes:
    """按 YARA 的转义规则把字符串字面量转成字节。"""
    out = bytearray()
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            d = s[i + 1]
            if d == "x" and i + 3 < n:
                try:
                    out.append(int(s[i + 2:i + 4], 16)); i += 4; continue
                except ValueError:
                    pass
            if d in _ESC:
                out.append(_ESC[d]); i += 2; continue
            out.extend(d.encode("utf-8", "ignore")); i += 2; continue
        out.extend(c.encode("utf-8", "ignore")); i += 1
    return bytes(out)


def _parse_strings(body: str):
    """返回 (strings, hex_patterns, regexes, literals)。仅供元数据/报告使用。"""
    txt = _section(body, "strings", ("condition",))
    strings, hexes, regexes, lits = [], [], [], []
    for m in re.finditer(
            r'(\$[A-Za-z_]\w*|\$)\s*=\s*("(?:[^"\\]|\\.)*"|\{.*?\}|/(?:[^/\\\n]|\\.)*/)([^\n]*)',
            txt, re.S):
        name = m.group(1)
        val = m.group(2)
        flags = (m.group(3) or "").strip().lower()
        if val.startswith('"'):
            raw = val[1:-1]
            raw_b = _unescape_yara(raw)
            # YARA 语义：无 wide → 仅 ascii；有 wide 无 ascii → 仅 wide；
            # `wide ascii` → 两者都生成。
            want_wide = "wide" in flags
            want_ascii = ("ascii" in flags) or (not want_wide)
            if want_wide:
                strings.append((name, raw_b.decode("latin1").encode("utf-16-le"), "wide"))
            if want_ascii:
                strings.append((name, raw_b, "ascii"))
            lits.append(raw_b.decode("latin1", "ignore"))
        elif val.startswith("{"):
            mask, pat, approx = _parse_hex(val[1:-1])
            if pat:
                hexes.append((name, mask, pat))
                run = bytearray()
                for i in range(len(mask)):
                    if mask[i] == 0xFF:
                        run.append(pat[i])
                    else:
                        if len(run) >= 4:
                            lits.append(run.decode("latin1"))
                        run = bytearray()
                if len(run) >= 4:
                    lits.append(run.decode("latin1"))
        else:  # 正则
            regexes.append((name, val[1:-1], flags))
            lits.append(val[1:-1])
    return strings, hexes, regexes, lits


def _parse_flags(body: str) -> dict:
    """{字符串名: 修饰符文本}（nocase / wide / ascii / fullword / xor ...）。"""
    txt = _section(body, "strings", ("condition",))
    flags = {}
    for m in re.finditer(
            r'(\$[A-Za-z_]\w*|\$)\s*=\s*("(?:[^"\\]|\\.)*"|\{.*?\}|/(?:[^/\\\n]|\\.)*/)([^\n]*)',
            txt, re.S):
        flags[m.group(1)] = (m.group(3) or "").strip().lower()
    return flags


def _classify_condition(body: str):
    """粗分 any / all / N / custom —— 只喂给 rule_quality 定档用。"""
    cond = _section(body, "condition", ()).strip()
    low = cond.lower()
    if re.search(r"\ball\s+of\s+them\b", low):
        return cond, "all", -1
    if re.search(r"\bany\s+of\s+them\b", low):
        return cond, "any", 1
    m = re.search(r"\b(\d+)\s+of\s+them\b", low)
    if m:
        return cond, "N", int(m.group(1))
    if re.search(r"\ball\s+of\s+\(", low):
        return cond, "all", -1
    m = re.search(r"\b(\d+)\s+of\s+\(", low)
    if m:
        return cond, "N", int(m.group(1))
    if re.search(r"\$[A-Za-z_]\w*\s+and\s+\$", low):
        return cond, "all", -1
    if re.search(r"\$[A-Za-z_]\w*\s+or\s+\$", low):
        return cond, "any", 1
    return cond, "custom", 1


# ══════════════════════════════════════════════════════════════════════════
# 扫描器
# ══════════════════════════════════════════════════════════════════════════

class YaraScanner:
    """YARA 扫描器 —— 真 libyara 后端。

    保持与旧实现相同的公开 API：`rules` / `load_rules` / `scan_file` /
    `scan_content` / `scan_content_typed` / `rule_confidence`。
    另新增 `compile_errors`（哪些规则文件被真 YARA 拒绝）与 `libyara_path`。
    """

    def __init__(self, rules_dir: str = None):
        self.rules: list[YaraRule] = []
        self._rules_dir = rules_dir or ""
        self._rules_ptr = None          # YR_RULES*
        self.compile_errors: list = []  # [(file, msg), ...]
        self.quality_stats: dict = {}
        self.libyara_path: str = ""
        self.last_scan_error: int = 0

        # ── 文件类型索引（**仅为保持 API / UI 契约而保留**）──
        # 旧实现（自制引擎）用这四份索引做"按文件类型挑选规则子集"的前置过滤，
        # 因为它的逐条条件求值很慢。现在匹配交给 libyara（全量规则扫 96MB 只要
        # 2.2s），**过滤反而会造成漏报**（例如一个没有 MZ 头的文件就永远不会
        # 参与 _rules_pe），所以这里只统计、**不用于筛选**。
        # 但 app.py 的 /api/v1/scan/perf-stats（1268-1270）与 /api/v1/version
        # （3167-3168）会读这几个属性来展示规则构成，缺了会抛 AttributeError，
        # 被 except 兜成 HTTP 500 —— 前端"引擎性能"面板就会整块变 0。
        self._rules_pe: list[YaraRule] = []                    # 条件含 MZ 头检查
        self._rules_elf: list[YaraRule] = []                   # 条件含 ELF 头检查
        self._rules_generic: list[YaraRule] = []               # 无文件类型限制
        self._rules_filesize: list = []                        # [(rule, op, bytes)]

        if self._rules_dir:
            self.load_rules(self._rules_dir)

    # ---------------- 加载与编译 ----------------

    def _iter_rule_files(self, directory: str):
        for root, dirs, files in os.walk(directory):
            # 跳过 _disabled / 点开头的子目录（旧实现踩过的坑：停用了却仍被递归加载）
            dirs[:] = [d for d in dirs if not d.startswith("_") and not d.startswith(".")]
            for fname in sorted(files):
                if fname.endswith(".yar") or fname.endswith(".yara"):
                    yield os.path.join(root, fname)

    def _compile_one(self, lib, sources):
        """用一个新的 compiler 编译给定 [(rel, text)]，成功返回 YR_RULES*，否则 None。"""
        comp = c_void_p()
        if lib.yr_compiler_create(byref(comp)) != 0 or not comp:
            return None
        try:
            for rel, text in sources:
                ns = rel.replace("\\", "/").encode("utf-8")
                n = lib.yr_compiler_add_string(comp, text.encode("utf-8", "ignore"), ns)
                if n != 0:
                    return None
            rules = c_void_p()
            if lib.yr_compiler_get_rules(comp, byref(rules)) != 0 or not rules:
                return None
            return rules
        finally:
            # YR_RULES 是独立分配物，compiler 可以销毁
            lib.yr_compiler_destroy(comp)

    def _error_of(self, lib, text: str, rel: str) -> str:
        """单独编译一条看错误信息。"""
        comp = c_void_p()
        if lib.yr_compiler_create(byref(comp)) != 0 or not comp:
            return "compiler 创建失败"
        try:
            n = lib.yr_compiler_add_string(comp, text.encode("utf-8", "ignore"),
                                           rel.encode("utf-8"))
            if n == 0:
                return ""
            buf = ctypes.create_string_buffer(4096)
            lib.yr_compiler_get_error_message(comp, buf, 4096)
            return buf.value.decode("utf-8", "replace").strip()
        finally:
            lib.yr_compiler_destroy(comp)

    def load_rules(self, directory: str) -> int:
        """加载目录下所有规则。返回加载成功的规则条数。

        真 YARA 比旧的自制解析器**严格得多**（未引用字符串、语法错误等都会拒绝
        整个文件）。这里分三趟：先整体编译；有错则逐文件定位；最后只用能通过
        的文件编一份合并规则。被拒的文件记在 `compile_errors`。
        """
        self._rules_dir = directory
        self.rules = []
        self._rules_pe = []
        self._rules_elf = []
        self._rules_generic = []
        self._rules_filesize = []
        self.compile_errors = []
        self._destroy_rules()

        lib = _load_lib()
        self.libyara_path = getattr(lib, "LIBYARA_PATH", "")

        files = list(self._iter_rule_files(directory))
        sources = []
        for path in files:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception as e:
                self.compile_errors.append((path, f"读取失败: {e}"))
                continue
            sources.append((os.path.relpath(path, directory), text, path))

        if not sources:
            return 0

        # 第一趟：整体
        good = [(rel, text) for rel, text, _p in sources]
        ptr = self._compile_one(lib, good)
        if ptr is None:
            # 第二趟：逐文件定位坏文件
            kept = []
            for rel, text, path in sources:
                if self._compile_one(lib, [(rel, text)]) is None:
                    self.compile_errors.append((path, self._error_of(lib, text, rel)))
                else:
                    kept.append((rel, text))
            # 第三趟：只编好的
            ptr = self._compile_one(lib, kept) if kept else None
            if kept and ptr is None:
                self.compile_errors.append(
                    ("<合并>", "剩余规则合并编译仍失败（可能存在跨文件命名冲突）"))

        self._rules_ptr = ptr

        # 收集元数据（不受编译结果影响，便于诊断）
        for rel, text, path in sources:
            clean = _strip_comments(text)
            for name, body in _iter_rule_blocks(clean):
                rule = YaraRule(name, path)
                rule.namespace = rel.replace("\\", "/")
                rule.meta = _parse_meta(body)
                rule.condition_raw, rule.condition_type, rule.condition_n = \
                    _classify_condition(body)
                rule.flags_map = _parse_flags(body)
                st, hx, rx, _lits = _parse_strings(body)
                rule.strings = st
                rule.hex_patterns = hx
                rule.regexes = rx
                self.rules.append(rule)
                self._index_rule(rule)

        self._apply_rule_quality()
        return len(self.rules)

    def _destroy_rules(self):
        if self._rules_ptr:
            try:
                lib = _load_lib()
                lib.yr_rules_destroy(self._rules_ptr)
            except Exception:
                pass
            self._rules_ptr = None

    def _all_literals(self, rule: YaraRule) -> list:
        vals = [v.decode("latin1", "ignore") if isinstance(v, bytes) else str(v)
                for (_n, v, _t) in rule.strings if v]
        for (_n, mask, pat) in rule.hex_patterns:
            run = bytearray()
            for i in range(len(mask)):
                if mask[i] == 0xFF:
                    run.append(pat[i])
                else:
                    if len(run) >= 4:
                        vals.append(run.decode("latin1"))
                    run = bytearray()
            if len(run) >= 4:
                vals.append(run.decode("latin1"))
        vals += [p for (_n, p, _f) in rule.regexes]
        return vals

    def _apply_rule_quality(self):
        """给每条规则算置信度（沿用 engine.rule_quality，语义不变）。"""
        try:
            from engine.rule_quality import analyze_literals
        except Exception:
            return
        stats = {"high": 0, "medium": 0, "low": 0}
        for rule in self.rules:
            rule.quality = analyze_literals(self._all_literals(rule),
                                            rule.condition_type, rule.condition_n)
            t = rule.quality.get("tier", "medium")
            stats[t] = stats.get(t, 0) + 1
        self.quality_stats = stats
        try:
            import logging
            logging.getLogger("yutian").info(
                "规则置信度分级: high=%d medium=%d low=%d（libyara=%s）",
                stats.get("high", 0), stats.get("medium", 0), stats.get("low", 0),
                os.path.basename(self.libyara_path or "?"))
        except Exception:
            pass

    def rule_confidence(self, rule_name: str) -> str:
        for r in self.rules:
            if r.name == rule_name:
                return (r.quality or {}).get("tier", "medium")
        return "medium"

    def _index_rule(self, rule: YaraRule):
        """按 condition 里的文件类型特征把规则归类 —— **仅供统计/展示**。

        与旧实现（备份文件 `yara_scanner.py.bak_*` 的 `_index_rule`）判定规则
        保持一致，这样 `/api/v1/scan/perf-stats` 与 `/api/v1/version` 报出的
        pe_rules / elf_rules / generic_rules 数字口径不变。

        ⚠️ 与旧实现的**唯一区别**：不再用这些索引去筛选待扫规则。libyara 全量
        扫描既正确又快（实测 96MB / 200 个系统文件 2.2s），而按文件类型过滤会让
        "没有 MZ 头的样本" 永远拿不到 PE 规则，属于漏报风险。
        """
        cond = rule.condition_raw.lower()
        cond_type = rule.condition_type

        has_mz = ("uint16" in cond and "0x5a4d" in cond) or cond_type == "mz_check"
        has_elf = ("uint32" in cond and "0x464c457f" in cond) or cond_type == "elf_check"

        if "filesize" in cond:
            m = re.search(r"filesize\s*([<>!=]+)\s*(\d+)\s*(kb|mb)?", cond, re.I)
            if m:
                op, val, unit = m.group(1), int(m.group(2)), (m.group(3) or "")
                if unit == "kb":
                    val *= 1024
                elif unit == "mb":
                    val *= 1024 * 1024
                self._rules_filesize.append((rule, op, val))

        if has_mz:
            self._rules_pe.append(rule)
        elif has_elf:
            self._rules_elf.append(rule)
        else:
            self._rules_generic.append(rule)

    # ---------------- 扫描 ----------------

    def _scan(self, callback_installer) -> list:
        """跑一次 libyara 扫描，callback_installer 负责实际调用。"""
        lib = _load_lib()
        matched: list = []

        def _cb(ctx, message, mdata, user):
            if message == CALLBACK_MSG_RULE_MATCHING and mdata:
                try:
                    p = cast(mdata + YR_RULE_IDENTIFIER_OFFSET, POINTER(c_char_p))
                    nm = p.contents.value
                    if nm:
                        matched.append(nm.decode("utf-8", "replace"))
                except Exception:
                    pass
                if len(matched) >= _MAX_MATCHES:
                    return 1        # CALLBACK_ABORT
            return CALLBACK_CONTINUE

        cb = YR_CALLBACK_FUNC(_cb)
        try:
            self.last_scan_error = callback_installer(lib, cb)
        except Exception:
            self.last_scan_error = -1
        return matched

    def _build_results(self, names, content: bytes) -> list:
        by_name = {r.name: r for r in self.rules}
        out = []
        for nm in names:
            rule = by_name.get(nm)
            if rule is None:
                # libyara 命中了但源码解析没抓到（跨文件同名等）：给出最小结构
                out.append({"rule": nm, "description": nm, "malware_type": "UNKNOWN",
                            "source_file": "", "matched_patterns": [], "meta": {},
                            "confidence": "medium", "quality_reason": ""})
                continue
            out.append({
                "rule": rule.name,
                "description": rule.description,
                "malware_type": rule.malware_type,
                "source_file": rule.source_file,
                "matched_patterns": self._report_patterns(rule, content),
                "meta": rule.meta,
                "confidence": (rule.quality or {}).get("tier", "medium"),
                "quality_reason": (rule.quality or {}).get("reason", ""),
            })
        return out

    def _report_patterns(self, rule: YaraRule, content: bytes) -> list:
        """**报告用**：列出该规则里哪些模式能在内容中找到。

        判定已由 libyara 完成，这里只是给日志/UI 一个尽力而为的归因。
        支持 ascii / wide / nocase / fullword / 半字节通配；xor、base64、
        [n-m] 跳转等无法在纯 Python 侧精确复现的，按近似处理。
        """
        found = []
        flags_map = rule.flags_map or {}

        for name, value, typ in rule.strings:
            fl = flags_map.get(name, "")
            hit = False
            if typ == "wide":
                hit = value in content
            elif "nocase" in fl:
                hit = value.lower() in content.lower()
            else:
                hit = value in content
            if hit:
                if "fullword" in fl:
                    hit = self._fullword_ok(content, value, "nocase" in fl)
            if hit:
                found.append(name)

        for name, mask, pattern in rule.hex_patterns:
            if self._search_with_mask(content, mask, pattern):
                found.append(name)

        for name, _p, _f in rule.regexes:
            # 正则不做复现（libyara 已判定命中）；仅在其字面量可见时报告
            try:
                if _p.encode("utf-8", "ignore") in content:
                    found.append(name)
            except Exception:
                pass
        return found

    @staticmethod
    def _fullword_ok(content: bytes, value: bytes, nocase: bool) -> bool:
        hay = content.lower() if nocase else content
        needle = value.lower() if nocase else value

        def is_word(b: int) -> bool:
            return (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or b == 95

        start = 0
        while True:
            i = hay.find(needle, start)
            if i < 0:
                return False
            before = hay[i - 1] if i > 0 else 0
            after_i = i + len(needle)
            after = hay[after_i] if after_i < len(hay) else 0
            if not is_word(before) and not is_word(after):
                return True
            start = i + 1

    @staticmethod
    def _search_with_mask(data: bytes, mask: bytes, pattern: bytes) -> bool:
        n = len(pattern)
        if n == 0 or len(data) < n:
            return False
        first_fixed = next((i for i in range(n) if mask[i] == 0xFF), 0)
        start = 0
        while True:
            i = data.find(bytes([pattern[first_fixed]]), start)
            if i < 0:
                return False
            base = i - first_fixed
            if base >= 0 and base + n <= len(data):
                ok = True
                for k in range(n):
                    if mask[k] and (data[base + k] & mask[k]) != (pattern[k] & mask[k]):
                        ok = False
                        break
                if ok:
                    return True
            start = i + 1

    def scan_content(self, content: bytes, file_path: str = "") -> list:
        """扫描内存内容（**热路径**：零额外 I/O，直接 yr_rules_scan_mem）。"""
        if not self._rules_ptr or not content:
            return []
        buf = (c_uint8 * len(content)).from_buffer_copy(content)
        names = self._scan(lambda lib, cb: lib.yr_rules_scan_mem(
            self._rules_ptr, buf, len(content), 0, cb, None, 0))
        if not names:
            return []
        return self._build_results(names, content)

    def scan_content_typed(self, content: bytes, file_path: str = "",
                           file_size: int = 0) -> list:
        """扫描内存内容。

        注意：libyara 在内存扫描时 `filesize` 取**缓冲区长度**。当 file_size 与
        len(content) 不同（例如只读了文件前 N 字节）时，仅依赖 filesize 的条件
        会按缓冲区长度评估。要精确的 filesize 语义请用 `scan_file()`。
        """
        return self.scan_content(content, file_path)

    def scan_file(self, file_path: str) -> list:
        """扫描磁盘文件（用 yr_rules_scan_file，filesize 精确、内存映射）。"""
        if not self._rules_ptr:
            return []
        try:
            size = os.path.getsize(file_path)
        except Exception:
            return []
        if size == 0 or size > _MAX_FILE_SIZE:
            return []
        names = self._scan(lambda lib, cb: lib.yr_rules_scan_file(
            self._rules_ptr, os.fsencode(file_path), 0, cb, None, 0))
        if not names:
            return []
        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except Exception:
            content = b""
        return self._build_results(names, content)

    def close(self):
        self._destroy_rules()

    def __del__(self):
        try:
            self._destroy_rules()
        except Exception:
            pass


def create_scanner(rules_dir: str = None) -> YaraScanner:
    """工厂函数（保持旧签名）。"""
    return YaraScanner(rules_dir)
