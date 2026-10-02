"""
YARA 规则扫描引擎 - 纯 Python 实现
支持 string、hex 模式匹配及基本条件表达式
"""
import os
import re
import fnmatch
from collections import deque


class _AhoCorasick:
    """多模式字节匹配自动机（Aho-Corasick）。
    用于一次性扫描出所有字符串模式是否命中，避免逐规则逐字符串 `in` 匹配。
    """

    def __init__(self):
        self._children = [{}]   # node -> {byte(int): next_node}
        self._fail = [0]        # node -> fail link
        self._output = [[]]     # node -> payload list

    def add(self, pattern: bytes, payload):
        if not pattern:
            return
        node = 0
        for b in pattern:
            nxt = self._children[node].get(b)
            if nxt is None:
                nxt = len(self._children)
                self._children[node][b] = nxt
                self._children.append({})
                self._fail.append(0)
                self._output.append([])
            node = nxt
        self._output[node].append(payload)

    def build(self):
        """BFS 构建失配链接并合并输出。无模式时安全。"""
        if len(self._children) == 1 and not self._children[0]:
            return
        q = deque()
        for node in self._children[0].values():
            self._fail[node] = 0
            q.append(node)
        while q:
            cur = q.popleft()
            for b, nxt in self._children[cur].items():
                q.append(nxt)
                f = self._fail[cur]
                while f and b not in self._children[f]:
                    f = self._fail[f]
                f = self._children[f].get(b, 0)
                self._fail[nxt] = f
                if self._output[f]:
                    self._output[nxt] = self._output[nxt] + self._output[f]

    def find(self, data: bytes) -> list:
        """一次遍历 data，返回全部命中的 payload（允许重复，交由调用方去重）。"""
        if not data or (len(self._children) == 1 and not self._children[0]):
            return []
        node = 0
        hits = []
        for b in data:
            while node and b not in self._children[node]:
                node = self._fail[node]
            node = self._children[node].get(b, 0)
            if self._output[node]:
                hits.extend(self._output[node])
        return hits


class YaraRule:
    """单条 YARA 规则"""

    def __init__(self, name: str, source_file: str = ""):
        self.name = name
        self.source_file = source_file
        self.meta: dict[str, str] = {}
        self.strings: list[tuple[str, str, str]] = []  # (name, value, type)
        self.hex_patterns: list[tuple[str, bytes, bytes]] = []  # (name, mask, pattern)
        self.condition_raw: str = ""
        self.condition_type: str = "any"  # any / all / N / custom
        self.condition_n: int = 1

    @property
    def total_patterns(self) -> int:
        return len(self.strings) + len(self.hex_patterns)

    @property
    def malware_type(self) -> str:
        return self.meta.get("malware_type", self.meta.get("category", "UNKNOWN")).upper()

    @property
    def description(self) -> str:
        return self.meta.get("description", self.meta.get("malware", self.name))


class YaraScanner:
    """YARA 规则扫描器（v2.0 按文件类型索引优化版）"""

    def __init__(self, rules_dir: str = None):
        self.rules: list[YaraRule] = []
        self._rules_dir = rules_dir or ""
        # v2.0: 规则按文件类型索引，减少无效匹配
        self._rules_pe: list[YaraRule] = []       # 需要 MZ 头检查的规则
        self._rules_elf: list[YaraRule] = []      # 需要 ELF 头检查的规则
        self._rules_generic: list[YaraRule] = []  # 无文件类型限制的规则
        self._rules_filesize: list[tuple[YaraRule, str, int]] = []  # 带文件大小条件的规则
        self._ac: tuple[_AhoCorasick, _AhoCorasick] | None = None  # (ascii, wide) 懒构建
        if self._rules_dir:
            self.load_rules(self._rules_dir)

    def load_rules(self, directory: str):
        """加载目录下所有 .yar 文件并构建文件类型索引"""
        self._rules_dir = directory
        self.rules = []
        self._rules_pe = []
        self._rules_elf = []
        self._rules_generic = []
        self._rules_filesize = []
        self._ac = None  # 规则变更后失效，下次扫描重建
        loaded = 0
        for root, _, files in os.walk(directory):
            for fname in files:
                if fname.endswith(".yar") or fname.endswith(".yara"):
                    path = os.path.join(root, fname)
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        parsed = self._parse_rules(content, path)
                        for rule in parsed:
                            self._index_rule(rule)
                        self.rules.extend(parsed)
                        loaded += len(parsed)
                    except Exception:
                        pass
        return loaded

    def _index_rule(self, rule: YaraRule):
        """按文件类型将规则索引到对应的分类中"""
        cond = rule.condition_raw.lower()
        cond_type = rule.condition_type

        # 检查是否包含 MZ 头条件（PE 文件专用规则）
        has_mz = ("uint16" in cond and "0x5a4d" in cond) or cond_type == "mz_check"
        # 检查是否包含 ELF 头条件
        has_elf = ("uint32" in cond and "0x464c457f" in cond) or cond_type == "elf_check"
        # 检查是否有文件大小限制
        has_filesize = "filesize" in cond

        if has_filesize:
            # 提取文件大小条件（op, value）
            fs_match = re.search(r'filesize\s*([<>!=]+)\s*(\d+)(KB|MB)?', cond, re.IGNORECASE)
            if fs_match:
                op = fs_match.group(1)
                val = int(fs_match.group(2))
                unit = fs_match.group(3) or ""
                if unit.upper() == "KB":
                    val *= 1024
                elif unit.upper() == "MB":
                    val *= 1024 * 1024
                self._rules_filesize.append((rule, op, val))
            # 有 filesize 条件的也放入对应类型（冗余保障）
            if has_mz:
                self._rules_pe.append(rule)
            elif has_elf:
                self._rules_elf.append(rule)
            else:
                self._rules_generic.append(rule)
        elif has_mz:
            self._rules_pe.append(rule)
        elif has_elf:
            self._rules_elf.append(rule)
        else:
            self._rules_generic.append(rule)

    def _get_rules_for_file(self, file_path: str = "", content: bytes = b"",
                             file_size: int = 0) -> list[YaraRule]:
        """根据文件类型选择匹配的规则子集，大幅减少无效匹配"""
        has_mz = len(content) >= 2 and content[:2] == b"MZ"
        has_elf = len(content) >= 4 and content[:4] == b"\x7fELF"

        if has_mz:
            candidate = list(self._rules_pe)
        elif has_elf:
            candidate = list(self._rules_elf)
        else:
            candidate = []

        # 通用规则总是添加
        candidate.extend(self._rules_generic)

        # 带文件大小条件的规则：前置过滤
        for rule, op, val in self._rules_filesize:
            if file_size > 0:
                ok = False
                if op == '<': ok = file_size < val
                elif op == '>': ok = file_size > val
                elif op == '<=': ok = file_size <= val
                elif op == '>=': ok = file_size >= val
                elif op == '==': ok = file_size == val
                if ok and rule not in candidate:
                    candidate.append(rule)

        return candidate

    def scan_file(self, file_path: str) -> list[dict]:
        """
        扫描单个文件，返回匹配的规则列表（v2.0 使用文件类型索引）
        """
        results = []
        try:
            size = os.path.getsize(file_path)
            if size == 0 or size > 200 * 1024 * 1024:
                return results
        except Exception:
            return results

        content = b""
        try:
            with open(file_path, "rb") as f:
                content = f.read(16 * 1024 * 1024)
        except Exception:
            return results

        return self._scan_with_rules(content, file_path, size)

    def scan_content(self, content: bytes, file_path: str = "") -> list[dict]:
        """扫描内存中的内容（v2.0 使用索引优化）"""
        return self._scan_with_rules(content, file_path, len(content))

    def scan_content_typed(self, content: bytes, file_path: str = "",
                            file_size: int = 0) -> list[dict]:
        """扫描内存内容（传入文件实际大小做前置过滤）"""
        return self._scan_with_rules(content, file_path, file_size or len(content))

    def _ensure_ac(self) -> tuple[_AhoCorasick, _AhoCorasick]:
        """懒构建 ascii / wide 两套多模式自动机（含构建后再失效）。"""
        if self._ac is None:
            ac_ascii = _AhoCorasick()
            ac_wide = _AhoCorasick()
            for rule in self.rules:
                rid = id(rule)
                for name, value, typ in rule.strings:
                    if typ == 'wide':
                        ac_wide.add(value, (rid, name))
                    else:
                        ac_ascii.add(value, (rid, name))
            ac_ascii.build()
            ac_wide.build()
            self._ac = (ac_ascii, ac_wide)
        return self._ac

    def _scan_with_rules(self, content: bytes, file_path: str,
                          file_size: int) -> list[dict]:
        """核心扫描：按文件类型索引选择规则子集，大幅减少无效匹配。
        先用 Aho-Corasick 一次遍历命中全部字符串模式，再评估各规则条件。
        """
        results = []
        rules_subset = self._get_rules_for_file(file_path, content, file_size)

        # 多模式一次遍历，得到 rule_id -> 命中字符串名集合
        rule_pre: dict = {}
        ac_ascii, ac_wide = self._ensure_ac()
        for rid, name in ac_ascii.find(content):
            rule_pre.setdefault(rid, set()).add(name)
        for rid, name in ac_wide.find(content):
            rule_pre.setdefault(rid, set()).add(name)

        for rule in rules_subset:
            # 未命中任何字符串时传空集合（而非 None），保证走 AC 结果、避免回退逐条扫描
            pre = rule_pre.get(id(rule)) or set()
            matched = self._match_rule(rule, content, file_path, pre)
            if matched:
                results.append({
                    "rule": rule.name,
                    "description": rule.description,
                    "malware_type": rule.malware_type,
                    "source_file": rule.source_file,
                    "matched_patterns": matched,
                    "meta": rule.meta
                })
        return results

    # ==================== 规则解析 ====================

    def _parse_rules(self, content: str, source: str) -> list[YaraRule]:
        """解析 YARA 规则文本"""
        rules = []
        # 先移除注释
        content = self._strip_comments(content)

        # 用 finditer 一次找到所有 rule 块
        rule_pattern = re.compile(r'rule\s+(\w+)\s*\{')
        for m in rule_pattern.finditer(content):
            rule_name = m.group(1)
            start = m.end() - 1  # 指向第一个 {

            # 找匹配的 }
            depth = 1
            j = start + 1
            while j < len(content) and depth > 0:
                if content[j] == '{':
                    depth += 1
                elif content[j] == '}':
                    depth -= 1
                j += 1

            body = content[start + 1:j - 1]
            rule = self._parse_rule_body(rule_name, body, source)
            if rule and rule.total_patterns > 0:
                rules.append(rule)

        return rules

    def _parse_rule_body(self, name: str, body: str, source: str) -> YaraRule | None:
        rule = YaraRule(name, source)

        # 解析 meta 块
        meta_match = re.search(r'meta\s*:\s*(.*?)(?:strings\s*:|condition\s*:)', body, re.DOTALL)
        if meta_match:
            meta_text = meta_match.group(1)
            for line in meta_text.split('\n'):
                # 格式: key = "value"
                m = re.match(r'(\w+)\s*=\s*"([^"]*)"', line.strip())
                if m:
                    rule.meta[m.group(1)] = m.group(2)

        # 解析 strings 块
        strings_match = re.search(r'strings\s*:\s*(.*?)(?:condition\s*:)', body, re.DOTALL)
        if strings_match:
            strings_text = strings_match.group(1)
            rule.strings, rule.hex_patterns = self._parse_strings(strings_text)

        # 解析 condition
        cond_match = re.search(r'condition\s*:\s*(.*)', body, re.DOTALL)
        if cond_match:
            rule.condition_raw = cond_match.group(1).strip()
            rule.condition_type, rule.condition_n = self._parse_condition(rule.condition_raw)

        return rule

    def _parse_strings(self, text: str) -> tuple[list, list]:
        """解析 strings 块，返回 (text_strings, hex_patterns)"""
        text_patterns = []
        hex_patterns = []

        lines = text.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line or line.startswith('//'):
                i += 1
                continue

            # 字符串模式: $name = "text" modifiers
            # 注意：YARA 中用 \" 表示转义引号，需正确处理
            equals_idx = line.find('=')
            if equals_idx > 0:
                pre = line[:equals_idx].strip()
                rest = line[equals_idx + 1:].strip()
                # 检查是否是 $name = "..." 格式
                if re.match(r'^\$\w*$', pre) and rest.startswith('"'):
                    name = pre
                    # 手动解析转义引号（注意：不能复用外层行索引 i）
                    in_content = rest[1:]  # 去掉开头的 "
                    content_parts = []
                    k = 0
                    while k < len(in_content):
                        if in_content[k] == '\\' and k + 1 < len(in_content) and in_content[k + 1] == '"':
                            content_parts.append('"')
                            k += 2
                        elif in_content[k] == '"':
                            # 找到结束引号
                            k += 1
                            break
                        else:
                            content_parts.append(in_content[k])
                            k += 1
                    value = ''.join(content_parts)
                    # 剩余部分为修饰符（nocase, wide, ascii 等）
                    remainder = in_content[k:].strip()
                    flags = remainder.split()[0] if remainder else ""
                    # ascii wide 意味着搜索 ASCII 和 UTF-16LE
                    if 'wide' in flags:
                        text_patterns.append((name, value.encode('utf-16-le'), 'wide'))
                    text_patterns.append((name, value.encode('utf-8', errors='ignore'), 'ascii'))
                    i += 1
                    continue

            # 十六进制模式: $name = { AA BB ?? CC }
            hex_match = re.match(r'(\$\w*)\s*=\s*\{\s*(.*?)\s*\}', line)
            if hex_match:
                name = hex_match.group(1)
                hex_body = hex_match.group(2)
                # 如果行不完整（右括号在下一行），合并后续行
                if not line.rstrip().endswith('}'):
                    more_lines = []
                    j = i + 1
                    while j < len(lines):
                        more_lines.append(lines[j].strip())
                        if '}' in lines[j]:
                            break
                        j += 1
                    hex_body += ' ' + ' '.join(more_lines).rstrip('}')
                    i = j

                mask, pattern = self._parse_hex_pattern(hex_body)
                if pattern:
                    hex_patterns.append((name, mask, pattern))
                i += 1
                continue

            i += 1

        return text_patterns, hex_patterns

    def _parse_hex_pattern(self, hex_body: str) -> tuple[bytes, bytes]:
        """解析十六进制模式，返回 (mask, pattern)"""
        mask_bytes = bytearray()
        pattern_bytes = bytearray()

        # 处理通配符和跳转
        tokens = hex_body.strip().split()
        j = 0
        while j < len(tokens):
            token = tokens[j]
            if token == '??':
                mask_bytes.append(0)
                pattern_bytes.append(0)
            elif token.startswith('?') and len(token) >= 2:
                # 半字节通配符如 ?4, ?A
                try:
                    val = int(token[1:], 16) & 0xF
                    mask_bytes.append(0xF0)
                    pattern_bytes.append(val << 4)
                except ValueError:
                    mask_bytes.append(0)
                    pattern_bytes.append(0)
            elif len(token) >= 2:
                # 完整字节
                try:
                    val = int(token[:2], 16)
                    mask_bytes.append(0xFF)
                    pattern_bytes.append(val)
                except ValueError:
                    mask_bytes.append(0)
                    pattern_bytes.append(0)
            # 跳转由简单实现跳过（在匹配时用搜索替代）
            j += 1

        return bytes(mask_bytes), bytes(pattern_bytes)

    def _parse_condition(self, cond: str) -> tuple[str, int]:
        """解析 condition 表达式 — 支持丰富语法"""
        cond = cond.strip()

        # any of them / all of them
        if cond == 'all of them':
            return 'all', -1
        if cond == 'any of them':
            return 'any', 1

        # all of ($var*, $var2*) — 通配符集合
        all_wild = re.match(r'all\s+of\s+\(([^)]+)\)', cond)
        if all_wild:
            return 'all_wild', 0

        # N of ($var*, ...)
        n_wild = re.match(r'(\d+)\s+of\s+\(([^)]+)\)', cond)
        if n_wild:
            return 'N_wild', int(n_wild.group(1))

        # N of them
        n_match = re.match(r'(\d+)\s+of\s+them', cond)
        if n_match:
            return 'N', int(n_match.group(1))

        # $var at 0 and all of ... (复合条件)
        and_match = re.match(r'(.+?)\s+and\s+(.+)', cond, re.IGNORECASE)
        if and_match:
            return 'and', 0

        # $var at 0 or $var2 at 0 (或条件)
        or_match = re.match(r'(.+?)\s+or\s+(.+)', cond, re.IGNORECASE)
        if or_match:
            return 'or', 0

        # $var at 0 (位置条件)
        at_match = re.match(r'(\$\w+)\s+at\s+(0|[1-9]\d*)', cond)
        if at_match:
            return 'at', int(at_match.group(2))

        # for any of ($var*) : ($) 等循环条件（暂简化处理）
        for_match = re.match(r'for\s+any\s+of\s+\(', cond)
        if for_match:
            return 'any', 1

        # uint16(0) == 0x5a4d (MZ/PE 头条件)
        if re.search(r'uint16\(\s*0\s*\)\s*==\s*0x5a4d', cond, re.IGNORECASE):
            return 'mz_check', 0

        # uint32(0) == 0x464c457f (ELF header condition)
        if re.search(r'uint32\(\s*0\s*\)\s*==\s*0x464c457f', cond, re.IGNORECASE):
            return 'elf_check', 0

        # filesize < XX KB
        if 'filesize' in cond:
            return 'any', 1  # 简化：有 filesize 条件时退化为 any

        # # of ($var*) > N (匹配计数条件)
        count_match = re.match(r'#(\w+)\s*[><=]+\s*(\d+)', cond)
        if count_match:
            return 'any', 1

        # 默认 any
        return 'any', 1

    # ==================== 模式匹配 ====================

    def _match_rule(self, rule: YaraRule, content: bytes, file_path: str,
                    pre_matched: set | None = None) -> list[str]:
        """匹配单条规则，返回匹配到的模式名列表。支持丰富条件表达式。
        pre_matched: 由 Aho-Corasick 预计算的该规则命中的字符串名集合（含 $ 前缀）；
                     为 None 时回退为逐字符串 `in` 扫描（兼容外部直接调用）。
        """
        matched = []

        # 调试：记录规则和条件
        # print(f"  Rule: {rule.name}, cond={rule.condition_type}, raw={rule.condition_raw[:60]}")

        # 匹配字符串模式
        if pre_matched is not None:
            for name, _value, _typ in rule.strings:
                if name in pre_matched and name not in matched:
                    matched.append(name)
        else:
            for name, value, typ in rule.strings:
                if typ == 'wide':
                    if self._search_bytes(content, value):
                        if name not in matched:
                            matched.append(name)
                else:
                    if value in content:
                        if name not in matched:
                            matched.append(name)

        # 匹配十六进制模式（带通配符搜索）
        for name, mask, pattern in rule.hex_patterns:
            if self._search_with_mask(content, mask, pattern):
                if name not in matched:
                    matched.append(name)

        # 评估条件
        return self._evaluate_condition(rule, matched, content)

    def _evaluate_condition(self, rule: YaraRule, matched: list[str], content: bytes) -> list[str]:
        """
        评估 YARA 条件表达式
        返回匹配的模式名列表（空列表表示未命中）
        """
        cond = rule.condition_raw
        cond_type = rule.condition_type

        # ---- 简单条件 ----
        if cond_type == 'all':
            if len(matched) >= rule.total_patterns and rule.total_patterns > 0:
                return matched
            return []

        if cond_type == 'N':
            if len(matched) >= rule.condition_n:
                return matched
            return []

        if cond_type == 'any':
            if len(matched) >= 1:
                return matched
            return []

        # ---- 位置条件: $var at OFFSET ----
        if cond_type == 'at':
            target_offset = rule.condition_n
            for name in matched:
                # 查找该模式在内容中的实际位置
                for _name, value, _typ in rule.strings:
                    if _name == name:
                        pos = content.find(value)
                        if pos == target_offset:
                            return matched
                for _name, _mask, pattern in rule.hex_patterns:
                    if _name == name:
                        pos = content.find(pattern)
                        if pos == target_offset:
                            return matched
            return []

        # ---- MZ/PE 头检查条件 ----
        if cond_type == 'mz_check':
            if len(content) >= 2 and content[:2] == b'MZ':
                # MZ 头存在，继续检查其他匹配
                if matched:
                    return matched
            return []

        # ---- ELF 头检查条件 ----
        if cond_type == 'elf_check':
            if len(content) >= 4 and content[:4] == b'\x7fELF':
                if matched:
                    return matched
            return []

        # ---- AND 条件: $var at 0 and all of ($s*) ----
        if cond_type == 'and':
            parts = re.split(r'\s+and\s+', cond, flags=re.IGNORECASE)
            all_met = True
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                if not self._eval_condition_part(part, rule, matched, content):
                    all_met = False
                    break
            return matched if all_met else []

        # ---- OR 条件 ----
        if cond_type == 'or':
            parts = re.split(r'\s+or\s+', cond, flags=re.IGNORECASE)
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                if self._eval_condition_part(part, rule, matched, content):
                    return matched
            return []

        # ---- 通配符集合: all of ($s*) / N of ($s*, $hex*) ----
        if cond_type == 'all_wild':
            # 找出匹配了集合中模式名的数量
            matched_in_set = self._count_wildcard_matches(cond, rule, matched)
            # 集合大小
            set_patterns = self._extract_wildcard_patterns(cond, rule)
            if set_patterns > 0 and matched_in_set >= set_patterns:
                return matched
            return []

        # ---- 通配符 N of ---
        if cond_type == 'N_wild':
            matched_in_set = self._count_wildcard_matches(cond, rule, matched)
            if matched_in_set >= rule.condition_n:
                return matched
            return []

        return []

    def _eval_condition_part(self, part: str, rule: YaraRule, matched: list[str], content: bytes) -> bool:
        """评估 AND/OR 条件中的一个子句"""
        part = part.strip()

        # $var at OFFSET
        at_m = re.match(r'(\$\w+)\s+at\s+(\d+)', part)
        if at_m:
            var_name, offset = at_m.group(1), int(at_m.group(2))
            # 检查该模式是否在指定偏移匹配
            if var_name in matched:
                # 验证实际位置
                for _name, value, _typ in rule.strings:
                    if _name == var_name:
                        return content.find(value) == offset
                for _name, _mask, pattern in rule.hex_patterns:
                    if _name == var_name:
                        return content.find(pattern) == offset
            return False

        # all of ($s*) — 通配符集合
        all_wild = re.match(r'all\s+of\s+\(([^)]+)\)', part)
        if all_wild:
            set_str = all_wild.group(1)
            # 提取集合内的所有通配符模式
            wild_patterns = [w.strip().replace('$', '') for w in set_str.split(',') if w.strip().startswith('$')]
            # 计算名匹配的模式
            required_total = len(wild_patterns)
            matched_required = 0
            for wp in wild_patterns:
                if wp.endswith('*'):
                    prefix = wp[:-1]
                    for m in matched:
                        if m.lstrip('$').startswith(prefix):
                            matched_required += 1
                            break
                else:
                    if '$' + wp in matched:
                        matched_required += 1
            return matched_required >= required_total if required_total > 0 else True

        # any of ($s*, ...)
        any_wild = re.match(r'any\s+of\s+\(([^)]+)\)', part)
        if any_wild:
            set_str = any_wild.group(1)
            wild_patterns = [w.strip().replace('$', '') for w in set_str.split(',') if w.strip().startswith('$')]
            for wp in wild_patterns:
                if wp.endswith('*'):
                    prefix = wp[:-1]
                    for m in matched:
                        if m.lstrip('$').startswith(prefix):
                            return True
                else:
                    if '$' + wp in matched:
                        return True
            return False

        # N of ($s*, ...)
        n_wild = re.match(r'(\d+)\s+of\s+\(([^)]+)\)', part)
        if n_wild:
            required, set_str = int(n_wild.group(1)), n_wild.group(2)
            wild_patterns = [w.strip().replace('$', '') for w in set_str.split(',') if w.strip().startswith('$')]
            matched_cnt = 0
            for wp in wild_patterns:
                if wp.endswith('*'):
                    prefix = wp[:-1]
                    for m in matched:
                        if m.lstrip('$').startswith(prefix):
                            matched_cnt += 1
                            break
                else:
                    if '$' + wp in matched:
                        matched_cnt += 1
            return matched_cnt >= required

        # $var at 0 (简单位置)
        at_simple = re.match(r'\$\w+\s+at\s+\d+', part)
        if at_simple:
            # 已经在主 matched 逻辑中处理
            return bool(matched)

        # # of ($var*) > N (计数)
        count_m = re.match(r'#(\w+)\s*([><=!]+)\s*(\d+)', part)
        if count_m:
            # 简化处理：只要匹配了就算
            return bool(matched)

        # uint16(0) == 0x5a4d
        if re.search(r'uint16\(\s*0\s*\)\s*==\s*0x5a4d', part, re.IGNORECASE):
            return len(content) >= 2 and content[:2] == b'MZ'

        # filesize 检查
        fs_m = re.match(r'filesize\s*([<>!=]+)\s*(\d+)', part, re.IGNORECASE)
        if fs_m:
            op, val = fs_m.group(1), int(fs_m.group(2))
            fsize = len(content)
            if op == '<': return fsize < val
            if op == '>': return fsize > val
            if op == '<=': return fsize <= val
            if op == '>=': return fsize >= val
            if op == '==': return fsize == val
            return False

        # 裸变量名: $var —— 检查该模式是否实际匹配（不能退化为 bool(matched)）
        var_only = re.match(r'^\$\w+$', part)
        if var_only:
            return var_only.group(0) in matched

        # 括号表达式: ($a or $b or $c) / ($a and $b) / ($a)
        paren = re.match(r'^\(\s*(.+?)\s*\)$', part, re.DOTALL)
        if paren:
            inner = paren.group(1).strip()
            has_or = re.search(r'\bor\b', inner, re.IGNORECASE)
            has_and = re.search(r'\band\b', inner, re.IGNORECASE)
            if has_or and not has_and:
                subparts = re.split(r'\s+or\s+', inner, flags=re.IGNORECASE)
                return any(self._eval_condition_part(sp.strip(), rule, matched, content)
                           for sp in subparts)
            if has_and and not has_or:
                subparts = re.split(r'\s+and\s+', inner, flags=re.IGNORECASE)
                return all(self._eval_condition_part(sp.strip(), rule, matched, content)
                           for sp in subparts)
            # 单个变量（或混合表达式简化）：检查是否匹配
            return inner in matched

        # 默认：有匹配就算
        return bool(matched)

    def _count_wildcard_matches(self, cond: str, rule: YaraRule, matched: list[str]) -> int:
        """计算通配符集合中实际匹配的模式数"""
        m = re.search(r'\((.*?)\)', cond)
        if not m:
            return 0
        wild_str = m.group(1)
        wild_patterns = [w.strip().replace('$', '') for w in wild_str.split(',')]
        count = 0
        for wp in wild_patterns:
            if wp.endswith('*'):
                prefix = wp[:-1]
                for m_name in matched:
                    if m_name.lstrip('$').startswith(prefix):
                        count += 1
                        break
            else:
                if '$' + wp in matched:
                    count += 1
        return count

    def _extract_wildcard_patterns(self, cond: str, rule: YaraRule) -> int:
        """提取通配符集合中的模式总数"""
        m = re.search(r'\((.*?)\)', cond)
        if not m:
            return 0
        wild_str = m.group(1)
        return len([w for w in wild_str.split(',') if w.strip().startswith('$')])

    @staticmethod
    def _search_bytes(data: bytes, pattern: bytes) -> bool:
        """在数据中搜索字节序列"""
        if not pattern:
            return False
        try:
            return data.find(pattern) != -1
        except Exception:
            return False

    @staticmethod
    def _search_with_mask(data: bytes, mask: bytes, pattern: bytes) -> bool:
        """
        带通配符的字节搜索（优化的 Sunday 算法变体）
        mask[i] == 0 表示该位置是通配符
        """
        if not pattern or len(data) < len(pattern):
            return False

        n = len(pattern)
        dlen = len(data)
        start = 0

        while start <= dlen - n:
            match = True
            for k in range(n):
                if mask[k] == 0:
                    continue  # 通配符，跳过
                if data[start + k] != pattern[k]:
                    match = False
                    break
            if match:
                return True

            # 计算跳步：找到第一个非通配符且在 pattern 中最后出现的位置
            if start + n < dlen:
                next_char = data[start + n]
                shift = 1
                # 从后往前找 next_char 在 pattern 中的位置
                for k in range(n - 1, -1, -1):
                    if mask[k] != 0 and pattern[k] == next_char:
                        shift = n - k
                        break
                if shift == 1:
                    # 如果 next_char 不在 pattern 中，跳 n+1
                    shift = n + 1
                start += shift
            else:
                start += 1

        return False

    # ==================== 辅助 ====================

    @staticmethod
    def _strip_comments(content: str) -> str:
        """移除单行注释（//）和多行注释（/* */）"""
        # 移除多行注释
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        # 移除单行注释
        lines = []
        for line in content.split('\n'):
            # 跳过纯注释行
            stripped = line.strip()
            if stripped.startswith('//'):
                continue
            # 移除行内注释（简单处理）
            in_string = False
            result = []
            for i, ch in enumerate(line):
                if ch == '"' and (i == 0 or line[i - 1] != '\\'):
                    in_string = not in_string
                if not in_string and i < len(line) - 1 and line[i:i + 2] == '//':
                    break
                result.append(ch)
            lines.append(''.join(result))
        return '\n'.join(lines)


# ==================== 便捷工厂函数 ====================

def create_scanner(rules_dir: str = None) -> YaraScanner:
    """创建 YARA 扫描器实例"""
    if rules_dir is None:
        # 默认规则目录
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rules_dir = os.path.join(base, "Yara-rules-master", "Yara-rules-master", "rules")
    scanner = YaraScanner(rules_dir)
    return scanner
