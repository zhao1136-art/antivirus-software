"""yara_scanner 单元测试 —— **真 libyara 后端**。

2026-10-05 变更：本项目原来的 YARA 引擎是从零手写的子集（含 `_AhoCorasick`、
`_ac` 懒构建等内部实现）。现已替换为自建的 `libyara.dll`（YARA 4.5.5，见
engine/native/yara/BUILD.md），因此旧测试中针对被替换实现的用例（自动机、
懒构建）不再适用，改为**语义正确性**用例 —— 这正是当初驱动这次替换的原因：
旧引擎在这 7 项里有 5 项是错的。
"""
import os
import tempfile

import pytest

from engine.yara_scanner import YaraRule, YaraScanner, create_scanner

RULES = r'''
rule demo_nocase
{
    strings:
        $a = "EvilMarker" nocase
    condition:
        $a
}

rule demo_fullword
{
    strings:
        $a = "cat" fullword
    condition:
        $a
}

rule demo_count
{
    strings:
        $a = "HIT"
    condition:
        #a > 3
}

rule demo_xor
{
    strings:
        $a = "SecretKey" xor
    condition:
        $a
}

rule demo_hexjump
{
    strings:
        $a = { DE AD [4-6] BE EF }
    condition:
        $a
}

rule demo_regex
{
    strings:
        $a = /ab+c/
    condition:
        $a
}

rule demo_filesize
{
    condition:
        filesize > 100
}

rule demo_meta
{
    meta:
        malware_type = "trojan"
        description = "meta test"
    strings:
        $s1 = "EICAR"
        $s2 = "malicious"
    condition:
        any of them
}
'''


@pytest.fixture()
def scanner():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "t.yar"), "w", encoding="utf-8") as f:
            f.write(RULES)
        sc = YaraScanner(d)
        yield sc
        sc.close()


def _names(hits):
    return sorted(h["rule"] for h in hits)


# ══════════════════════════════════════════════════════════════════════
# 语义正确性 —— 这些用例在旧的自制引擎上有 5 个是错的
# ══════════════════════════════════════════════════════════════════════

class TestSemantics:
    def test_nocase_matches_lowercase(self, scanner):
        # 旧引擎漏报：它只认第一个修饰符且未实现 nocase
        assert _names(scanner.scan_content(b"...evilmarker...")) == ["demo_nocase"]

    def test_fullword_rejects_substring(self, scanner):
        # 旧引擎误报："cat" 会命中 "concatenate"
        assert _names(scanner.scan_content(b"this is concatenate text")) == []

    def test_fullword_accepts_real_word(self, scanner):
        assert "demo_fullword" in _names(scanner.scan_content(b"a cat sat"))

    def test_count_threshold_respected(self, scanner):
        # 旧引擎误报：#a>3 只要出现 1 次就命中
        assert _names(scanner.scan_content(b"only one HIT here")) == []
        assert "demo_count" in _names(scanner.scan_content(b"HIT HIT HIT HIT"))

    def test_xor_string(self, scanner):
        # 旧引擎漏报：未实现 xor
        enc = bytes(b ^ 0x41 for b in b"SecretKey")
        assert _names(scanner.scan_content(b"pad" + enc + b"pad")) == ["demo_xor"]

    def test_hex_jump(self, scanner):
        # 旧引擎漏报：[4-6] 被当成单个通配字节
        data = b"\xde\xad" + b"\x01\x02\x03\x04" + b"\xbe\xef"
        assert _names(scanner.scan_content(data)) == ["demo_hexjump"]

    def test_regex_string(self, scanner):
        # 旧引擎漏报：正则字符串压根不解析
        assert _names(scanner.scan_content(b"xxabbbcxx")) == ["demo_regex"]

    def test_filesize_only_condition(self, scanner):
        # 旧引擎漏报：无字符串时条件退化为 any，永不成立
        assert _names(scanner.scan_content(b"z" * 200)) == ["demo_filesize"]
        assert _names(scanner.scan_content(b"z" * 50)) == []


# ══════════════════════════════════════════════════════════════════════
# 公开 API / 返回结构（调用方契约）
# ══════════════════════════════════════════════════════════════════════

class TestContract:
    def test_rules_loaded(self, scanner):
        assert len(scanner.rules) == 8
        assert scanner.compile_errors == []

    def test_hit_dict_shape(self, scanner):
        hits = scanner.scan_content(b"EICAR", "sample.bin")
        assert len(hits) == 1
        h = hits[0]
        for key in ("rule", "description", "malware_type", "source_file",
                    "matched_patterns", "meta", "confidence", "quality_reason"):
            assert key in h, key
        assert h["rule"] == "demo_meta"
        assert h["malware_type"] == "TROJAN"          # meta 值大写
        assert h["description"] == "meta test"
        assert "$s1" in h["matched_patterns"]
        assert h["confidence"] in ("high", "medium", "low")

    def test_no_match_returns_empty(self, scanner):
        assert scanner.scan_content(b"haystack with nothing") == []

    def test_empty_content(self, scanner):
        assert scanner.scan_content(b"") == []

    def test_scan_file(self, scanner):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"EICAR payload")
            path = f.name
        try:
            assert _names(scanner.scan_file(path)) == ["demo_meta"]
        finally:
            os.unlink(path)

    def test_scan_content_typed(self, scanner):
        assert _names(scanner.scan_content_typed(b"EICAR", "x", 5)) == ["demo_meta"]

    def test_rule_confidence_lookup(self, scanner):
        assert scanner.rule_confidence("demo_meta") in ("high", "medium", "low")
        assert scanner.rule_confidence("不存在的规则") == "medium"

    def test_quality_stats_present(self, scanner):
        assert set(scanner.quality_stats) >= {"high", "medium", "low"}

    def test_create_scanner_factory(self):
        sc = create_scanner()
        assert isinstance(sc, YaraScanner)
        assert sc.rules == []
        sc.close()

    def test_libyara_actually_loaded(self, scanner):
        assert scanner.libyara_path.endswith("libyara.dll")
        assert os.path.isfile(scanner.libyara_path)


class TestYaraRule:
    def test_properties(self):
        r = YaraRule("R")
        r.meta = {"malware_type": "backdoor", "description": "desc"}
        assert r.malware_type == "BACKDOOR"
        assert r.description == "desc"
        assert r.total_patterns == 0

    def test_defaults(self):
        r = YaraRule("R2", "a.yar")
        assert r.malware_type == "UNKNOWN"
        assert r.description == "R2"
        assert r.quality is None


class TestDisabledDirs:
    def test_underscore_dirs_are_skipped(self):
        """`_disabled/` 与点开头目录必须被剪枝。

        旧实现踩过的坑：把 LNK_Ruleset.yar 移进 _disabled/ 以为停用了，但
        os.walk 仍会递归进去照旧加载 —— 那次"停用"等于没做。
        """
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "_disabled"))
            with open(os.path.join(d, "on.yar"), "w", encoding="utf-8") as f:
                f.write('rule On { strings: $a = "AAA" condition: $a }')
            with open(os.path.join(d, "_disabled", "off.yar"), "w", encoding="utf-8") as f:
                f.write('rule Off { strings: $a = "BBB" condition: $a }')
            sc = YaraScanner(d)
            assert [r.name for r in sc.rules] == ["On"]
            sc.close()


class TestCompileErrors:
    def test_unreferenced_string_is_reported_not_fatal(self):
        """真 YARA 会拒绝整个文件；这里要能报出来且不影响其它文件。"""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "good.yar"), "w", encoding="utf-8") as f:
                f.write('rule Good { strings: $a = "AAA" condition: $a }')
            with open(os.path.join(d, "bad.yar"), "w", encoding="utf-8") as f:
                f.write('rule Bad\n{\n    strings:\n        $x = "BBB"\n'
                        '        $unused = "CCC"\n    condition:\n        $x\n}\n')
            sc = YaraScanner(d)
            assert os.path.basename(sc.compile_errors[0][0]) == "bad.yar"
            assert "unreferenced" in sc.compile_errors[0][1].lower()
            # 好的文件仍然生效
            assert "Good" in _names(sc.scan_content(b"AAA"))
            assert _names(sc.scan_content(b"CCC")) == []
            sc.close()


class TestIndexContract:
    """守住 `_rules_pe` / `_rules_elf` / `_rules_generic` / `_rules_filesize`。

    2026-10-05 教训：把引擎换成 libyara 时，我删掉了这四个旧的"文件类型索引"
    属性（以为随引擎一起作废），结果 `app.py` 的
    `/api/v1/scan/perf-stats`（1268-1270）与 `/api/v1/version`（3167-3168）
    读它们时抛 AttributeError，被 except 兜成 HTTP 500 —— 前端"引擎性能"
    面板整块显示为 0。这四个属性必须存在。
    """

    def test_index_attributes_exist(self, scanner):
        for attr in ("_rules_pe", "_rules_elf", "_rules_generic", "_rules_filesize"):
            assert hasattr(scanner, attr), f"缺少 {attr}（app.py 会读它）"
            assert isinstance(getattr(scanner, attr), list)

    def test_app_py_expressions_do_not_raise(self, scanner):
        """逐字复刻 app.py 的两处表达式。"""
        y = scanner
        # app.py:1266-1271
        info = {
            "total_rules": len(y.rules),
            "pe_rules": len(y._rules_pe),
            "elf_rules": len(y._rules_elf),
            "generic_rules": len(y._rules_generic),
        }
        assert info["total_rules"] == 8
        assert sum(info[k] for k in ("pe_rules", "elf_rules", "generic_rules")) == 8
        # app.py:3166-3168
        assert isinstance(len(y._rules_pe), int)
        assert isinstance(len(y._rules_generic), int)

    def test_indices_are_reset_on_reload(self, scanner):
        before = len(scanner._rules_generic)
        scanner.load_rules(scanner._rules_dir)
        assert len(scanner._rules_generic) == before, "重复 load_rules 会累加索引"

    def test_indices_do_not_affect_scanning(self, scanner):
        """索引只用于统计 —— 换成哨兵不应改变扫描结果。

        旧实现用它们按文件类型挑规则子集；libyara 全量扫描既正确又快，
        过滤反而会让"没有 MZ 头的样本"拿不到 PE 规则（漏报）。
        """
        sample = b"hello EICAR world"
        baseline = _names(scanner.scan_content(sample))
        assert baseline, "样本本身应命中 demo_meta"
        scanner._rules_pe = ["SENTINEL"]
        scanner._rules_elf = ["SENTINEL"]
        scanner._rules_generic = ["SENTINEL"]
        scanner._rules_filesize = ["SENTINEL"]
        assert _names(scanner.scan_content(sample)) == baseline

    def test_pe_rules_counted_by_condition(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pe.yar"), "w", encoding="utf-8") as f:
                f.write('rule PeOne {\n    strings:\n        $a = "MZRULE"\n'
                        '    condition:\n        uint16(0) == 0x5a4d and $a\n}\n')
            with open(os.path.join(d, "gen.yar"), "w", encoding="utf-8") as f:
                f.write('rule GenOne {\n    strings:\n        $a = "GENRULE"\n'
                        '    condition:\n        $a\n}\n')
            sc = YaraScanner(d)
            assert [r.name for r in sc._rules_pe] == ["PeOne"]
            assert [r.name for r in sc._rules_generic] == ["GenOne"]
            sc.close()
