"""yara_scanner 单元测试：Aho-Corasick 多模式匹配 + 规则解析/匹配。"""
import os
import tempfile
import pytest

from engine.yara_scanner import _AhoCorasick, YaraScanner, YaraRule


class TestAhoCorasick:
    def test_single_pattern(self):
        ac = _AhoCorasick()
        ac.add(b"abc", "payload1")
        ac.build()
        assert ac.find(b"xxabcyy") == ["payload1"]
        assert ac.find(b"zzz") == []

    def test_overlapping_patterns(self):
        ac = _AhoCorasick()
        ac.add(b"a", "A")
        ac.add(b"ab", "AB")
        ac.add(b"b", "B")
        ac.build()
        hits = ac.find(b"ab")
        assert set(hits) == {"A", "AB", "B"}

    def test_empty_safe(self):
        ac = _AhoCorasick()
        ac.build()  # 不应抛异常
        assert ac.find(b"abc") == []

    def test_wide_and_ascii_distinct(self):
        # 验证 ascii 与 wide 自动机互不混杂（交给 YaraScanner 场景覆盖）
        ac = _AhoCorasick()
        ac.add("恶意".encode("utf-16-le"), "wide")
        ac.build()
        assert ac.find("恶意".encode("utf-8")) == []
        assert len(ac.find("恶意".encode("utf-16-le"))) == 1


class TestYaraScanner:
    def _make_scanner(self, rules_text: str):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "test.yar"), "w", encoding="utf-8") as f:
                f.write(rules_text)
            return YaraScanner(d)

    def test_ascii_string_match_and_condition(self):
        sc = self._make_scanner("""
rule TestRule {
    meta:
        malware_type = "trojan"
        description = "test"
    strings:
        $s1 = "EICAR"
        $s2 = "malicious"
    condition:
        any of them
}
""")
        assert len(sc.rules) == 1
        res = sc.scan_content(b"hello EICAR world")
        assert len(res) == 1
        assert res[0]["rule"] == "TestRule"
        assert res[0]["malware_type"] == "TROJAN"
        assert res[0]["matched_patterns"] == ["$s1"]

    def test_no_match(self):
        sc = self._make_scanner("""
rule TestRule {
    strings:
        $s1 = "needle"
    condition:
        all of them
}
""")
        assert sc.scan_content(b"haystack no match here") == []

    def test_wide_string_match(self):
        sc = self._make_scanner("""
rule WideRule {
    strings:
        $w = "evil" wide
    condition:
        $w
}
""")
        data = "pre_eVIL_suf".replace("evil", "evil".upper()).encode() + "拜evil拜".encode("utf-16-le")
        # 构造含 UTF-16LE 的 "evil"
        wide_data = b"AA" + "evil".encode("utf-16-le") + b"BB"
        res = sc.scan_content(wide_data)
        assert len(res) == 1
        assert "$w" in res[0]["matched_patterns"]

    def test_mz_check_condition(self):
        sc = self._make_scanner("""
rule PeRule {
    strings:
        $s = "marker"
    condition:
        uint16(0) == 0x5a4d and $s
}
""")
        assert len(sc.scan_content(b"MZ" + b"marker")) == 1
        assert sc.scan_content(b"not-mz-marker") == []

    def test_hex_pattern_wildcard(self):
        sc = self._make_scanner("""
rule HexRule {
    strings:
        $h = { 4D 5A 90 ?? 00 }
    condition:
        $h
}
""")
        assert len(sc.scan_content(b"\x4d\x5a\x90\xff\x00")) == 1
        assert sc.scan_content(b"\x4d\x5a\x91\xff\x00") == []

    def test_parse_returns_lazy_ac_not_built_without_scan(self):
        sc = self._make_scanner("rule R { strings: $s=\"x\" condition: $s }")
        assert sc._ac is None
        sc.scan_content(b"x")
        assert sc._ac is not None  # 懒构建

    def test_rule_properties(self):
        r = YaraRule("R")
        r.meta = {"malware_type": "backdoor", "description": "desc"}
        assert r.malware_type == "BACKDOOR"
        assert r.description == "desc"