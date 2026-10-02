"""signature_manager 单元测试：内存索引查询 / 写入 / 批量导入幂等。"""
import os
import tempfile
import pytest

from engine.signature_manager import SignatureManager


@pytest.fixture
def sig():
    """每个用例独立临时 DB，避免污染真实特征库。"""
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "test_signatures.db")
        m = SignatureManager(db)
        yield m
        try:
            m.close()
        except Exception:
            pass


def test_empty_lookup_returns_none(sig):
    assert sig.lookup(md5="0" * 32) is None


def test_add_and_lookup_md5(sig):
    md5 = "abcd" * 8  # 32 hex
    ok = sig.add_signature("md5", md5, "Win32/Trojan.Test", "high", "trojan", "unit-test")
    assert ok is True
    hit = sig.lookup(md5=md5.upper())  # 大小写不敏感
    assert hit is not None
    assert hit["threat_name"] == "Win32/Trojan.Test"
    assert hit["threat_level"] == "high"
    assert hit["matched_hash"] == "md5"


def test_add_duplicate_returns_false(sig):
    md5 = "11223344556677889900aabbccddeeff"
    assert sig.add_signature("md5", md5, "A", "low")
    assert sig.add_signature("md5", md5, "B", "low") is False


def test_sha256_lookup(sig):
    sha = "a" * 64
    sig.add_signature("sha256", sha, "SHA.Crafted", "critical", "rootkit", "t")
    hit = sig.lookup(sha256=sha)
    assert hit is not None
    assert hit["matched_hash"] == "sha256"


def test_get_stats(sig):
    sig.add_signature("md5", "0" * 32, "one", "high")
    stats = sig.get_stats()
    assert stats["total_signatures"] >= 1
    assert stats["by_level"].get("high", 0) >= 1
    assert stats["version"]


def test_import_md5_text_and_duplicates(sig):
    with tempfile.TemporaryDirectory() as d:
        txt = os.path.join(d, "vdl.txt")
        lines = ["not-a-hash", "", "aa" * 16, "bb" * 16, "aa" * 16]  # 1 非法 + 2 唯一 + 1 重复
        with open(txt, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        r = sig.import_md5_text(txt, batch_size=2)
    assert r["total_lines"] == 4  # 非空行：not-a-hash, aa, bb, aa（空行不计）
    assert r["imported"] == 2
    assert r["skipped"] == 2  # 1 非法行 + 1 重复行
    assert sig.lookup(md5="aa" * 16) is not None
    assert sig.lookup(md5="bb"* 16) is not None


def test_import_md5_incremental_idempotent(sig):
    tempdir = tempfile.mkdtemp()
    txt = os.path.join(tempdir, "vdl.txt")
    with open(txt, "w", encoding="utf-8") as f:
        f.write("cc" * 16)
    try:
        r1 = sig.import_md5_incremental(txt, version="20260419")
        assert r1["incremental"] is True
        assert r1["imported"] == 1
        # 相同版本重复导入 → 直接跳过
        r2 = sig.import_md5_incremental(txt, version="20260419")
        assert r2["status"] == "already_up_to_date"
    finally:
        try:
            os.remove(txt)
            os.rmdir(tempdir)
        except Exception:
            pass


def test_seed_signatures_present(sig):
    # 内建种子（Flame）启动即存在
    seed = "c81d037b723adc43e3ee17b1eee9d6cc"
    hit = sig.lookup(md5=seed)
    assert hit is not None
    assert "Flame" in hit["threat_name"]