"""local_scanner 单元测试：特征库命中 / 干净文件 / 统计。"""
import os
import tempfile
import pytest

from engine.local_scanner import LocalScanner
from engine.signature_manager import SignatureManager


class FakeSig:
    """最小可替换特征库：lookup 恒为 None（干净文件路径）。"""

    def lookup(self, md5="", sha1="", sha256=""):
        return None


@pytest.fixture
def clean_scanner():
    return LocalScanner(FakeSig())


def test_clean_file_no_threat(clean_scanner):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "clean.txt")
        with open(p, "wb") as f:
            f.write(b"just some harmless bytes")
        threats = clean_scanner._scan_single_file(p)
        assert threats == []


def test_signature_threat_detected():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "sig.db")
        sig = SignatureManager(db)
        scanner = LocalScanner(sig)
        try:
            p = os.path.join(d, "evil.bin")
            content = b"malicious payload content here"
            with open(p, "wb") as f:
                f.write(content)
            md5 = __import__("hashlib").md5(content).hexdigest()
            sig.add_signature("md5", md5, "Unit.Test.Sample", "high", "trojan", "unit")

            threats = scanner._scan_single_file(p)
            assert len(threats) == 1
            t = threats[0]
            assert t["engine"] == "signature"
            assert t["signature"] == "Unit.Test.Sample"
            assert t["md5"] == md5
            assert t["threat_level"] == "high"
            assert t["action"] == "quarantine"
        finally:
            try:
                sig.close()
            except Exception:
                pass


def test_scan_paths_detects_signature():
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "sig.db")
        sig = SignatureManager(db)
        scanner = LocalScanner(sig)
        try:
            content = b"payload-that-should-be-flagged"
            md5 = __import__("hashlib").md5(content).hexdigest()
            sig.add_signature("md5", md5, "Pipe.Test", "medium", "trojan", "unit")
            with open(os.path.join(d, "a.bin"), "wb") as f:
                f.write(content)
            with open(os.path.join(d, "clean.txt"), "wb") as f:
                f.write(b"clean")

            res = scanner.scan_paths([d], scan_type="custom")
            assert res["threats_found"] >= 1
            engines = {t["engine"] for t in res["threats"]}
            assert "signature" in engines
        finally:
            try:
                sig.close()
            except Exception:
                pass


def test_perf_stats_present(clean_scanner):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x.bin")
        with open(p, "wb") as f:
            f.write(b"0" * 4096)
        clean_scanner._scan_single_file(p)
        stats = clean_scanner.get_perf_stats()
        assert "total_scans" in stats
        assert "cache_hits" in stats
        assert "avg_scan_time_ms" in stats
        assert stats["total_scans"] >= 1