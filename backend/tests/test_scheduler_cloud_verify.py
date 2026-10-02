"""scheduler._cloud_verify_scan 单元测试：云端复核逻辑。"""
import os
import tempfile
import pytest

from engine.scheduler import Scheduler


class FakeCloudBatch:
    """模拟云端批量查询：按哈希返回威胁或无。"""

    def __init__(self, hits: dict):
        self._hits = hits
        self.available = True

    def lookup_hashes_batch(self, hashes):
        return {h: (self._hits.get(h) or None) for h in hashes}

    def lookup_hash(self, sha256=""):
        return self._hits.get(sha256)


def _make_result(threat_paths, scanned_files):
    return {
        "threats": [{"path": p, "sha256": None} for p in threat_paths],
        "_scanned_hashes": {},
        "_scanned_files": scanned_files,
        "threats_found": len(threat_paths),
    }


def test_empty_threats_returns_zero():
    from engine.scheduler import Scheduler
    fn = Scheduler._cloud_verify_scan
    # 需要真实实例对象；用 __new__ 绕过 __init__
    inst = Scheduler.__new__(Scheduler)
    inst.cloud = FakeCloudBatch({})
    res = _make_result([], [])
    assert fn(inst, res, []) == 0


def test_batch_hits_appended_to_cloud_hits():
    SchedulerLocal = Scheduler
    inst = SchedulerLocal.__new__(SchedulerLocal)
    with tempfile.TemporaryDirectory() as d:
        fp = os.path.join(d, "evil.bin")
        with open(fp, "wb") as f:
            f.write(b"xxx")
        # 计算 sha256
        import hashlib
        h = hashlib.sha256(b"xxx").hexdigest()
        inst.cloud = FakeCloudBatch({h: {
            "threat_name": "Cloud.Malware",
            "threat_level": "high",
            "engine": "andun",
        }})
        res = _make_result([fp], [])
        res["_scanned_hashes"][fp] = h
        cloud_hits = []
        checked = inst._cloud_verify_scan(res, cloud_hits)
        assert checked == 1
        assert len(cloud_hits) == 1
        hit = cloud_hits[0]
        assert hit["path"] == os.path.abspath(fp)
        assert hit["threat_name"] == "Cloud.Malware"


def test_non_existent_file_skipped():
    SchedulerLocal = Scheduler
    inst = SchedulerLocal.__new__(SchedulerLocal)
    inst.cloud = FakeCloudBatch({})
    res = _make_result([r"C:\nonexistent\file.bin"], [])
    cloud_hits = []
    checked = inst._cloud_verify_scan(res, cloud_hits)
    assert checked == 0
    assert cloud_hits == []


def test_no_threats_short_circuits_scanned_files():
    """真实行为：threats 为空时 _cloud_verify_scan 提前 return 0，
    不会去遍历 _scanned_files（该分支仅在存在威胁时才可能执行）。"""
    SchedulerLocal = Scheduler
    inst = SchedulerLocal.__new__(SchedulerLocal)
    with tempfile.TemporaryDirectory() as d:
        fp = os.path.join(d, "extra.bin")
        with open(fp, "wb") as f:
            f.write(b"data")
        import hashlib
        h = hashlib.sha256(b"data").hexdigest()
        inst.cloud = FakeCloudBatch({h: {"threat_name": "CloudSusp", "threat_level": "medium"}})
        # threats 为空，但 _scanned_files 非空
        res = _make_result([], [fp])
        res["_scanned_hashes"][fp] = h
        cloud_hits = []
        checked = inst._cloud_verify_scan(res, cloud_hits)
        assert checked == 0
        assert cloud_hits == []