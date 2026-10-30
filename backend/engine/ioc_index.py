"""第三方 IOC 索引 —— 紧凑 uint64 二分查找，支持"裸域名匹配子域"。

数据来源与许可
--------------
`engine/data/ioc/` 下的两个二进制索引由 maltrail 的静态 IOC 生成：
  · url_extra.u64 —— 1,061,714 个恶意域名（malware + malicious 两类；
    static/suspicious 按"宁可漏报不可滥杀"刻意排除）
  · ip_extra.u64  —— 22,747 个恶意 IP
maltrail 为 MIT 许可（Copyright (c) 2014-2026 Maltrail developers），
可随产品发布，保留声明即可。构建脚本见 tools/build_ioc_index.py。

为什么不用 Python set
--------------------
1.1M 个 str 在 CPython 里约 130MB+，对桌面杀软常驻内存不可接受。
这里存成排序好的 uint64 哈希数组（8.1MB），查询时对 host 及其各级后缀
各做一次二分查找 —— 既保留"example.com 命中 a.b.example.com"的语义，
内存又只有 set 的 1/15。

哈希用 crc32 双拼（不是内置 hash()，后者受 PYTHONHASHSEED 影响，重启就变）。
碰撞概率 n²/2^65 ≈ 3e-8，且后果是"多拦一个名字"，不涉及放行，可接受。
"""
from __future__ import annotations

import bisect
import array
import hashlib
import json
import os
import threading
import zlib

__all__ = ["match_domain", "match_ip", "get_ioc_stats", "reload",
           "hash64", "HASH_BLAKE2B", "HASH_LEGACY"]

IOC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ioc")
# 每类可以有多个索引文件（来源分开存，便于各自更新与溯源）：
#   url_extra.u64 —— maltrail 静态库（MIT）
#   url_feed.u64  —— 动态拉取的 URL/域名情报（当前为 abuse.ch，CC0）
#   ip_extra.u64  —— maltrail 静态库（MIT）
#   c2_ip.u64     —— 动态拉取的 C2 IP（IPsum + Feodo，Unlicense/CC0）
DOMAIN_FILES = ["url_extra.u64", "url_feed.u64"]
IP_FILES = ["ip_extra.u64", "c2_ip.u64"]
META_FILE = os.path.join(IOC_DIR, "url_extra_meta.json")
FEEDS_META_FILE = os.path.join(IOC_DIR, "feeds_meta.json")

# ── 哈希算法 ──────────────────────────────────────────────────────
# v1（legacy）：crc32 两遍拼接 —— 直觉上 64 位，但两次 crc32 高度相关，
#   实际有效熵只有约 **32 位**。106 万条域名下生日碰撞概率 ≈ 1.3%，
#   意味着约一万多对无关域名会互相"命中"（拦截向，只多拦不放行，但仍应修）。
# v2：blake2b-64 —— 真 64 位，106 万条下碰撞概率 ≈ 3e-8。
# 索引文件用哪个算法记录在各自的 meta JSON 里；加载时按文件选择，
# 因此新旧索引可以并存（重建过程中某个源失败时不会静默错配）。
HASH_LEGACY = "crc32x2"
HASH_BLAKE2B = "blake2b-64"


def hash64(s: str, algo: str = HASH_BLAKE2B) -> int:
    """把字符串映射成 64 位整数；algo 决定用哪套哈希。"""
    b = s.encode("utf-8", "ignore")
    if algo == HASH_LEGACY:
        return (zlib.crc32(b) & 0xFFFFFFFF) | \
               ((zlib.crc32(b, 0x9E3779B9) & 0xFFFFFFFF) << 32)
    digest = hashlib.blake2b(b, digest_size=8).digest()
    return int.from_bytes(digest, "little")


def h64(s: str) -> int:
    """向后兼容别名（旧代码调用；等价于 blake2b-64）。"""
    return hash64(s, HASH_BLAKE2B)


# 懒加载状态与锁（此前在重构哈希函数时被误删，导致 _ensure_loaded 抛 NameError）
_lock = threading.Lock()
_state: dict | None = None


def _load_u64(path: str) -> array.array:
    """把文件读成 uint64 数组（按需，失败返回空数组）。"""
    arr = array.array("Q")
    try:
        size = os.path.getsize(path)
        n = size // 8
        if n <= 0:
            return arr
        with open(path, "rb") as f:
            arr.fromfile(f, n)
    except (OSError, ValueError):
        return array.array("Q")
    return arr


def _ensure_loaded() -> dict:
    global _state
    if _state is not None:
        return _state
    with _lock:
        if _state is not None:
            return _state
        meta = {}
        try:
            with open(META_FILE, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except (OSError, ValueError):
            meta = {}
        feeds = {}
        try:
            with open(FEEDS_META_FILE, "r", encoding="utf-8") as f:
                feeds = json.load(f)
        except (OSError, ValueError):
            feeds = {}
        _state = {
            # 每项 = (哈希算法, 有序数组)。算法按文件记，新旧索引可并存：
            # 重建过程中若某个源失败，旧文件仍按旧算法正确匹配，不会静默错配。
            "domains": [
                (meta.get("hash_algo") or HASH_LEGACY, arr)
                for arr in (_load_u64(os.path.join(IOC_DIR, n)) for n in DOMAIN_FILES)
                if arr
            ],
            "ips": [
                (feeds.get("hash_algo") or HASH_LEGACY, arr)
                for arr in (_load_u64(os.path.join(IOC_DIR, n)) for n in IP_FILES)
                if arr
            ],
            "meta": meta,
            "feeds": feeds,
        }
    return _state


def _contains_any(arrays: list, value: str) -> bool:
    """在多个 (algo, 有序数组) 中查找 value 的哈希（并集语义）。

    同一个候选串在两套算法下哈希不同 → 按每个索引文件自己的算法分别计算。
    """
    for algo, arr in arrays:
        h = hash64(value, algo)
        i = bisect.bisect_left(arr, h)
        if i < len(arr) and arr[i] == h:
            return True
    return False


def match_domain(host: str) -> bool:
    """host 或其任一级父域名是否命中恶意域名索引。

    例：`a.b.evil.com` 会依次检查 `a.b.evil.com`、`b.evil.com`、`evil.com`，
    与火绒黑名单"裸注册域名匹配子域"的语义一致。
    """
    if not host:
        return False
    st = _ensure_loaded()
    arrs = st["domains"]
    if not arrs:
        return False
    h = host.strip().strip(".").lower()
    if not h:
        return False
    labels = h.split(".")
    # 少于两个标签（如 "localhost"）不查：索引里没有单级条目
    start = 0 if len(labels) >= 2 else len(labels)
    for i in range(start, len(labels) - 1):
        cand = ".".join(labels[i:])
        if _contains_any(arrs, cand):
            return True
    return False


def match_ip(ip: str) -> bool:
    """IP 是否命中恶意 IP 索引（精确匹配）。"""
    if not ip:
        return False
    st = _ensure_loaded()
    arrs = st["ips"]
    if not arrs:
        return False
    return _contains_any(arrs, ip.strip().lower())


def get_ioc_stats() -> dict:
    """索引统计（供界面/接口展示）。

    ⚠️ st["domains"] / st["ips"] 现在是 [(hash_algo, array), ...]，
    统计必须取 `arr` 的长度而不是元组长度（否则会显示 domains=2、ips=4 这种假数）。
    """
    st = _ensure_loaded()
    meta = st["meta"] or {}
    feeds = st["feeds"] or {}
    n_dom = sum(len(arr) for _algo, arr in st["domains"])
    n_ip = sum(len(arr) for _algo, arr in st["ips"])
    return {
        "domains": n_dom,
        "ips": n_ip,
        "source": meta.get("source", "maltrail"),
        "license": meta.get("license", "MIT"),
        "built_at": meta.get("built_at", ""),
        "memory_mb": round((n_dom + n_ip) * 8 / 1048576, 2),
        "hash_algo": {
            "domains": [a for a, _arr in st["domains"]],
            "ips": [a for a, _arr in st["ips"]],
        },
        "feed_sources": [s.get("source") for s in (feeds.get("sources") or [])],
        "feed_built_at": feeds.get("built_at", ""),
    }


def reload():
    """清空缓存，下次查询时重新加载（数据更新后调用）。"""
    global _state
    with _lock:
        _state = None
