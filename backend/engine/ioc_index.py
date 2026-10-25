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
import json
import os
import threading
import zlib

__all__ = ["match_domain", "match_ip", "get_ioc_stats", "reload"]

IOC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ioc")
DOMAIN_FILE = os.path.join(IOC_DIR, "url_extra.u64")
IP_FILE = os.path.join(IOC_DIR, "ip_extra.u64")
META_FILE = os.path.join(IOC_DIR, "url_extra_meta.json")

_lock = threading.Lock()
_state: dict | None = None


def h64(s: str) -> int:
    """稳定 64 位哈希：crc32 两遍拼接。"""
    b = s.encode("utf-8", "ignore")
    return (zlib.crc32(b) & 0xFFFFFFFF) | \
           ((zlib.crc32(b, 0x9E3779B9) & 0xFFFFFFFF) << 32)


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
        _state = {
            "domains": _load_u64(DOMAIN_FILE),
            "ips": _load_u64(IP_FILE),
            "meta": meta,
        }
    return _state


def _contains(arr: array.array, h: int) -> bool:
    """在有序数组中二分查找哈希。"""
    i = bisect.bisect_left(arr, h)
    return i < len(arr) and arr[i] == h


def match_domain(host: str) -> bool:
    """host 或其任一级父域名是否命中恶意域名索引。

    例：`a.b.evil.com` 会依次检查 `a.b.evil.com`、`b.evil.com`、`evil.com`，
    与火绒黑名单"裸注册域名匹配子域"的语义一致。
    """
    if not host:
        return False
    st = _ensure_loaded()
    arr = st["domains"]
    if not arr:
        return False
    h = host.strip().strip(".").lower()
    if not h:
        return False
    labels = h.split(".")
    # 少于两个标签（如 "localhost"）不查：索引里没有单级条目
    start = 0 if len(labels) >= 2 else len(labels)
    for i in range(start, len(labels) - 1):
        cand = ".".join(labels[i:])
        if _contains(arr, h64(cand)):
            return True
    return False


def match_ip(ip: str) -> bool:
    """IP 是否命中恶意 IP 索引（精确匹配）。"""
    if not ip:
        return False
    st = _ensure_loaded()
    arr = st["ips"]
    if not arr:
        return False
    return _contains(arr, h64(ip.strip().lower()))


def get_ioc_stats() -> dict:
    """索引统计（供界面/接口展示）。"""
    st = _ensure_loaded()
    meta = st["meta"] or {}
    return {
        "domains": len(st["domains"]),
        "ips": len(st["ips"]),
        "source": meta.get("source", "maltrail"),
        "license": meta.get("license", "MIT"),
        "built_at": meta.get("built_at", ""),
        "memory_mb": round((len(st["domains"]) + len(st["ips"])) * 8 / 1048576, 1),
    }


def reload():
    """清空缓存，下次查询时重新加载（数据更新后调用）。"""
    global _state
    with _lock:
        _state = None
