"""从 maltrail 静态 IOC 构建紧凑的第三方黑名单索引。

数据来源：maltrail（https://github.com/stamparm/maltrail，MIT 许可）
  输入 —— maltrail-master/trails/static/**/*.txt
  输出 —— backend/engine/data/ioc/url_extra.u64   恶意域名（uint64 排序数组）
          backend/engine/data/ioc/ip_extra.u64    恶意 IP
          backend/engine/data/ioc/url_extra_meta.json

只收 `static/malware` 与 `static/malicious` 两类；`static/suspicious` 是
"可疑"而非"已定性恶意"，按本项目"宁可漏报，不可滥杀"的原则不进拦截。

用法：
  python tools\\build_ioc_index.py --zip "H:\\新建文件夹\\maltrail-master.zip"
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import struct
import time
import zipfile
import hashlib
import zlib

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

# 只收这两类；见模块说明
INCLUDE_CATEGORIES = ("static/malware", "static/malicious")

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "backend", "engine", "data", "ioc")


def h64(s: str) -> int:
    """blake2b-64（真 64 位，不受 PYTHONHASHSEED 影响）。

    旧实现是 crc32 两遍拼接：看着 64 位，但两次 crc32 高度相关，
    有效熵只有约 **32 位** —— 106 万条域名下生日碰撞概率约 1.3%。
    """
    return int.from_bytes(
        hashlib.blake2b(s.encode("utf-8", "ignore"), digest_size=8).digest(),
        "little")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", required=True, help="maltrail-master.zip 路径")
    ap.add_argument("--out", default=OUT_DIR)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    domains: set[str] = set()
    ips: set[str] = set()
    by_category = collections.Counter()
    wildcards = 0
    files = 0
    t0 = time.time()

    with zipfile.ZipFile(args.zip) as zf:
        for n in zf.namelist():
            if not n.lower().endswith(".txt") or "/trails/" not in n:
                continue
            parts = n.split("/")
            try:
                i = parts.index("trails")
                cat = "/".join(parts[i + 1:-1]) or "root"
            except ValueError:
                cat = "?"
            files += 1
            try:
                raw = zf.read(n).decode("utf-8", "ignore")
            except Exception:
                continue
            for line in raw.splitlines():
                s = line.strip().lower()
                if not s or s.startswith("#"):
                    continue
                if "*" in s:
                    wildcards += 1
                    continue
                # 行内注释/附加列：取第一个分隔符之前
                for sep in ("#", ",", ";", "|", " "):
                    if sep in s:
                        s = s.split(sep, 1)[0].strip()
                s = s.strip(".")
                if not s:
                    continue
                if IP_RE.match(s):
                    ips.add(s)
                elif DOMAIN_RE.match(s):
                    if cat in INCLUDE_CATEGORIES:
                        domains.add(s)
                        by_category[cat] += 1

    print(f"扫描 {files} 个 IOC 文件，耗时 {time.time()-t0:.1f}s")
    print(f"纳入域名 {len(domains):,}   恶意 IP {len(ips):,}   跳过通配 {wildcards:,}")
    for k, v in by_category.most_common():
        print(f"  {k:<24}{v:>10,}")

    dpath = os.path.join(args.out, "url_extra.u64")
    with open(dpath, "wb") as f:
        f.write(struct.pack(f"<{len(domains)}Q",
                            *sorted(h64(d) for d in domains)))
    ipath = os.path.join(args.out, "ip_extra.u64")
    with open(ipath, "wb") as f:
        f.write(struct.pack(f"<{len(ips)}Q", *sorted(h64(i) for i in ips)))

    meta = {
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": "maltrail (https://github.com/stamparm/maltrail)",
        "license": "MIT",
        "attribution": "Copyright (c) 2014-2026 Maltrail developers",
        "categories": list(INCLUDE_CATEGORIES),
        "domain_count": len(domains),
        "ip_count": len(ips),
        "skipped_wildcards": wildcards,
        "hash": "blake2b-64 (digest_size=8, little-endian)",
        "hash_algo": "blake2b-64",
        "files": {"domains": "url_extra.u64", "ips": "ip_extra.u64"},
    }
    with open(os.path.join(args.out, "url_extra_meta.json"), "w",
              encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print(f"\n域名索引 -> {dpath}  {os.path.getsize(dpath)/1048576:.2f} MB")
    print(f"IP  索引 -> {ipath}  {os.path.getsize(ipath)/1048576:.2f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

