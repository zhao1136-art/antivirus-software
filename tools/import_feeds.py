"""从外部威胁情报源导入 IOC，生成紧凑索引（与 engine/ioc_index 同格式）。

许可守卫
--------
每个源都标注许可；**NC/SA 类源直接拒绝导入**（例如 C2IntelFeeds 的
CC BY-NC-SA 4.0 商业产品不可用），避免"能跑就不管许可"的隐患。

源现状（2026-10 实测）
---------------------
- abuse.ch Feodo：匿名可拉，但列表已很小（QakBot/Emotet 大部分下线）
- abuse.ch URLhaus / ThreatFox：**必须带 Auth-Key**（免费，需在
  https://auth.abuse.ch/ 注册）。用 --auth-key 或环境变量 ABUSECH_AUTH_KEY 传入。
- 这些源均为 **CC0**，可随商业产品发布。

用法
----
  python tools\\import_feeds.py --source feodo
  set ABUSECH_AUTH_KEY=xxxx
  python tools\\import_feeds.py --source urlhaus --source threatfox
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
import time
import urllib.request
import zlib

IOC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "backend", "engine", "data", "ioc")
UA = {"User-Agent": "andun-ioc/1.0"}

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HOST_RE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

# source -> (url, license, requires_key, kind)
SOURCES = {
    "feodo": ("https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
              "CC0", False, "ip"),
    "urlhaus": ("https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
                "CC0", True, "url"),
    "threatfox": ("https://threatfox-api.abuse.ch/api/v1/",
                  "CC0", True, "threatfox"),
}

# 明确禁止导入的源（许可不允许商用/再分发）
DENY_LICENSES = ("CC BY-NC", "NonCommercial", "BY-NC-SA", "proprietary")


def h64(s: str) -> int:
    b = s.encode("utf-8", "ignore")
    return (zlib.crc32(b) & 0xFFFFFFFF) | \
           ((zlib.crc32(b, 0x9E3779B9) & 0xFFFFFFFF) << 32)


def fetch(url: str, auth_key: str = "", timeout: int = 60) -> bytes:
    headers = dict(UA)
    if auth_key:
        headers["Auth-Key"] = auth_key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def parse_csv_text(raw: bytes):
    """逐行 csv 解析，跳过 # 注释。"""
    import csv
    import io
    txt = raw.decode("utf-8", "ignore")
    body = "\n".join(ln for ln in txt.splitlines()
                     if ln.strip() and not ln.lstrip().startswith("#"))
    return list(csv.reader(io.StringIO(body)))


def collect_feodo(raw: bytes) -> tuple[set[str], set[str]]:
    ips: set[str] = set()
    rows = parse_csv_text(raw)
    for r in rows:
        for cell in r:
            v = cell.strip().strip('"')
            if IP_RE.match(v):
                ips.add(v)
                break
    return ips, set()


def collect_urlhaus(raw: bytes) -> tuple[set[str], set[str]]:
    """URLhaus 导出：行内包含 url / host。取出 host 的注册域名。"""
    ips: set[str] = set()
    hosts: set[str] = set()
    for row in parse_csv_text(raw):
        for cell in row:
            v = cell.strip().strip('"').lower()
            if IP_RE.match(v):
                ips.add(v)
                continue
            if "://" in v:
                v = v.split("://", 1)[1].split("/", 1)[0]
            v = v.split(":", 1)[0].strip(".")
            if HOST_RE.match(v):
                hosts.add(v)
    return ips, hosts


def collect_threatfox(raw: bytes) -> tuple[set[str], set[str]]:
    """ThreatFox API: JSON {"data":[{"ioc_value":...}]}"""
    ips: set[str] = set()
    hosts: set[str] = set()
    try:
        doc = json.loads(raw.decode("utf-8", "ignore"))
    except ValueError:
        return ips, hosts
    for item in (doc.get("data") or []):
        v = str(item.get("ioc_value") or "").strip().lower()
        if not v:
            continue
        if IP_RE.match(v):
            ips.add(v)
        elif HOST_RE.match(v):
            hosts.add(v)
    return ips, hosts


COLLECTORS = {"feodo": collect_feodo, "urlhaus": collect_urlhaus,
              "threatfox": collect_threatfox}


def write_index(path: str, values: set[str]):
    with open(path, "wb") as f:
        f.write(struct.pack(f"<{len(values)}Q",
                            *sorted(h64(v) for v in values)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", action="append", required=True,
                    choices=sorted(SOURCES))
    ap.add_argument("--auth-key", default=os.environ.get("ABUSECH_AUTH_KEY", ""))
    ap.add_argument("--out", default=IOC_DIR)
    ap.add_argument("--merge", action="store_true",
                    help="把 IP 结果并入 c2_ip.u64（默认覆盖）")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    all_ips: set[str] = set()
    all_hosts: set[str] = set()
    used = []

    for src in args.source:
        url, lic, need_key, _kind = SOURCES[src]
        if any(d.lower() in lic.lower() for d in DENY_LICENSES):
            print(f"!! 拒绝导入 {src}：许可 {lic} 不允许商用/再分发")
            continue
        if need_key and not args.auth_key:
            print(f"!! 跳过 {src}：需要 Auth-Key（免费注册 https://auth.abuse.ch/）")
            continue
        u = url.format(key=args.auth_key) if "{key}" in url else url
        headers = dict(UA)
        if need_key:
            headers["Auth-Key"] = args.auth_key
        try:
            if src == "threatfox":
                import json as _json
                body = _json.dumps({"query": "get_iocs", "days": 7}).encode()
                req = urllib.request.Request(u, data=body, headers=headers)
                with urllib.request.urlopen(req, timeout=60) as r:
                    raw = r.read()
            else:
                req = urllib.request.Request(u, headers=headers)
                with urllib.request.urlopen(req, timeout=60) as r:
                    raw = r.read()
        except Exception as exc:
            print(f"!! {src} 下载失败: {type(exc).__name__}: {exc}")
            continue
        ips, hosts = COLLECTORS[src](raw)
        print(f"   {src:<10} {len(raw)/1024:>8.1f} KB   IP {len(ips):>6}  "
              f"域名 {len(hosts):>6}   许可 {lic}")
        all_ips |= ips
        all_hosts |= hosts
        used.append({"source": src, "license": lic, "url": u,
                     "ips": len(ips), "hosts": len(hosts)})

    if not used:
        print("没有成功导入的源")
        return 2

    ip_path = os.path.join(args.out, "c2_ip.u64")
    host_path = os.path.join(args.out, "url_feed.u64")
    write_index(ip_path, all_ips)
    write_index(host_path, all_hosts)

    meta = {
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "sources": used,
        "ip_count": len(all_ips),
        "host_count": len(all_hosts),
        "hash": "crc32(b) | crc32(b, 0x9E3779B9) << 32",
        "files": {"ips": "c2_ip.u64", "hosts": "url_feed.u64"},
    }
    with open(os.path.join(args.out, "feeds_meta.json"), "w",
              encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print(f"\nIP   {len(all_ips):,} -> {ip_path}")
    print(f"域名 {len(all_hosts):,} -> {host_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
