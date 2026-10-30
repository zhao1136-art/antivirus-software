"""从外部威胁情报源导入 IOC，生成紧凑索引（与 engine/ioc_index 同格式）。

许可守卫
--------
每个源都标注许可；**NC/SA 类源直接拒绝导入**（例如 C2IntelFeeds 的
CC BY-NC-SA 4.0 商业产品不可用），避免"能跑就不管许可"的隐患。

当前采用范围（2026-10-30 维护者决定）
------------------------------------
生产只用 **IPsum + Feodo** 两个源：
  · ipsum —— The Unlicense（公有领域），无需注册，约 2 万条高置信 IP
  · feodo —— CC0，匿名可拉（abuse.ch 策略调整后列表很小，仅作补充）
`urlhaus` / `threatfox` 代码保留，但它们自 2025 年起**必须 Auth-Key**
（免费，需在 https://auth.abuse.ch/ 注册），默认不启用 —— 需要时显式
`--source urlhaus` 并设置环境变量 `ABUSECH_AUTH_KEY`。

源现状（2026-10 实测）
---------------------
- abuse.ch Feodo：匿名可拉，但列表已很小（QakBot/Emotet 大部分下线）
- abuse.ch URLhaus / ThreatFox：**必须带 Auth-Key**，旧无鉴权路径已 410 Gone
- 这些源均为 **CC0**，可随商业产品发布。

用法
----
  python tools\\import_feeds.py --source ipsum --source feodo      # 生产默认
  set ABUSECH_AUTH_KEY=xxxx
  python tools\\import_feeds.py --source urlhaus --source threatfox # 注册后可选
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
    # IPsum：stamparm（maltrail 作者）聚合 30+ 公开黑名单，每行 "IP\t<出现在几个名单里>"。
    # 许可是 **The Unlicense（公有领域）**，可商用、可再分发，无需注册。
    # 这是 abuse.ch 在 IP 侧最合适的替代：可自行按置信分数过滤。
    "ipsum": ("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
              "Unlicense (public domain)", False, "ipsum"),
}

# IPsum 的最低置信分数：README 建议"出现在 ≥3 个名单里"才用于自动封禁
IPSUM_MIN_SCORE = 3

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


def collect_ipsum(raw: bytes, min_score: int = IPSUM_MIN_SCORE) -> tuple[set[str], set[str]]:
    """IPsum：每行 "IP<TAB>分数"（分数 = 出现在多少个公开黑名单里）。

    只收分数 >= min_score 的条目 —— 单名单命中的 IP 误报率明显更高，
    用来做本机阻断不合适。
    """
    ips: set[str] = set()
    for line in raw.decode("utf-8", "ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if not parts or not IP_RE.match(parts[0]):
            continue
        try:
            score = int(parts[1]) if len(parts) > 1 else 0
        except ValueError:
            score = 0
        if score >= min_score:
            ips.add(parts[0])
    return ips, set()


COLLECTORS = {"feodo": collect_feodo, "urlhaus": collect_urlhaus,
              "threatfox": collect_threatfox, "ipsum": collect_ipsum}


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
    ap.add_argument("--force", action="store_true",
                    help="即使新索引比现有小也写入（默认拒绝，防止源失败覆盖好数据）")
    ap.add_argument("--ipsum-min-score", type=int, default=IPSUM_MIN_SCORE,
                    help=f"IPsum 最低置信分数（默认 {IPSUM_MIN_SCORE}）")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    all_ips: set[str] = set()
    all_hosts: set[str] = set()
    used = []
    failed: list[tuple[str, str]] = []      # (源, 原因) —— 有失败就不允许写盘

    for src in args.source:
        url, lic, need_key, _kind = SOURCES[src]
        if any(d.lower() in lic.lower() for d in DENY_LICENSES):
            print(f"!! 拒绝导入 {src}：许可 {lic} 不允许商用/再分发")
            failed.append((src, f"许可不允许: {lic}"))
            continue
        if need_key and not args.auth_key:
            print(f"!! 跳过 {src}：需要 Auth-Key（免费注册 https://auth.abuse.ch/）")
            failed.append((src, "缺少 Auth-Key"))
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
            failed.append((src, f"下载失败: {type(exc).__name__}"))
            continue
        ips, hosts = COLLECTORS[src](raw)
        if src == "ipsum":
            # 重新按 CLI 指定的阈值解析（COLLECTORS 里的默认值只是兜底）
            ips, hosts = collect_ipsum(raw, args.ipsum_min_score)
        print(f"   {src:<10} {len(raw)/1024:>8.1f} KB   IP {len(ips):>6}  "
              f"域名 {len(hosts):>6}   许可 {lic}")
        all_ips |= ips
        all_hosts |= hosts
        used.append({"source": src, "license": lic, "url": u,
                     "ips": len(ips), "hosts": len(hosts)})

    if not used:
        print("没有成功导入的源")
        return 2

    # ⚠️ 有任何一个**被请求的源**失败，就默认不写盘。
    # 实测过一次：网络抖动让 ipsum 下载被重置，结果只把 feodo 的 5 条写进
    # c2_ip.u64，把原有 19,927 条 IP 直接覆盖掉了（总数从 42,674 掉到 22,752）。
    # 这类"部分成功"的写入比完全不写危险得多，所以默认拒绝，确认要写加 --force。
    if failed and not args.force:
        print("\n!! 检测到失败的源，拒绝覆盖现有索引：")
        for src, why in failed:
            print(f"     - {src}: {why}")
        print("   现有索引保持不变。确认要用不完整数据覆盖，请加 --force。")
        return 3

    ip_path = os.path.join(args.out, "c2_ip.u64")
    host_path = os.path.join(args.out, "url_feed.u64")

    # ⚠️ 防"部分源失败把好索引覆盖成小索引"：
    # 实测过一次网络抖动导致 ipsum 下载被重置，结果只剩 feodo 的 5 条写盘，
    # 把原有 19,927 条 IP（IPsum 19,922 + Feodo 5）直接覆盖掉了。
    # 阈值取 90%：正常的 feed 波动（几百条上下）不该被拦，而"某个源整个失败"
    # 会让数量掉一个量级，必须拦住。确认要缩小再加 --force。
    old_ip = (os.path.getsize(ip_path) // 8) if os.path.isfile(ip_path) else 0
    if (all_ips and old_ip and len(all_ips) < old_ip * 0.9
            and not args.force):
        print(f"!! 拒绝写入：新 IP 索引 {len(all_ips):,} 条，"
              f"不足现有 {old_ip:,} 条的 90%")
        print("   很可能某个源下载失败或被抓取到不完整数据。")
        print("   确认要缩小索引再加 --force 重跑。")
        return 3

    def _sync_index(path: str, values: set[str], label: str):
        """空集合时**删除**旧索引文件，而不是写一个 0 字节文件。

        原先无条件写：当前只用 IPsum+Feodo（都不含域名）时，
        url_feed.u64 会被写成 0 字节并留在仓库里 —— 既误导统计
        （"域名索引 0 条"看着像数据损坏），也让加载端多做一次无用 IO。
        """
        if values:
            write_index(path, values)
            print(f"{label} {len(values):,} -> {path}")
        else:
            try:
                if os.path.isfile(path):
                    os.unlink(path)
                    print(f"{label} 0 条（无可写索引，已删除旧文件 {os.path.basename(path)}）")
                else:
                    print(f"{label} 0 条（无可写索引）")
            except OSError as exc:
                print(f"{label} 0 条，删除旧索引失败: {exc}")

    _sync_index(ip_path, all_ips, "IP  ")
    _sync_index(host_path, all_hosts, "域名")

    meta = {
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "sources": used,
        "ip_count": len(all_ips),
        "host_count": len(all_hosts),
        "hash": "crc32(b) | crc32(b, 0x9E3779B9) << 32",
        "files": {k: v for k, v in
                  (("ips", "c2_ip.u64"), ("hosts", "url_feed.u64"))
                  if (k == "ips" and all_ips) or (k == "hosts" and all_hosts)},
    }
    with open(os.path.join(args.out, "feeds_meta.json"), "w",
              encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

