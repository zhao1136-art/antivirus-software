# -*- coding: utf-8 -*-
"""
病毒库扩充脚本（一次性工具）
从多个来源提取恶意样本哈希 / 恶意 IP，生成特征库文本文件到 bingduku/ 目录：
  1. theZoo-0.60.zip 官方 .md5 / .sha256 / .md5sum 校验文件（本地，真实恶意样本）
  2. ESET malware-ioc 仓库 samples.sha256（联网，148+ 家族）
  3. MalwareBazaar API 近期恶意样本（联网，免认证）
  4. C2IntelFeeds 恶意 C2 IP（本地）
生成文件均为纯哈希/IP 每行一个的格式，可直接被 signature_manager 导入。
"""
import os
import re
import json
import time
import zipfile
import urllib.request
import urllib.parse

BINGDUKU = r"f:\Caelire\bingduku"
ZOO = os.path.join(BINGDUKU, "theZoo-0.60.zip")
C2DIR = r"f:\Caelire\C2IntelFeeds-master\C2IntelFeeds-master\feeds"
UA = {"User-Agent": "AnDun-Antivirus/1.0"}

_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_IP_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})$")


def fetch(url, data=None, timeout=30):
    req = urllib.request.Request(url, data=data, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def extract_zoo():
    """从 theZoo zip 内 .md5/.md5sum/.sha256 校验文件提取哈希"""
    md5s, sha256s = set(), set()
    with zipfile.ZipFile(ZOO) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename.lower()
            try:
                text = zf.read(info).decode("utf-8", "ignore")
            except Exception:
                continue
            for line in text.splitlines():
                s = line.strip()
                if not s:
                    continue
                first = s.split()[0] if s.split() else s
                if name.endswith(".md5") or name.endswith(".md5sum"):
                    if _MD5_RE.match(first):
                        md5s.add(first.lower())
                elif name.endswith(".sha256"):
                    if _SHA256_RE.match(first):
                        sha256s.add(first.lower())
    return md5s, sha256s


def fetch_eset():
    """下载 ESET malware-ioc 仓库所有家族的 samples.sha256"""
    sha256s = set()
    try:
        listing = json.loads(fetch("https://api.github.com/repos/eset/malware-ioc/contents/"))
        dirs = [d["name"] for d in listing if d.get("type") == "dir"]
        for folder in dirs:
            url = ("https://raw.githubusercontent.com/eset/malware-ioc/master/"
                   + folder + "/samples.sha256")
            try:
                text = fetch(url, timeout=15).decode("utf-8", "ignore")
                for line in text.splitlines():
                    s = line.strip().split()
                    if s and _SHA256_RE.match(s[0]):
                        sha256s.add(s[0].lower())
            except Exception:
                pass
            time.sleep(0.3)
    except Exception as e:
        print("  [ESET] 失败:", e)
    return sha256s


def fetch_malwarebazaar():
    """拉取 MalwareBazaar 近 365 天恶意样本哈希（get_recent 每窗口 1000 条）"""
    md5s, sha256s = set(), set()
    api = "https://mb-api.abuse.ch/api/v1/"
    for days in (30, 60, 90, 180, 365):
        try:
            body = urllib.parse.urlencode(
                {"query": "get_recent", "selector": "time", "days": days}).encode()
            data = json.loads(fetch(api, data=body, timeout=30))
            if data.get("query_status") != "ok":
                continue
            for item in data.get("data", []):
                if item.get("md5_hash") and _MD5_RE.match(item["md5_hash"]):
                    md5s.add(item["md5_hash"].lower())
                if item.get("sha256_hash") and _SHA256_RE.match(item["sha256_hash"]):
                    sha256s.add(item["sha256_hash"].lower())
        except Exception as e:
            print("  [MalwareBazaar] days=%s 失败: %s" % (days, e))
        time.sleep(1.2)  # 限速 1 req/s
    return md5s, sha256s


def extract_c2_ips():
    """从 C2IntelFeeds CSV 提取恶意 C2 IP"""
    ips = set()
    for f in os.listdir(C2DIR):
        if not f.lower().endswith(".csv"):
            continue
        p = os.path.join(C2DIR, f)
        try:
            with open(p, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if line.startswith("#") or "," not in line:
                        continue
                    first = line.split(",")[0].strip()
                    if _IP_RE.match(first):
                        ips.add(first)
        except Exception:
            pass
    return ips


def write_txt(path, items):
    with open(path, "w", encoding="utf-8") as f:
        for it in sorted(items):
            f.write(it + "\r\n")


def main():
    print("[1/4] theZoo 官方校验哈希...")
    zoo_md5, zoo_sha = extract_zoo()
    print("  md5=%d sha256=%d" % (len(zoo_md5), len(zoo_sha)))

    print("[2/4] ESET malware-ioc...")
    eset_sha = fetch_eset()
    print("  sha256=%d" % len(eset_sha))

    print("[3/4] MalwareBazaar...")
    mb_md5, mb_sha = fetch_malwarebazaar()
    print("  md5=%d sha256=%d" % (len(mb_md5), len(mb_sha)))

    print("[4/4] C2IntelFeeds 恶意 IP...")
    c2_ips = extract_c2_ips()
    print("  ip=%d" % len(c2_ips))

    write_txt(os.path.join(BINGDUKU, "病毒特征库-theZoo-恶意样本.md5.txt"), zoo_md5)
    write_txt(os.path.join(BINGDUKU, "病毒特征库-theZoo-恶意样本.sha256.txt"), zoo_sha)
    write_txt(os.path.join(BINGDUKU, "病毒特征库-eset-ioc.sha256.txt"), eset_sha)
    write_txt(os.path.join(BINGDUKU, "病毒特征库-malwarebazaar.md5.txt"), mb_md5)
    write_txt(os.path.join(BINGDUKU, "病毒特征库-malwarebazaar.sha256.txt"), mb_sha)
    write_txt(os.path.join(BINGDUKU, "病毒特征库-c2-恶意IP.txt"), c2_ips)
    print("生成完成 ->", BINGDUKU)


if __name__ == "__main__":
    main()
