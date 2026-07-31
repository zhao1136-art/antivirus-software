"""
安盾 安全策略配置模块
处理策略（自动删除/隔离/仅告警）+ 白名单管理 + 文件哈希工具
"""
import os
import json
import hashlib
import threading
from dataclasses import dataclass, asdict
from typing import Optional

CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_FILE = os.path.join(CONFIG_DIR, "data", "policy.json")
WHITELIST_FILE = os.path.join(CONFIG_DIR, "data", "whitelist.json")

os.makedirs(os.path.join(CONFIG_DIR, "data"), exist_ok=True)

_lock = threading.Lock()

# 默认策略
DEFAULT_POLICY = {
    "threat_action": "quarantine",  # delete / quarantine / alert_only
    "auto_update_signatures": True,
    "enable_network_monitor": True,
    "enable_startup_scan": True,
    "network_alert_level": "high",  # high / medium / low
    "scan_archives": True,
    "max_scan_size_mb": 500,
    "log_retention_days": 30,
}


def load_policy() -> dict:
    with _lock:
        if os.path.isfile(POLICY_FILE):
            try:
                with open(POLICY_FILE, "r", encoding="utf-8") as f:
                    policy = json.load(f)
                for k, v in DEFAULT_POLICY.items():
                    if k not in policy:
                        policy[k] = v
                return policy
            except (json.JSONDecodeError, OSError):
                pass
        return dict(DEFAULT_POLICY)


def save_policy(policy: dict) -> bool:
    with _lock:
        try:
            with open(POLICY_FILE, "w", encoding="utf-8") as f:
                json.dump(policy, f, indent=2, ensure_ascii=False)
            return True
        except OSError:
            return False


def update_policy(**kwargs) -> dict:
    policy = load_policy()
    for k, v in kwargs.items():
        if k in DEFAULT_POLICY:
            policy[k] = v
    save_policy(policy)
    return policy


# ============== 白名单管理 ==============

def load_whitelist() -> dict:
    with _lock:
        if os.path.isfile(WHITELIST_FILE):
            try:
                with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {"paths": [], "hashes": [], "processes": [], "publishers": []}


def save_whitelist(wl: dict) -> bool:
    with _lock:
        try:
            with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
                json.dump(wl, f, indent=2, ensure_ascii=False)
            return True
        except OSError:
            return False


def whitelist_add_path(path: str, note: str = "") -> dict:
    """添加路径白名单"""
    wl = load_whitelist()
    if path not in [p["path"] for p in wl["paths"]]:
        wl["paths"].append({"path": path, "note": note, "added": _now()})
    save_whitelist(wl)
    return wl


def whitelist_add_hash(path: str, note: str = "") -> dict:
    """添加文件哈希白名单"""
    h = file_sha256(path)
    if not h:
        return {"error": "无法计算哈希"}
    wl = load_whitelist()
    existing = [e for e in wl["hashes"] if e["hash"] == h]
    if not existing:
        wl["hashes"].append({"hash": h, "path": path, "note": note, "added": _now()})
    save_whitelist(wl)
    return wl


def whitelist_remove(category: str, value: str) -> dict:
    """移除白名单条目"""
    wl = load_whitelist()
    if category == "paths":
        wl["paths"] = [p for p in wl["paths"] if p["path"] != value]
    elif category == "hashes":
        wl["hashes"] = [h for h in wl["hashes"] if h["hash"] != value and h["path"] != value]
    elif category == "processes":
        wl["processes"] = [p for p in wl["processes"] if p != value]
    elif category == "publishers":
        wl["publishers"] = [p for p in wl["publishers"] if p != value]
    save_whitelist(wl)
    return wl


def is_whitelisted(path: str = "", file_hash: str = "") -> bool:
    """检查是否在白名单中"""
    wl = load_whitelist()
    if path:
        # 路径匹配（支持目录白名单）
        for entry in wl["paths"]:
            p = entry["path"]
            if p == path or (os.path.isdir(p) and path.startswith(p)):
                return True
    if file_hash:
        for entry in wl["hashes"]:
            if entry["hash"] == file_hash:
                return True
    return False


# ============== 文件哈希工具 ==============

def file_md5(path: str) -> str:
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def file_sha1(path: str) -> str:
    try:
        h = hashlib.sha1()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def file_sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def file_all_hashes(path: str) -> dict:
    """计算文件所有哈希值"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        size = os.path.getsize(path)
        return {
            "path": path,
            "size": size,
            "size_human": _fmt_size(size),
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except (OSError, PermissionError) as e:
        return {"path": path, "error": str(e)}


def batch_hash_directory(dir_path: str, max_files: int = 1000) -> list[dict]:
    """批量计算目录下所有文件的哈希"""
    results = []
    count = 0
    for root, _, files in os.walk(dir_path):
        for fname in files:
            if count >= max_files:
                break
            full = os.path.join(root, fname)
            h = file_sha256(full)
            if h:
                results.append({
                    "path": full,
                    "size": os.path.getsize(full),
                    "sha256": h,
                })
                count += 1
        if count >= max_files:
            break
    return results


def _fmt_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
