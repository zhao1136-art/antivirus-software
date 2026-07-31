"""
安盾 防篡改模块
程序本体完整性校验，防止病毒破坏杀毒软件自身
"""
import os
import hashlib
import json

INTEGRITY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "integrity.json")

# 关键文件清单（相对于 backend/ 或 _internal/）
CRITICAL_FILES = [
    "app.py", "config.py",
    "engine/engine.py", "engine/scanner.py", "engine/scheduler.py",
    "engine/quarantine.py", "engine/signature_manager.py",
    "engine/startup_scanner.py", "engine/network_monitor.py",
    "engine/policy_manager.py",
    "engine/file_guard.py", "engine/system_guard.py",
    "engine/watchdog.py",
    "engine/native_guard/file_guard.exe",
    "vigil/launcher.py",
    "vigil/src/dashboard.py", "vigil/src/scan_api.py",
]


def _get_root_dir() -> str:
    import sys
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def build_integrity_baseline() -> dict:
    """计算所有关键文件的 SHA256 基线"""
    root = _get_root_dir()
    baseline = {}
    for rel_path in CRITICAL_FILES:
        full_path = os.path.join(root, rel_path)
        if os.path.isfile(full_path):
            h = hashlib.sha256()
            try:
                with open(full_path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                baseline[rel_path] = h.hexdigest()
            except (OSError, PermissionError):
                baseline[rel_path] = "ERROR"
        else:
            baseline[rel_path] = "MISSING"
    os.makedirs(os.path.dirname(INTEGRITY_FILE), exist_ok=True)
    with open(INTEGRITY_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "baseline": baseline,
            "total_files": len(baseline),
        }, f, indent=2)
    return baseline


def check_integrity() -> dict:
    """检查关键文件完整性"""
    if not os.path.isfile(INTEGRITY_FILE):
        return {"status": "no_baseline", "message": "尚未建立完整性基线，请执行 build", "tampered": []}

    try:
        with open(INTEGRITY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"status": "error", "message": "基线文件损坏", "tampered": []}

    baseline = data.get("baseline", {})
    root = _get_root_dir()
    tampered = []

    for rel_path in CRITICAL_FILES:
        full_path = os.path.join(root, rel_path)
        expected = baseline.get(rel_path, "")
        if not os.path.isfile(full_path):
            tampered.append({"file": rel_path, "status": "missing"})
            continue
        try:
            h = hashlib.sha256()
            with open(full_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            current = h.hexdigest()
            if expected and current != expected:
                tampered.append({"file": rel_path, "status": "modified"})
        except (OSError, PermissionError):
            tampered.append({"file": rel_path, "status": "unreadable"})

    return {
        "status": "clean" if not tampered else "tampered",
        "total_checked": len(CRITICAL_FILES),
        "tampered_count": len(tampered),
        "tampered": tampered,
        "message": "所有文件完整" if not tampered else f"发现 {len(tampered)} 个文件异常"
    }
