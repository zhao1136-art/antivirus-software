"""
御天 下载防护模块

监控浏览器、迅雷、QQ 等接收文件的目录，自动检测新文件是否恶意。
"""
import os
import sys
import time
import json
import threading
import hashlib
from datetime import datetime
from pathlib import Path

IS_WINDOWS = sys.platform == 'win32'

DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data"
)
LOG_FILE = os.path.join(DATA_DIR, "logs", "download_guard.log")

# 默认监控的下载目录
DEFAULT_WATCH_DIRS = [
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
]

# 浏览器下载目录模式
BROWSER_DOWNLOAD_DIRS = {
    "chrome": os.path.expandvars(r"%USERPROFILE%\Downloads"),
    "edge": os.path.expandvars(r"%USERPROFILE%\Downloads"),
    "firefox": os.path.expandvars(r"%USERPROFILE%\Downloads"),
}

# 迅雷下载目录（常见位置）
XUNLEI_DIRS = [
    os.path.expandvars(r"%USERPROFILE%\Downloads\Thunder"),
    os.path.expandvars(r"%PROGRAMFILES(X86)%\Thunder Network\Thunder\Program"),
]

# QQ 接收文件目录
QQ_RECV_DIRS = [
    os.path.expandvars(r"%USERPROFILE%\Documents\Tencent Files"),
]


class DownloadGuard:
    """下载防护"""

    def __init__(self):
        self._enabled = False
        self._running = False
        self._stop_event = threading.Event()
        self._watch_dirs: list[str] = list(DEFAULT_WATCH_DIRS)
        self._scanned_files: dict[str, float] = {}  # 文件路径 -> 扫描时间
        self._detected_threats: list[dict] = []
        self._lock = threading.Lock()
        self._scan_count = 0
        self._threat_count = 0
        os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)

    def _log(self, msg: str):
        t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{t}] {msg}\n")
        except Exception:
            pass

    def enable(self):
        if self._enabled:
            return
        self._enabled = True
        self._log("下载防护已启用")
        if not self._running:
            self._start()

    def disable(self):
        self._enabled = False
        self._log("下载防护已禁用")

    def _start(self):
        self._running = True
        self._stop_event.clear()
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()

    def stop(self):
        self._enabled = False
        self._stop_event.set()
        self._running = False

    def add_watch_dir(self, path: str) -> bool:
        """添加监控目录"""
        path = os.path.abspath(path)
        if os.path.isdir(path):
            with self._lock:
                if path not in self._watch_dirs:
                    self._watch_dirs.append(path)
                    self._log(f"添加监控目录: {path}")
            return True
        return False

    def remove_watch_dir(self, path: str) -> bool:
        path = os.path.abspath(path)
        with self._lock:
            if path in self._watch_dirs:
                self._watch_dirs.remove(path)
                self._log(f"移除监控目录: {path}")
            return True

    def get_watch_dirs(self) -> list[str]:
        with self._lock:
            return list(self._watch_dirs)

    def _monitor_loop(self):
        """轮询监控目录中的新文件"""
        while not self._stop_event.is_set():
            if not self._enabled:
                self._stop_event.wait(2)
                continue
            try:
                with self._lock:
                    dirs = list(self._watch_dirs)
                for watch_dir in dirs:
                    if not os.path.isdir(watch_dir):
                        continue
                    try:
                        for entry in os.scandir(watch_dir):
                            if not entry.is_file():
                                continue
                            fpath = entry.path
                            mtime = entry.stat().st_mtime
                            # 只检查最近 60 秒内创建/修改的文件
                            now = time.time()
                            if now - mtime > 60:
                                continue
                            # 检查是否已扫描过
                            if fpath in self._scanned_files:
                                continue
                            # 仅扫描可执行文件、脚本、压缩包等
                            ext = os.path.splitext(fpath)[1].lower()
                            if ext in ('.exe', '.dll', '.msi', '.bat', '.cmd', '.ps1',
                                       '.vbs', '.js', '.jar', '.docm', '.xlsm', '.pptm',
                                       '.zip', '.rar', '.7z'):
                                self._scan_file(fpath)
                    except (PermissionError, OSError):
                        pass
            except Exception:
                pass
            self._stop_event.wait(5)  # 每 5 秒检查一次

    def _scan_file(self, fpath: str):
        """扫描文件（调用已有扫描引擎）"""
        try:
            # 计算哈希
            sha256 = hashlib.sha256()
            with open(fpath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            file_hash = sha256.hexdigest()

            # 标记已扫描
            self._scanned_files[fpath] = time.time()
            # 清理旧记录
            now = time.time()
            self._scanned_files = {k: v for k, v in self._scanned_files.items() if now - v < 3600}

            # 简单检测：尝试调用本地扫描
            threat = None
            try:
                from engine.local_scanner import LocalScanner
                scanner = LocalScanner()
                result = scanner.scan_file(fpath)
                if result and result.get("malicious"):
                    threat = {
                        "path": fpath,
                        "hash": file_hash,
                        "name": result.get("signature", "未知威胁"),
                        "time": datetime.now().isoformat(),
                        "source": "下载防护自动扫描"
                    }
            except ImportError:
                pass

            if threat:
                with self._lock:
                    self._detected_threats.insert(0, threat)
                    self._threat_count += 1
                    if len(self._detected_threats) > 100:
                        self._detected_threats = self._detected_threats[:100]
                self._log(f"检测到威胁: {fpath} ({threat['name']})")
            else:
                self._log(f"文件安全: {fpath}")

            with self._lock:
                self._scan_count += 1

        except Exception as e:
            self._log(f"扫描文件失败: {fpath} - {e}")

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self._enabled,
                "scan_count": self._scan_count,
                "threat_count": self._threat_count,
                "watch_dirs": list(self._watch_dirs),
                "recent_threats": list(self._detected_threats[:10])
            }

    def get_status(self) -> dict:
        return {
            "enabled": self._enabled,
            "running": self._running,
            "scan_total": self._scan_count,
            "threat_total": self._threat_count,
            "watch_dirs_count": len(self._watch_dirs)
        }