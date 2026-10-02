"""
御天 隐私保护引擎

保护用户隐私数据，扫描并清理隐私痕迹，防止敏感文件被未授权访问。

功能：
  1. enable() 启用文档/桌面/下载目录保护（内核驱动防护层已移除，仅记录访问）
  2. scan_privacy_traces() 扫描浏览器历史/Cookie/缓存/最近文档/临时文件/回收站/剪贴板
  3. clean_traces(categories) 清理选定的隐私痕迹
  4. protect_sensitive_files(paths) 保护敏感文件（访问记录 + 访问日志）
  5. get_sensitive_file_access_log() 获取敏感文件访问日志
  6. get_status() 状态查询

支持的清理类别：
  - browser_history  浏览器历史记录
  - cookies          浏览器 Cookie
  - cache            浏览器缓存
  - recent_docs      最近文档记录
  - temp_files       临时文件
  - recycle_bin      回收站
  - clipboard        剪贴板

特性：
  - 支持 Chrome / Edge / Firefox / IE 四种浏览器的隐私痕迹扫描与清理
  - 敏感文件访问日志持久化到 data/sensitive_access_log.json
  - 内核驱动防护层已移除，仅提供扫描/清理与访问记录（无内核级文件保护）
  - 线程安全（双重检查锁单例 + 实例锁）
"""

import os
import sys
import json
import time
import shutil
import threading
import subprocess
import logging
from collections import deque
from typing import Optional, Any

IS_WINDOWS = sys.platform == "win32"

# ============================================================
# 路径与常量
# ============================================================

# data 目录：backend/data/
_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data"
)
# 敏感文件访问日志持久化文件
ACCESS_LOG_FILE = os.path.join(_DATA_DIR, "sensitive_access_log.json")
# 敏感文件列表持久化文件
SENSITIVE_FILES_FILE = os.path.join(_DATA_DIR, "sensitive_files.json")
# 日志目录
_LOG_DIR = os.path.join(_DATA_DIR, "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "privacy_shield.log")

# 访问日志最大保留条数
MAX_ACCESS_LOG = 500

# 默认保护目录
DEFAULT_PROTECTED_DIRS = [
    os.path.expandvars(r"%USERPROFILE%\Documents"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
]

# 支持的清理类别
SUPPORTED_CATEGORIES = [
    "browser_history", "cookies", "cache", "recent_docs",
    "temp_files", "recycle_bin", "clipboard",
]

# 浏览器用户数据目录
BROWSER_USER_DATA = {
    "chrome": {
        "data_dir": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data"),
        "history_files": ["Default\\History", "Default\\History-journal"],
        "cookie_files": ["Default\\Network\\Cookies", "Default\\Network\\Cookies-journal"],
        "cache_dirs": ["Default\\Cache", "Default\\Code Cache", "Default\\GPUCache"],
    },
    "edge": {
        "data_dir": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data"),
        "history_files": ["Default\\History", "Default\\History-journal"],
        "cookie_files": ["Default\\Network\\Cookies", "Default\\Network\\Cookies-journal"],
        "cache_dirs": ["Default\\Cache", "Default\\Code Cache", "Default\\GPUCache"],
    },
    "firefox": {
        "data_dir": os.path.expandvars(r"%APPDATA%\Mozilla\Firefox"),
        # Firefox 使用 places.sqlite 存历史，cookies.sqlite 存 Cookie
        "history_files": [],  # 动态扫描 profiles
        "cookie_files": [],
        "cache_dirs": [],
    },
    "ie": {
        "data_dir": "",
        # IE 历史通过 Shell API 清理
        "history_files": [],
        "cookie_files": [],
        "cache_dirs": [],
    },
}

# Windows 系统路径
RECENT_DOCS_DIR = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent")
TEMP_DIR = os.path.expandvars(r"%TEMP%")


# ============================================================
# 日志器
# ============================================================

def _get_logger() -> logging.Logger:
    """获取隐私保护专用日志记录器"""
    os.makedirs(_LOG_DIR, exist_ok=True)
    logger = logging.getLogger("privacy_shield")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(_LOG_FILE, encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(fh)
    return logger


# ============================================================
# 工具函数
# ============================================================

def _get_process_name(pid: int) -> str:
    """根据 PID 获取进程名"""
    if not IS_WINDOWS or pid <= 0:
        return "unknown"
    try:
        result = subprocess.run(
            ["wmic", "process", "where", f"ProcessId={pid}", "get", "Name", "/format:value"],
            capture_output=True, text=True, timeout=3, encoding="utf-8", errors="ignore"
        )
        for line in result.stdout.splitlines():
            if line.lower().startswith("name="):
                return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def _safe_remove(path: str) -> bool:
    """安全删除文件（失败返回 False，不抛异常）"""
    try:
        if os.path.isfile(path):
            os.remove(path)
            return True
    except Exception:
        return False
    return False


def _safe_rmtree(path: str) -> bool:
    """安全删除目录树"""
    try:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
            return True
    except Exception:
        return False
    return False


def _get_file_size(path: str) -> int:
    """获取文件大小（字节），失败返回 0"""
    try:
        if os.path.isfile(path):
            return os.path.getsize(path)
    except Exception:
        pass
    return 0


def _get_dir_size(path: str) -> int:
    """获取目录总大小（字节）"""
    total = 0
    try:
        for root, dirs, files in os.walk(path):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    total += os.path.getsize(fpath)
                except Exception:
                    continue
    except Exception:
        pass
    return total


# ============================================================
# PrivacyShield — 隐私保护引擎主类
# ============================================================

class PrivacyShield:
    """隐私保护引擎

    扫描并清理隐私痕迹，保护敏感文件，记录访问日志。
    """

    # 驱动规则 ID 起始（避免与其他模块冲突）
    _next_rule_id = 60000

    def __init__(self):
        """初始化隐私保护引擎"""
        self._logger = _get_logger()

        # 保护目录列表
        self._protected_dirs: list[str] = list(DEFAULT_PROTECTED_DIRS)
        self._dirs_lock = threading.Lock()

        # 敏感文件列表（受保护的特定文件）
        self._sensitive_files: list[str] = []
        self._sensitive_lock = threading.Lock()

        # 访问日志 deque[{timestamp, file_path, pid, process_name, action}]
        self._access_log: deque = deque(maxlen=MAX_ACCESS_LOG)
        self._log_lock = threading.Lock()

        # 启用状态
        self._enabled = False
        self._enabled_lock = threading.Lock()

        # 驱动下发的规则 ID 列表（内核驱动防护层已移除，恒为空）
        self._driver_rule_ids: list[int] = []
        self._rule_ids_lock = threading.Lock()

        # 统计
        self._stats = {
            "scans_performed": 0,
            "items_scanned": 0,
            "items_cleaned": 0,
            "bytes_cleaned": 0,
            "sensitive_files_protected": 0,
            "access_alerts": 0,
        }
        self._stats_lock = threading.Lock()

        # 加载敏感文件列表和访问日志
        self._load_sensitive_files()
        self._load_access_log()

        self._log("info", "隐私保护引擎初始化完成")

    # ── 属性 ──

    @property
    def driver_available(self) -> bool:
        """驱动是否可用（内核驱动防护层已移除，恒为 False）"""
        return False

    @property
    def enabled(self) -> bool:
        with self._enabled_lock:
            return self._enabled

    # ── 启用/停用 ──

    def enable(self) -> dict:
        """启用隐私保护

        1. 将文档/桌面/下载目录标记为受保护目录
        2. 重新下发已保存的敏感文件保护规则

        内核驱动防护层已移除：驱动规则下发与驱动事件处理器注册均不再生效。

        Returns:
            {"protected_dirs": list, "rules_pushed": int, "driver_available": bool}
        """
        with self._enabled_lock:
            if self._enabled:
                self._log("info", "隐私保护已启用，跳过重复启用")
                return {"protected_dirs": list(self._protected_dirs),
                        "rules_pushed": 0, "driver_available": self.driver_available}
            self._enabled = True

        # 目录保护规则（内核驱动防护层已移除，恒为 0 条）
        rules_pushed = 0
        with self._dirs_lock:
            dirs_snapshot = list(self._protected_dirs)
        for d in dirs_snapshot:
            rules_pushed += self._push_dir_protection_rule(d)

        # 敏感文件保护规则（内核驱动防护层已移除，恒为 0 条）
        with self._sensitive_lock:
            sensitive_snapshot = list(self._sensitive_files)
        for f in sensitive_snapshot:
            if self._push_sensitive_file_rule(f):
                rules_pushed += 1

        # 注册驱动事件处理器（内核驱动防护层已移除，空实现）
        self._register_driver_handlers()

        self._log("info", f"隐私保护已启用: 保护 {len(dirs_snapshot)} 个目录，"
                          f"{len(sensitive_snapshot)} 个敏感文件，"
                          f"下发 {rules_pushed} 条规则")

        return {
            "protected_dirs": dirs_snapshot,
            "rules_pushed": rules_pushed,
            "driver_available": self.driver_available,
        }

    def disable(self) -> None:
        """停用隐私保护"""
        with self._enabled_lock:
            self._enabled = False

        # 移除驱动规则（内核驱动防护层已移除，空实现）
        self._remove_all_driver_rules()

        # 注销事件处理器（内核驱动防护层已移除，空实现）
        self._unregister_driver_handlers()

        self._log("info", "隐私保护已停用")

    # ── 隐私痕迹扫描 ──

    def scan_privacy_traces(self) -> dict:
        """扫描所有隐私痕迹

        Returns:
            按类别分组的扫描结果 {category: {count, size_bytes, details}}
        """
        with self._stats_lock:
            self._stats["scans_performed"] += 1

        result = {
            "browser_history": self._scan_browser_history(),
            "cookies": self._scan_cookies(),
            "cache": self._scan_cache(),
            "recent_docs": self._scan_recent_docs(),
            "temp_files": self._scan_temp_files(),
            "recycle_bin": self._scan_recycle_bin(),
            "clipboard": self._scan_clipboard(),
        }

        total_items = sum(v.get("count", 0) for v in result.values())
        total_size = sum(v.get("size_bytes", 0) for v in result.values())

        with self._stats_lock:
            self._stats["items_scanned"] += total_items

        self._log("info", f"隐私扫描完成: 共 {total_items} 项，"
                          f"{total_size / 1024 / 1024:.2f} MB")
        return result

    def _scan_browser_history(self) -> dict:
        """扫描浏览器历史记录"""
        files = []
        size = 0
        for browser in ("chrome", "edge"):
            data_dir = BROWSER_USER_DATA[browser]["data_dir"]
            if not data_dir or not os.path.isdir(data_dir):
                continue
            for rel in BROWSER_USER_DATA[browser]["history_files"]:
                fpath = os.path.join(data_dir, rel)
                if os.path.isfile(fpath):
                    files.append(fpath)
                    size += _get_file_size(fpath)

        # Firefox 动态扫描 profiles
        ff_dir = BROWSER_USER_DATA["firefox"]["data_dir"]
        if ff_dir and os.path.isdir(ff_dir):
            for root, dirs, fnames in os.walk(ff_dir):
                for fname in fnames:
                    if fname in ("places.sqlite", "places.sqlite-wal"):
                        fpath = os.path.join(root, fname)
                        files.append(fpath)
                        size += _get_file_size(fpath)

        return {
            "count": len(files),
            "size_bytes": size,
            "details": files[:20],  # 仅返回前 20 条
        }

    def _scan_cookies(self) -> dict:
        """扫描浏览器 Cookie"""
        files = []
        size = 0
        for browser in ("chrome", "edge"):
            data_dir = BROWSER_USER_DATA[browser]["data_dir"]
            if not data_dir or not os.path.isdir(data_dir):
                continue
            for rel in BROWSER_USER_DATA[browser]["cookie_files"]:
                fpath = os.path.join(data_dir, rel)
                if os.path.isfile(fpath):
                    files.append(fpath)
                    size += _get_file_size(fpath)

        # Firefox Cookie
        ff_dir = BROWSER_USER_DATA["firefox"]["data_dir"]
        if ff_dir and os.path.isdir(ff_dir):
            for root, dirs, fnames in os.walk(ff_dir):
                for fname in fnames:
                    if fname in ("cookies.sqlite", "cookies.sqlite-wal"):
                        fpath = os.path.join(root, fname)
                        files.append(fpath)
                        size += _get_file_size(fpath)

        return {"count": len(files), "size_bytes": size, "details": files[:20]}

    def _scan_cache(self) -> dict:
        """扫描浏览器缓存"""
        dirs = []
        size = 0
        for browser in ("chrome", "edge"):
            data_dir = BROWSER_USER_DATA[browser]["data_dir"]
            if not data_dir or not os.path.isdir(data_dir):
                continue
            for rel in BROWSER_USER_DATA[browser]["cache_dirs"]:
                dpath = os.path.join(data_dir, rel)
                if os.path.isdir(dpath):
                    dirs.append(dpath)
                    size += _get_dir_size(dpath)

        # Firefox 缓存
        ff_dir = BROWSER_USER_DATA["firefox"]["data_dir"]
        if ff_dir and os.path.isdir(ff_dir):
            for root, dirs_inner, fnames in os.walk(ff_dir):
                if "cache2" in root.lower():
                    dirs.append(root)
                    size += _get_dir_size(root)
                    break

        return {"count": len(dirs), "size_bytes": size, "details": dirs[:20]}

    def _scan_recent_docs(self) -> dict:
        """扫描最近文档记录"""
        files = []
        size = 0
        if os.path.isdir(RECENT_DOCS_DIR):
            try:
                for fname in os.listdir(RECENT_DOCS_DIR):
                    fpath = os.path.join(RECENT_DOCS_DIR, fname)
                    if os.path.isfile(fpath):
                        files.append(fpath)
                        size += _get_file_size(fpath)
            except Exception:
                pass
        return {"count": len(files), "size_bytes": size, "details": files[:20]}

    def _scan_temp_files(self) -> dict:
        """扫描临时文件"""
        files = []
        size = 0
        if os.path.isdir(TEMP_DIR):
            try:
                for root, dirs, fnames in os.walk(TEMP_DIR):
                    for fname in fnames:
                        fpath = os.path.join(root, fname)
                        try:
                            if os.path.isfile(fpath):
                                files.append(fpath)
                                size += os.path.getsize(fpath)
                        except Exception:
                            continue
            except Exception:
                pass
        # 限制返回数量（临时文件可能很多）
        return {"count": len(files), "size_bytes": size, "details": files[:20]}

    def _scan_recycle_bin(self) -> dict:
        """扫描回收站"""
        # 回收站大小通过 Shell API 获取，这里简化处理
        size = 0
        if IS_WINDOWS:
            for drive in ("C:", "D:", "E:", "F:"):
                recycle_dir = os.path.join(drive + os.sep, "$Recycle.Bin")
                if os.path.isdir(recycle_dir):
                    size += _get_dir_size(recycle_dir)
        return {"count": 1 if size > 0 else 0, "size_bytes": size,
                "details": ["$Recycle.Bin"] if size > 0 else []}

    def _scan_clipboard(self) -> dict:
        """扫描剪贴板内容"""
        # 剪贴板无法直接统计大小，仅检测是否有内容
        has_content = False
        if IS_WINDOWS:
            try:
                import ctypes
                # 简化检测：尝试打开剪贴板
                if ctypes.windll.user32.OpenClipboard(0):
                    has_content = ctypes.windll.user32.CountClipboardFormats() > 0
                    ctypes.windll.user32.CloseClipboard()
            except Exception:
                pass
        return {"count": 1 if has_content else 0, "size_bytes": 0,
                "details": ["clipboard_has_content"] if has_content else []}

    # ── 隐私痕迹清理 ──

    def clean_traces(self, categories: list[str]) -> dict:
        """清理选定的隐私痕迹

        Args:
            categories: 要清理的类别列表（参考 SUPPORTED_CATEGORIES）

        Returns:
            清理结果 {category: {cleaned_count, bytes_freed, failed}}
        """
        result = {}
        for cat in categories:
            if cat not in SUPPORTED_CATEGORIES:
                result[cat] = {"error": f"不支持的类别: {cat}"}
                continue

            if cat == "browser_history":
                result[cat] = self._clean_browser_history()
            elif cat == "cookies":
                result[cat] = self._clean_cookies()
            elif cat == "cache":
                result[cat] = self._clean_cache()
            elif cat == "recent_docs":
                result[cat] = self._clean_recent_docs()
            elif cat == "temp_files":
                result[cat] = self._clean_temp_files()
            elif cat == "recycle_bin":
                result[cat] = self._clean_recycle_bin()
            elif cat == "clipboard":
                result[cat] = self._clean_clipboard()

            # 更新统计
            info = result[cat]
            if isinstance(info, dict) and "cleaned_count" in info:
                with self._stats_lock:
                    self._stats["items_cleaned"] += info.get("cleaned_count", 0)
                    self._stats["bytes_cleaned"] += info.get("bytes_freed", 0)

        total_cleaned = sum(v.get("cleaned_count", 0) for v in result.values()
                            if isinstance(v, dict))
        total_bytes = sum(v.get("bytes_freed", 0) for v in result.values()
                          if isinstance(v, dict))

        self._log("info", f"隐私清理完成: 清理 {total_cleaned} 项，"
                          f"释放 {total_bytes / 1024 / 1024:.2f} MB")
        return result

    def _clean_browser_history(self) -> dict:
        """清理浏览器历史记录"""
        cleaned = 0
        freed = 0
        failed = 0

        # Chrome / Edge
        for browser in ("chrome", "edge"):
            data_dir = BROWSER_USER_DATA[browser]["data_dir"]
            if not data_dir:
                continue
            for rel in BROWSER_USER_DATA[browser]["history_files"]:
                fpath = os.path.join(data_dir, rel)
                if os.path.isfile(fpath):
                    freed += _get_file_size(fpath)
                    if _safe_remove(fpath):
                        cleaned += 1
                    else:
                        failed += 1

        # Firefox
        ff_dir = BROWSER_USER_DATA["firefox"]["data_dir"]
        if ff_dir and os.path.isdir(ff_dir):
            for root, dirs, fnames in os.walk(ff_dir):
                for fname in fnames:
                    if fname in ("places.sqlite", "places.sqlite-wal"):
                        fpath = os.path.join(root, fname)
                        freed += _get_file_size(fpath)
                        if _safe_remove(fpath):
                            cleaned += 1
                        else:
                            failed += 1

        return {"cleaned_count": cleaned, "bytes_freed": freed, "failed": failed}

    def _clean_cookies(self) -> dict:
        """清理浏览器 Cookie"""
        cleaned = 0
        freed = 0
        failed = 0

        for browser in ("chrome", "edge"):
            data_dir = BROWSER_USER_DATA[browser]["data_dir"]
            if not data_dir:
                continue
            for rel in BROWSER_USER_DATA[browser]["cookie_files"]:
                fpath = os.path.join(data_dir, rel)
                if os.path.isfile(fpath):
                    freed += _get_file_size(fpath)
                    if _safe_remove(fpath):
                        cleaned += 1
                    else:
                        failed += 1

        # Firefox Cookie
        ff_dir = BROWSER_USER_DATA["firefox"]["data_dir"]
        if ff_dir and os.path.isdir(ff_dir):
            for root, dirs, fnames in os.walk(ff_dir):
                for fname in fnames:
                    if fname in ("cookies.sqlite", "cookies.sqlite-wal"):
                        fpath = os.path.join(root, fname)
                        freed += _get_file_size(fpath)
                        if _safe_remove(fpath):
                            cleaned += 1
                        else:
                            failed += 1

        return {"cleaned_count": cleaned, "bytes_freed": freed, "failed": failed}

    def _clean_cache(self) -> dict:
        """清理浏览器缓存"""
        cleaned = 0
        freed = 0
        failed = 0

        for browser in ("chrome", "edge"):
            data_dir = BROWSER_USER_DATA[browser]["data_dir"]
            if not data_dir:
                continue
            for rel in BROWSER_USER_DATA[browser]["cache_dirs"]:
                dpath = os.path.join(data_dir, rel)
                if os.path.isdir(dpath):
                    freed += _get_dir_size(dpath)
                    if _safe_rmtree(dpath):
                        cleaned += 1
                    else:
                        failed += 1

        return {"cleaned_count": cleaned, "bytes_freed": freed, "failed": failed}

    def _clean_recent_docs(self) -> dict:
        """清理最近文档记录"""
        cleaned = 0
        freed = 0
        failed = 0
        if os.path.isdir(RECENT_DOCS_DIR):
            try:
                for fname in os.listdir(RECENT_DOCS_DIR):
                    fpath = os.path.join(RECENT_DOCS_DIR, fname)
                    if os.path.isfile(fpath):
                        freed += _get_file_size(fpath)
                        if _safe_remove(fpath):
                            cleaned += 1
                        else:
                            failed += 1
            except Exception:
                pass
        return {"cleaned_count": cleaned, "bytes_freed": freed, "failed": failed}

    def _clean_temp_files(self) -> dict:
        """清理临时文件"""
        cleaned = 0
        freed = 0
        failed = 0
        if os.path.isdir(TEMP_DIR):
            try:
                for root, dirs, fnames in os.walk(TEMP_DIR):
                    for fname in fnames:
                        fpath = os.path.join(root, fname)
                        try:
                            if os.path.isfile(fpath):
                                freed += os.path.getsize(fpath)
                                if _safe_remove(fpath):
                                    cleaned += 1
                                else:
                                    failed += 1
                        except Exception:
                            failed += 1
            except Exception:
                pass
        return {"cleaned_count": cleaned, "bytes_freed": freed, "failed": failed}

    def _clean_recycle_bin(self) -> dict:
        """清空回收站"""
        if not IS_WINDOWS:
            return {"cleaned_count": 0, "bytes_freed": 0, "failed": 0}

        # 计算回收站大小
        freed = 0
        for drive in ("C:", "D:", "E:", "F:"):
            recycle_dir = os.path.join(drive + os.sep, "$Recycle.Bin")
            if os.path.isdir(recycle_dir):
                freed += _get_dir_size(recycle_dir)

        # 调用 Shell API 清空回收站
        try:
            # SHEmptyRecycleBinW(hwnd, pszRootPath, dwFlags)
            # dwFlags: SHERB_NOCONFIRMATION(0x1) | SHERB_NOPROGRESSUI(0x2) | SHERB_NOSOUND(0x4)
            ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x7)
            return {"cleaned_count": 1, "bytes_freed": freed, "failed": 0}
        except Exception as e:
            self._log("error", f"清空回收站失败: {e}")
            return {"cleaned_count": 0, "bytes_freed": 0, "failed": 1}

    def _clean_clipboard(self) -> dict:
        """清空剪贴板"""
        if not IS_WINDOWS:
            return {"cleaned_count": 0, "bytes_freed": 0, "failed": 0}
        try:
            import ctypes
            if ctypes.windll.user32.OpenClipboard(0):
                ctypes.windll.user32.EmptyClipboard()
                ctypes.windll.user32.CloseClipboard()
            return {"cleaned_count": 1, "bytes_freed": 0, "failed": 0}
        except Exception as e:
            self._log("error", f"清空剪贴板失败: {e}")
            return {"cleaned_count": 0, "bytes_freed": 0, "failed": 1}

    # ── 敏感文件保护 ──

    def protect_sensitive_files(self, paths: list[str]) -> dict:
        """保护敏感文件

        Args:
            paths: 敏感文件路径列表

        Returns:
            {"protected": int, "failed": int, "paths": list}
        """
        protected = 0
        failed = 0
        protected_paths = []

        for path in paths:
            if not os.path.isfile(path):
                self._log("warning", f"敏感文件不存在: {path}")
                failed += 1
                continue

            with self._sensitive_lock:
                if path not in self._sensitive_files:
                    self._sensitive_files.append(path)

            # 下发驱动保护规则（内核驱动防护层已移除，恒返回 0，走记录模式）
            if self._push_sensitive_file_rule(path):
                protected += 1
                protected_paths.append(path)
            else:
                # 驱动不可用时仍记录到列表（降级模式）
                protected += 1
                protected_paths.append(path)

        # 持久化敏感文件列表
        self._save_sensitive_files()

        with self._stats_lock:
            self._stats["sensitive_files_protected"] = len(self._sensitive_files)

        self._log("info", f"敏感文件保护: 成功 {protected}，失败 {failed}")
        return {"protected": protected, "failed": failed, "paths": protected_paths}

    def unprotect_sensitive_file(self, path: str) -> bool:
        """取消保护敏感文件

        Args:
            path: 敏感文件路径

        Returns:
            成功返回 True
        """
        with self._sensitive_lock:
            if path not in self._sensitive_files:
                return False
            self._sensitive_files.remove(path)

        # 移除驱动规则（内核驱动防护层已移除，仅清空本地规则 ID）
        # 简化处理：移除所有规则后重新下发（少量文件时可接受）
        self._remove_all_driver_rules()
        if self.enabled:
            with self._sensitive_lock:
                for f in self._sensitive_files:
                    self._push_sensitive_file_rule(f)

        self._save_sensitive_files()
        return True

    def get_sensitive_files(self) -> list[str]:
        """获取敏感文件列表"""
        with self._sensitive_lock:
            return list(self._sensitive_files)

    def get_sensitive_file_access_log(self, limit: int = 100) -> list[dict]:
        """获取敏感文件访问日志

        Args:
            limit: 返回最近 N 条记录

        Returns:
            访问日志列表（按时间倒序）
        """
        with self._log_lock:
            log = list(self._access_log)
        log.reverse()
        return log[:limit]

    # ── 状态查询 ──

    def get_status(self) -> dict:
        """获取隐私保护完整状态"""
        with self._dirs_lock:
            dirs = list(self._protected_dirs)
        with self._sensitive_lock:
            sensitive_count = len(self._sensitive_files)
        with self._log_lock:
            log_count = len(self._access_log)
        with self._stats_lock:
            stats = dict(self._stats)
        with self._rule_ids_lock:
            rules_count = len(self._driver_rule_ids)

        return {
            "enabled": self.enabled,
            "driver_available": self.driver_available,
            "protected_dirs": dirs,
            "sensitive_files_count": sensitive_count,
            "access_log_count": log_count,
            "driver_rules_count": rules_count,
            "stats": stats,
            "supported_categories": SUPPORTED_CATEGORIES,
        }

    # ── 驱动规则下发（私有） ──

    def _push_dir_protection_rule(self, directory: str) -> int:
        """下发目录保护规则（监控文档/桌面/下载目录的文件访问）

        内核驱动防护层已移除，规则无法下发，恒返回 0（仅记录模式）。
        """
        self._log("info", f"内核驱动防护层已移除，目录 {directory} 仅启用记录模式")
        return 0

    def _push_sensitive_file_rule(self, file_path: str) -> int:
        """下发敏感文件保护规则

        内核驱动防护层已移除，规则无法下发，恒返回 0（仅记录模式）。
        """
        return 0

    def _remove_all_driver_rules(self) -> None:
        """移除所有已下发的隐私保护规则

        内核驱动防护层已移除，仅清空本地记录的规则 ID。
        """
        with self._rule_ids_lock:
            self._driver_rule_ids.clear()

    # ── 驱动事件处理器（私有） ──

    def _register_driver_handlers(self) -> None:
        """注册驱动文件事件处理器（内核驱动防护层已移除，保留空实现）"""
        return

    def _unregister_driver_handlers(self) -> None:
        """注销驱动事件处理器（内核驱动防护层已移除，保留空实现）"""
        return

    def _on_file_event(self, event: dict) -> None:
        """驱动文件事件回调

        检查目标路径是否为敏感文件，是则记录访问日志。
        """
        if not self.enabled:
            return

        target_path = event.get("targetPath", "")
        pid = event.get("pid", 0)
        event_type = event.get("eventType", 0)

        if not target_path:
            return

        # 检查是否为敏感文件
        with self._sensitive_lock:
            is_sensitive = any(
                os.path.normcase(target_path) == os.path.normcase(f)
                for f in self._sensitive_files
            )

        if not is_sensitive:
            return

        # 记录访问日志
        process_name = _get_process_name(pid)
        record = {
            "timestamp": time.time(),
            "file_path": target_path,
            "pid": pid,
            "process_name": process_name,
            "action": int(event_type),
            "action_name": {1: "create", 2: "write", 3: "delete"}.get(event_type, "unknown"),
        }
        with self._log_lock:
            self._access_log.append(record)

        with self._stats_lock:
            self._stats["access_alerts"] += 1

        self._log("warning", f"敏感文件访问: {process_name} (PID={pid}) "
                            f"{record['action_name']} {target_path}")

        # 异步持久化
        threading.Thread(target=self._save_access_log, daemon=True).start()

    # ── 持久化 ──

    def _save_sensitive_files(self) -> bool:
        """持久化敏感文件列表"""
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            with self._sensitive_lock:
                data = {
                    "saved_at": time.time(),
                    "files": list(self._sensitive_files),
                }
            with open(SENSITIVE_FILES_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            self._log("error", f"敏感文件列表持久化失败: {e}")
            return False

    def _load_sensitive_files(self) -> bool:
        """加载敏感文件列表"""
        if not os.path.exists(SENSITIVE_FILES_FILE):
            return False
        try:
            with open(SENSITIVE_FILES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            with self._sensitive_lock:
                self._sensitive_files = data.get("files", [])
            return True
        except Exception as e:
            self._log("error", f"敏感文件列表加载失败: {e}")
            return False

    def _save_access_log(self) -> bool:
        """持久化访问日志"""
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            with self._log_lock:
                data = {
                    "saved_at": time.time(),
                    "log": list(self._access_log),
                }
            with open(ACCESS_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            self._log("error", f"访问日志持久化失败: {e}")
            return False

    def _load_access_log(self) -> bool:
        """加载访问日志"""
        if not os.path.exists(ACCESS_LOG_FILE):
            return False
        try:
            with open(ACCESS_LOG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            log = data.get("log", [])
            with self._log_lock:
                self._access_log.clear()
                self._access_log.extend(log[-MAX_ACCESS_LOG:])
            return True
        except Exception as e:
            self._log("error", f"访问日志加载失败: {e}")
            return False

    # ── 日志 ──

    def _log(self, level: str, message: str) -> None:
        """记录日志"""
        try:
            getattr(self._logger, level, self._logger.info)(message)
        except Exception:
            pass


# ============================================================
# 单例模式（双重检查锁）
# ============================================================

_privacy_shield: Optional[PrivacyShield] = None
_privacy_shield_lock = threading.Lock()


def get_privacy_shield() -> PrivacyShield:
    """获取全局唯一的 PrivacyShield 实例（双重检查锁定单例）

    Returns:
        全局唯一的 PrivacyShield 实例
    """
    global _privacy_shield
    if _privacy_shield is None:
        with _privacy_shield_lock:
            if _privacy_shield is None:
                _privacy_shield = PrivacyShield()
    return _privacy_shield


# ============================================================
# 模块自检（直接运行时执行）
# ============================================================

if __name__ == "__main__":
    shield = PrivacyShield()

    print("[privacy_shield] 状态:", shield.get_status())

    print("[privacy_shield] 扫描隐私痕迹...")
    scan_result = shield.scan_privacy_traces()
    for cat, info in scan_result.items():
        count = info.get("count", 0)
        size = info.get("size_bytes", 0)
        print(f"  - {cat}: {count} 项, {size / 1024:.2f} KB")

    print("[privacy_shield] 启用保护...")
    enable_result = shield.enable()
    print(f"[privacy_shield] 启用结果: {enable_result}")

    # 保护一个测试文件
    test_file = os.path.join(_DATA_DIR, "sensitive_test.txt")
    try:
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("测试敏感文件内容")
        print("[privacy_shield] 保护测试敏感文件...")
        protect_result = shield.protect_sensitive_files([test_file])
        print(f"[privacy_shield] 保护结果: {protect_result}")

        print("[privacy_shield] 敏感文件列表:", shield.get_sensitive_files())

        # 清理部分痕迹（仅清理 temp_files 和 clipboard，避免影响系统）
        print("[privacy_shield] 清理临时文件...")
        clean_result = shield.clean_traces(["temp_files", "clipboard"])
        for cat, info in clean_result.items():
            print(f"  - {cat}: {info}")

        print("[privacy_shield] 访问日志:", shield.get_sensitive_file_access_log(limit=5))

        # 取消保护
        shield.unprotect_sensitive_file(test_file)
        os.remove(test_file)
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)

    print("[privacy_shield] 最终状态:", shield.get_status())

    shield.disable()
