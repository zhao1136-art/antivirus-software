"""
御天 浏览器保护引擎

保护 Chrome / Edge / Firefox / IE 四种主流浏览器，防止主页被劫持、
搜索引擎被篡改、扩展被恶意安装、代理被注入、hosts 被修改。

功能：
  1. enable() 启用浏览器保护（内核驱动防护层已移除，不再下发文件保护规则）
  2. 建立配置基线（主页/搜索引擎/扩展列表/代理/hosts），持久化到 data/browser_baseline.json
  3. 启动监控线程，定期 check_browser_integrity() 检测配置漂移
  4. protect_homepage / protect_search_engine / protect_extensions 单项保护
  5. 采用用户态轮询监控（内核驱动防护层已移除）

特性：
  - 浏览器路径检测：注册表查询 + 常见安装路径双策略
  - 线程安全（双重检查锁单例 + 实例锁）
  - JSON 持久化
"""

import os
import sys
import json
import time
import hashlib
import threading
import subprocess
import logging
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
# 配置基线持久化文件
BASELINE_FILE = os.path.join(_DATA_DIR, "browser_baseline.json")
# 日志目录
_LOG_DIR = os.path.join(_DATA_DIR, "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "browser_guard.log")

# 完整性检查间隔（秒）
CHECK_INTERVAL = 30

# 支持的浏览器列表
SUPPORTED_BROWSERS = ["chrome", "edge", "firefox", "ie"]

# hosts 文件路径
HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"

# 浏览器常见安装路径（注册表查询失败时回退）
BROWSER_INSTALL_PATHS = {
    "chrome": [
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ],
    "edge": [
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
    ],
    "firefox": [
        os.path.expandvars(r"%ProgramFiles%\Mozilla Firefox\firefox.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe"),
    ],
    "ie": [
        os.path.expandvars(r"%ProgramFiles%\Internet Explorer\iexplore.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Internet Explorer\iexplore.exe"),
    ],
}

# 浏览器用户数据目录（用于扩展、Preferences 等配置）
BROWSER_USER_DATA = {
    "chrome": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data"),
    "edge": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data"),
    "firefox": os.path.expandvars(r"%APPDATA%\Mozilla\Firefox"),
    "ie": "",  # IE 配置主要在注册表
}

# 注册表路径（用于查询主页/搜索引擎等）
BROWSER_REG_KEYS = {
    "ie_homepage": r"Software\Microsoft\Internet Explorer\Main",
    "ie_search": r"Software\Microsoft\Internet Explorer\Main",
    "chrome_homepage": r"Software\Google\Chrome\URLs",
    "edge_homepage": r"Software\Microsoft\Edge\BLBeacon",
}


# ============================================================
# 日志器
# ============================================================

def _get_logger() -> logging.Logger:
    """获取浏览器保护专用日志记录器"""
    os.makedirs(_LOG_DIR, exist_ok=True)
    logger = logging.getLogger("browser_guard")
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

def _file_sha256(path: str) -> str:
    """计算文件 SHA256 哈希"""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _read_registry(hive: int, subkey: str, value_name: str) -> Optional[str]:
    """读取注册表字符串值

    Args:
        hive: HKEY 根键（如 winreg.HKEY_CURRENT_USER）
        subkey: 子键路径
        value_name: 值名称

    Returns:
        值字符串，失败返回 None
    """
    if not IS_WINDOWS:
        return None
    try:
        import winreg
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
            return str(value)
    except Exception:
        return None


def _detect_browser_path(browser: str) -> Optional[str]:
    """检测浏览器安装路径

    优先查询注册表 App Paths，失败时回退到常见安装路径。

    Args:
        browser: 浏览器名称（chrome/edge/firefox/ie）

    Returns:
        浏览器可执行文件路径，未找到返回 None
    """
    if not IS_WINDOWS:
        return None

    # 注册表 App Paths 查询
    app_path_keys = {
        "chrome": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
        "edge": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
        "firefox": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe",
        "ie": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\iexplore.exe",
    }
    import winreg
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        path = _read_registry(hive, app_path_keys.get(browser, ""), "Path")
        if path:
            # Path 是目录，需要拼接可执行文件名
            exe_names = {
                "chrome": "chrome.exe",
                "edge": "msedge.exe",
                "firefox": "firefox.exe",
                "ie": "iexplore.exe",
            }
            full = os.path.join(path, exe_names.get(browser, ""))
            if os.path.isfile(full):
                return full

        # 也尝试直接读 (Default) 值
        default = _read_registry(hive, app_path_keys.get(browser, ""), "")
        if default and os.path.isfile(default):
            return default

    # 回退到常见安装路径
    for path in BROWSER_INSTALL_PATHS.get(browser, []):
        if os.path.isfile(path):
            return path

    return None


def _read_chromium_preferences(browser: str) -> dict:
    """读取 Chromium 系浏览器（Chrome/Edge）的 Preferences 文件

    Returns:
        Preferences JSON 字典，失败返回空字典
    """
    user_data = BROWSER_USER_DATA.get(browser, "")
    if not user_data or not os.path.isdir(user_data):
        return {}

    # 默认配置文件夹为 "Default"，也可能有多个 Profile
    profiles = ["Default"] + [
        d for d in os.listdir(user_data)
        if d.startswith("Profile ") and os.path.isdir(os.path.join(user_data, d))
    ]

    result = {}
    for profile in profiles:
        pref_path = os.path.join(user_data, profile, "Preferences")
        if os.path.isfile(pref_path):
            try:
                with open(pref_path, "r", encoding="utf-8") as f:
                    result[profile] = json.load(f)
            except Exception:
                continue
    return result


# ============================================================
# BrowserGuard — 浏览器保护引擎主类
# ============================================================

class BrowserGuard:
    """浏览器保护引擎

    保护 Chrome / Edge / Firefox / IE 浏览器配置不被恶意篡改。
    """

    # 驱动规则 ID 起始（避免与 custom_rules / honeypot 冲突）
    _next_rule_id = 80000

    def __init__(self):
        """初始化浏览器保护引擎"""
        self._logger = _get_logger()

        # 已检测到的浏览器路径 {browser: exe_path}
        self._browser_paths: dict[str, str] = {}
        self._paths_lock = threading.Lock()

        # 配置基线 {browser: {homepage, search_engine, extensions_hash, proxy, ...}}
        self._baseline: dict[str, dict] = {}
        self._baseline_lock = threading.Lock()

        # 启用状态
        self._enabled = False
        self._enabled_lock = threading.Lock()

        # 监控线程
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None

        # 驱动下发的规则 ID 列表（内核驱动防护层已移除，恒为空）
        self._driver_rule_ids: list[int] = []
        self._rule_ids_lock = threading.Lock()

        # 统计
        self._stats = {
            "browsers_protected": 0,
            "integrity_checks": 0,
            "anomalies_detected": 0,
        }
        self._stats_lock = threading.Lock()

        # 初始化延迟加载标记
        self._initialized = False

    def _ensure_init(self):
        """延迟初始化（首次 enable() 或 check 时触发）"""
        if not self._initialized:
            self._detect_all_browsers()
            self._load_baseline()
            self._initialized = True

        self._log("info", f"浏览器保护引擎初始化完成，检测到 "
                          f"{len(self._browser_paths)} 个浏览器")

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
        """启用浏览器保护

        1. 记录文件保护规则数量（内核驱动防护层已移除，恒为 0）
        2. 建立配置基线
        3. 启动监控线程

        Returns:
            {"enabled_browsers": list, "rules_pushed": int, "baseline_saved": bool}
        """
        self._ensure_init()
        with self._enabled_lock:
            if self._enabled:
                self._log("info", "浏览器保护已启用，跳过重复启用")
                return {"enabled_browsers": list(self._browser_paths.keys()),
                        "rules_pushed": 0, "baseline_saved": True}
            self._enabled = True

        # 文件保护规则（内核驱动防护层已移除，恒为 0 条）
        rules_pushed = 0
        for browser, exe_path in self._browser_paths.items():
            rules_pushed += self._push_browser_protection_rules(browser, exe_path)

        # 建立配置基线
        baseline_saved = self._establish_baseline()

        # 启动监控线程
        self._start_monitor()

        with self._stats_lock:
            self._stats["browsers_protected"] = len(self._browser_paths)

        self._log("info", f"浏览器保护已启用: 保护 {len(self._browser_paths)} 个浏览器，"
                          f"下发 {rules_pushed} 条规则")

        return {
            "enabled_browsers": list(self._browser_paths.keys()),
            "rules_pushed": rules_pushed,
            "baseline_saved": baseline_saved,
        }

    def disable(self) -> None:
        """停用浏览器保护"""
        with self._enabled_lock:
            self._enabled = False

        # 停止监控
        self._stop_monitor()

        # 移除驱动规则（内核驱动防护层已移除，空实现）
        self._remove_all_driver_rules()

        self._log("info", "浏览器保护已停用")

    # ── 单项保护 ──

    def protect_homepage(self, browser: str, url: str) -> bool:
        """保护指定浏览器的主页

        Args:
            browser: 浏览器名称
            url: 期望的主页 URL

        Returns:
            成功返回 True
        """
        if browser not in SUPPORTED_BROWSERS:
            self._log("error", f"不支持的浏览器: {browser}")
            return False

        # 写入基线
        with self._baseline_lock:
            if browser not in self._baseline:
                self._baseline[browser] = {}
            self._baseline[browser]["homepage"] = url
            self._baseline[browser]["homepage_protected_at"] = time.time()

        # 持久化
        self._save_baseline()

        self._log("info", f"已保护 {browser} 主页: {url}")
        return True

    def protect_search_engine(self, browser: str, engine: str) -> bool:
        """保护指定浏览器的搜索引擎

        Args:
            browser: 浏览器名称
            engine: 期望的搜索引擎名称（如 google / bing / baidu）

        Returns:
            成功返回 True
        """
        if browser not in SUPPORTED_BROWSERS:
            self._log("error", f"不支持的浏览器: {browser}")
            return False

        with self._baseline_lock:
            if browser not in self._baseline:
                self._baseline[browser] = {}
            self._baseline[browser]["search_engine"] = engine
            self._baseline[browser]["search_protected_at"] = time.time()

        self._save_baseline()

        self._log("info", f"已保护 {browser} 搜索引擎: {engine}")
        return True

    def protect_extensions(self, browser: str) -> bool:
        """保护指定浏览器的扩展列表（记录当前扩展哈希作为基线）

        Args:
            browser: 浏览器名称

        Returns:
            成功返回 True
        """
        if browser not in SUPPORTED_BROWSERS:
            return False

        extensions_hash = self._compute_extensions_hash(browser)
        if not extensions_hash:
            self._log("warning", f"无法获取 {browser} 扩展列表，跳过保护")
            return False

        with self._baseline_lock:
            if browser not in self._baseline:
                self._baseline[browser] = {}
            self._baseline[browser]["extensions_hash"] = extensions_hash
            self._baseline[browser]["extensions_protected_at"] = time.time()

        self._save_baseline()

        self._log("info", f"已保护 {browser} 扩展列表 (hash={extensions_hash[:16]}...)")
        return True

    # ── 完整性检查 ──

    def check_browser_integrity(self) -> list[dict]:
        """检查所有浏览器配置完整性

        检查项：主页 / 搜索引擎 / 代理 / hosts 文件 / 扩展列表

        Returns:
            异常列表，每项 {browser, check, expected, actual, detail}
        """
        self._ensure_init()
        anomalies: list[dict] = []

        with self._baseline_lock:
            baseline_snapshot = {b: dict(v) for b, v in self._baseline.items()}

        with self._stats_lock:
            self._stats["integrity_checks"] += 1

        for browser, baseline in baseline_snapshot.items():
            # 检查主页
            if "homepage" in baseline:
                current_homepage = self._get_current_homepage(browser)
                if current_homepage and current_homepage != baseline["homepage"]:
                    anomalies.append({
                        "browser": browser,
                        "check": "homepage",
                        "expected": baseline["homepage"],
                        "actual": current_homepage,
                        "detail": "主页被篡改",
                    })

            # 检查搜索引擎
            if "search_engine" in baseline:
                current_search = self._get_current_search_engine(browser)
                if current_search and current_search != baseline["search_engine"]:
                    anomalies.append({
                        "browser": browser,
                        "check": "search_engine",
                        "expected": baseline["search_engine"],
                        "actual": current_search,
                        "detail": "搜索引擎被篡改",
                    })

            # 检查扩展列表
            if "extensions_hash" in baseline:
                current_ext_hash = self._compute_extensions_hash(browser)
                if current_ext_hash and current_ext_hash != baseline["extensions_hash"]:
                    anomalies.append({
                        "browser": browser,
                        "check": "extensions",
                        "expected": baseline["extensions_hash"][:16] + "...",
                        "actual": current_ext_hash[:16] + "...",
                        "detail": "扩展列表被修改",
                    })

        # 检查系统级项：hosts 文件
        hosts_anomaly = self._check_hosts_file()
        if hosts_anomaly:
            anomalies.append(hosts_anomaly)

        # 检查代理设置
        proxy_anomaly = self._check_proxy_setting()
        if proxy_anomaly:
            anomalies.append(proxy_anomaly)

        if anomalies:
            with self._stats_lock:
                self._stats["anomalies_detected"] += len(anomalies)
            self._log("warning", f"完整性检查发现 {len(anomalies)} 个异常")

        return anomalies

    # ── 状态查询 ──

    def get_status(self) -> dict:
        """获取浏览器保护完整状态"""
        self._ensure_init()
        with self._paths_lock:
            paths = dict(self._browser_paths)
        with self._baseline_lock:
            baseline_count = len(self._baseline)
        with self._stats_lock:
            stats = dict(self._stats)
        with self._rule_ids_lock:
            rules_count = len(self._driver_rule_ids)

        return {
            "enabled": self.enabled,
            "driver_available": self.driver_available,
            "browsers_detected": paths,
            "baseline_count": baseline_count,
            "driver_rules_count": rules_count,
            "stats": stats,
            "baseline_file": BASELINE_FILE,
        }

    # ── 浏览器路径检测（私有） ──

    def _detect_all_browsers(self) -> None:
        """检测所有支持浏览器的安装路径"""
        with self._paths_lock:
            self._browser_paths.clear()
            for browser in SUPPORTED_BROWSERS:
                path = _detect_browser_path(browser)
                if path:
                    self._browser_paths[browser] = path
                    self._log("info", f"检测到 {browser}: {path}")

    # ── 驱动规则下发（私有） ──

    def _push_browser_protection_rules(self, browser: str, exe_path: str) -> int:
        """下发浏览器文件保护规则

        保护对象：浏览器可执行文件、用户数据目录、扩展目录
        内核驱动防护层已移除，规则无法下发，恒返回 0（仅用户态监控）。
        """
        self._log("info", f"内核驱动防护层已移除，{browser} 仅启用用户态监控")
        return 0

    def _remove_all_driver_rules(self) -> None:
        """移除所有已下发的浏览器保护规则

        内核驱动防护层已移除，仅清空本地记录的规则 ID。
        """
        with self._rule_ids_lock:
            self._driver_rule_ids.clear()

    # ── 基线建立（私有） ──

    def _establish_baseline(self) -> bool:
        """建立所有已检测浏览器的配置基线"""
        with self._baseline_lock:
            self._baseline.clear()

        for browser in self._browser_paths:
            baseline = {
                "homepage": self._get_current_homepage(browser) or "",
                "search_engine": self._get_current_search_engine(browser) or "",
                "extensions_hash": self._compute_extensions_hash(browser) or "",
                "established_at": time.time(),
            }
            with self._baseline_lock:
                self._baseline[browser] = baseline

        # 系统级基线
        with self._baseline_lock:
            self._baseline["_system"] = {
                "hosts_hash": _file_sha256(HOSTS_FILE),
                "proxy": self._get_current_proxy(),
                "established_at": time.time(),
            }

        return self._save_baseline()

    def _get_current_homepage(self, browser: str) -> Optional[str]:
        """获取浏览器当前主页"""
        if not IS_WINDOWS:
            return None
        try:
            import winreg
            if browser == "ie":
                return _read_registry(winreg.HKEY_CURRENT_USER,
                                      BROWSER_REG_KEYS["ie_homepage"], "Start Page")
            elif browser in ("chrome", "edge"):
                # Chromium 系读取 Preferences
                prefs = _read_chromium_preferences(browser)
                for profile, data in prefs.items():
                    # homepage 是 homepage 字段或 startup URLs
                    hp = data.get("homepage")
                    if hp:
                        return hp
                    startup = data.get("session", {}).get("restore_on_startup")
                    urls = data.get("session", {}).get("urls_to_restore_on_startup", [])
                    if urls:
                        return urls[0].get("url")
            elif browser == "firefox":
                # Firefox 读取 prefs.js
                ff_dir = BROWSER_USER_DATA.get("firefox", "")
                if ff_dir and os.path.isdir(ff_dir):
                    profiles_ini = os.path.join(ff_dir, "profiles.ini")
                    if os.path.isfile(profiles_ini):
                        # 简化处理：扫描 defaults/prefs.js
                        for root, dirs, files in os.walk(ff_dir):
                            for fname in files:
                                if fname == "prefs.js":
                                    fpath = os.path.join(root, fname)
                                    try:
                                        with open(fpath, "r", encoding="utf-8") as f:
                                            for line in f:
                                                if "browser.startup.homepage" in line:
                                                    # 解析 user_pref("browser.startup.homepage", "http://...");
                                                    parts = line.split(",", 1)
                                                    if len(parts) == 2:
                                                        rest = parts[1].strip()
                                                        # rest 形如 "http://...");
                                                        if rest.startswith('"'):
                                                            end = rest.find('"', 1)
                                                            if end > 0:
                                                                return rest[1:end]
                                    except Exception:
                                        continue
        except Exception as e:
            self._log("error", f"获取 {browser} 主页失败: {e}")
        return None

    def _get_current_search_engine(self, browser: str) -> Optional[str]:
        """获取浏览器当前默认搜索引擎"""
        try:
            if browser in ("chrome", "edge"):
                prefs = _read_chromium_preferences(browser)
                for profile, data in prefs.items():
                    # default_search_provider 数据
                    dsp = data.get("default_search_provider_data", {})
                    template = dsp.get("template_url", "")
                    if "google" in template.lower():
                        return "google"
                    elif "bing" in template.lower():
                        return "bing"
                    elif "baidu" in template.lower():
                        return "baidu"
                    return template
            elif browser == "ie":
                # IE 搜索引擎在注册表
                if IS_WINDOWS:
                    import winreg
                    return _read_registry(winreg.HKEY_CURRENT_USER,
                                          r"Software\Microsoft\Internet Explorer\SearchScopes",
                                          "DefaultScope")
        except Exception:
            pass
        return None

    def _compute_extensions_hash(self, browser: str) -> str:
        """计算浏览器扩展列表的哈希（用于检测扩展变更）"""
        if browser not in ("chrome", "edge"):
            # Firefox / IE 暂不支持扩展哈希
            return ""

        user_data = BROWSER_USER_DATA.get(browser, "")
        if not user_data or not os.path.isdir(user_data):
            return ""

        ext_ids = []
        # 遍历所有 Profile 的 Extensions 目录
        profiles = ["Default"] + [
            d for d in os.listdir(user_data)
            if d.startswith("Profile ") and os.path.isdir(os.path.join(user_data, d))
        ]
        for profile in profiles:
            ext_dir = os.path.join(user_data, profile, "Extensions")
            if os.path.isdir(ext_dir):
                try:
                    ext_ids.extend(sorted(os.listdir(ext_dir)))
                except Exception:
                    continue

        if not ext_ids:
            return ""

        # 对扩展 ID 列表计算哈希
        content = "\n".join(ext_ids)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _get_current_proxy(self) -> str:
        """获取当前系统代理设置"""
        if not IS_WINDOWS:
            return ""
        try:
            import winreg
            proxy_enable = _read_registry(winreg.HKEY_CURRENT_USER,
                                          r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                                          "ProxyEnable")
            proxy_server = _read_registry(winreg.HKEY_CURRENT_USER,
                                          r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                                          "ProxyServer")
            return f"{proxy_enable or '0'}|{proxy_server or ''}"
        except Exception:
            return ""

    def _check_hosts_file(self) -> Optional[dict]:
        """检查 hosts 文件是否被修改"""
        with self._baseline_lock:
            sys_baseline = self._baseline.get("_system", {})
            expected_hash = sys_baseline.get("hosts_hash", "")

        if not expected_hash:
            return None

        current_hash = _file_sha256(HOSTS_FILE)
        if current_hash and current_hash != expected_hash:
            return {
                "browser": "_system",
                "check": "hosts",
                "expected": expected_hash[:16] + "...",
                "actual": current_hash[:16] + "...",
                "detail": "hosts 文件被修改（可能用于 DNS 劫持）",
            }
        return None

    def _check_proxy_setting(self) -> Optional[dict]:
        """检查代理设置是否被修改"""
        with self._baseline_lock:
            sys_baseline = self._baseline.get("_system", {})
            expected_proxy = sys_baseline.get("proxy", "")

        if not expected_proxy:
            return None

        current_proxy = self._get_current_proxy()
        if current_proxy and current_proxy != expected_proxy:
            return {
                "browser": "_system",
                "check": "proxy",
                "expected": expected_proxy,
                "actual": current_proxy,
                "detail": "系统代理设置被修改",
            }
        return None

    # ── 监控线程 ──

    def _start_monitor(self) -> None:
        """启动完整性监控线程"""
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            return
        self._stop_event.clear()
        t = threading.Thread(target=self._monitor_loop, daemon=True, name="BrowserGuardMonitor")
        t.start()
        self._monitor_thread = t
        self._log("info", "浏览器完整性监控线程已启动")

    def _stop_monitor(self) -> None:
        """停止监控线程"""
        self._stop_event.set()
        t = self._monitor_thread
        if t is not None and t.is_alive():
            t.join(timeout=2.0)
        self._monitor_thread = None

    def _monitor_loop(self) -> None:
        """完整性监控主循环"""
        while not self._stop_event.is_set():
            try:
                if self.enabled:
                    anomalies = self.check_browser_integrity()
                    if anomalies:
                        for a in anomalies:
                            self._log("warning",
                                      f"完整性异常: browser={a['browser']} "
                                      f"check={a['check']} detail={a['detail']}")
                        self._show_alert(anomalies)
            except Exception as e:
                self._log("error", f"监控循环异常: {e}")

            self._stop_event.wait(CHECK_INTERVAL)

    def _show_alert(self, anomalies: list[dict]) -> None:
        """显示浏览器篡改告警弹窗"""
        if not IS_WINDOWS:
            return
        title = "御天 浏览器保护告警"
        lines = [f"检测到 {len(anomalies)} 项浏览器配置异常：\n"]
        for a in anomalies[:5]:
            lines.append(f"[{a['browser']}] {a['check']}: {a['detail']}")
        body = "\n".join(lines)
        body += "\n\n御天已记录异常，请检查浏览器设置是否被恶意修改。"
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, body, title, 0x30 | 0x1000)
        except Exception:
            pass

    # ── 持久化 ──

    def _save_baseline(self) -> bool:
        """将配置基线持久化到 data/browser_baseline.json"""
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            with self._baseline_lock:
                data = {
                    "saved_at": time.time(),
                    "browsers_detected": dict(self._browser_paths),
                    "baseline": {b: dict(v) for b, v in self._baseline.items()},
                }
            with open(BASELINE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            self._log("error", f"基线持久化失败: {e}")
            return False

    def _load_baseline(self) -> bool:
        """从 data/browser_baseline.json 加载配置基线"""
        if not os.path.exists(BASELINE_FILE):
            return False
        try:
            with open(BASELINE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            with self._baseline_lock:
                self._baseline = data.get("baseline", {})
            return True
        except Exception as e:
            self._log("error", f"基线加载失败: {e}")
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

_browser_guard: Optional[BrowserGuard] = None
_browser_guard_lock = threading.Lock()


def get_browser_guard() -> BrowserGuard:
    """获取全局唯一的 BrowserGuard 实例（双重检查锁定单例）

    Returns:
        全局唯一的 BrowserGuard 实例
    """
    global _browser_guard
    if _browser_guard is None:
        with _browser_guard_lock:
            if _browser_guard is None:
                _browser_guard = BrowserGuard()
    return _browser_guard


# ============================================================
# 模块自检（直接运行时执行）
# ============================================================

if __name__ == "__main__":
    guard = BrowserGuard()

    print("[browser_guard] 状态:", guard.get_status())

    print("[browser_guard] 启用保护...")
    result = guard.enable()
    print(f"[browser_guard] 启用结果: {result}")

    # 保护主页
    guard.protect_homepage("chrome", "https://www.google.com")
    guard.protect_search_engine("chrome", "google")
    guard.protect_extensions("chrome")

    print("[browser_guard] 完整性检查:")
    anomalies = guard.check_browser_integrity()
    print(f"[browser_guard] 异常数: {len(anomalies)}")
    for a in anomalies:
        print(f"  - {a}")

    print("[browser_guard] 最终状态:", guard.get_status())

    guard.disable()
