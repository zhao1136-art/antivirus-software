"""
御天 后端配置
"""
import os
import sys


def _get_base_dir():
    """获取基础目录（兼容开发模式和 PyInstaller 打包模式）"""
    if getattr(sys, 'frozen', False):
        # PyInstaller 打包模式: 源码在 _internal/，exe 在上层
        # sys._MEIPASS 指向 _internal/ 目录
        return sys._MEIPASS
    # 开发模式
    return os.path.dirname(os.path.abspath(__file__))


def _get_data_dir():
    """获取可写运行时数据目录。

    打包模式下 _internal/（sys._MEIPASS）是只读位置，SQLite 无法在其下建 WAL 日志，
    因此数据落到 %LOCALAPPDATA%\\Andun（当前用户一定可写）。
    开发模式沿用源码目录，便于直接调试。
    """
    if getattr(sys, 'frozen', False):
        # 用当前用户一定可写的目录（%ProgramData% 可能受安装权限/安全软件限制，
        # 导致 SQLite 无法创建 WAL 日志而报 disk I/O error）
        local_app_data = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(local_app_data, "Andun", "data")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "engine", "data")


BASE_DIR = _get_base_dir()
ENGINE_DIR = os.path.join(BASE_DIR, "engine")
DATA_DIR = _get_data_dir()

# 确保运行时目录存在（用于 PyInstaller 模式下自动创建）
# 目录创建失败不致命：避免单个目录权限问题在导入期直接拖垮整个进程；
# 真正用到该目录的功能会在后续触发明确错误，且已被 app.py 的诊断引导捕获。
for _sub_dir in ("db", "logs", "quarantine"):
    try:
        os.makedirs(os.path.join(DATA_DIR, _sub_dir), exist_ok=True)
    except Exception as _dir_e:
        try:
            print(f"[config] 目录创建失败（非致命）: {os.path.join(DATA_DIR, _sub_dir)} -> {_dir_e}")
        except Exception:
            pass

# ── 持久化配置加载（启动时自动加载用户自定义设置） ──
try:
    from persistence import load_config_save
    _persistent_config = load_config_save()
    _scan_cfg = _persistent_config.get("scan", {})

    # 扫描配置覆盖
    if _scan_cfg.get("max_workers", 0) > 0:
        MAX_WORKERS = _scan_cfg["max_workers"]
    if _scan_cfg.get("single_file_timeout", 0) > 0:
        SINGLE_FILE_TIMEOUT = _scan_cfg["single_file_timeout"]
    if _scan_cfg.get("max_file_size_mb", 0) > 0:
        MAX_FILE_SIZE = _scan_cfg["max_file_size_mb"] * 1024 * 1024
    if _scan_cfg.get("ml_pe_max_read_mb", 0) > 0:
        ML_PE_MAX_READ = _scan_cfg["ml_pe_max_read_mb"] * 1024 * 1024
    if _scan_cfg.get("yara_enabled", True) is False:
        YARA_ENABLED = False
    if _scan_cfg.get("cloud_enabled", True) is False:
        CLOUD_ENABLED = False

    # 网络监控配置覆盖
    _net_cfg = _persistent_config.get("network", {})
    if _net_cfg.get("monitor_interval", 0) > 0:
        NETWORK_MONITOR_INTERVAL = _net_cfg["monitor_interval"]

    # 策略配置覆盖
    _policy_cfg = _persistent_config.get("policy", {})
    if _policy_cfg.get("log_retention_days", 0) > 0:
        LOG_RETENTION_DAYS = _policy_cfg["log_retention_days"]

    # 云查杀 engines 配置（引擎优先级 / AVIC 凭据）保存在 cloud 段；
    # 但对应常量（CLOUD_ENGINE_ORDER / AVIC_API_KEY）定义在本模块下方，
    # 此处先留存原始配置，待常量定义完成后再覆盖，避免被默认值冲掉。
    _PERSISTED_CLOUD_CFG = _persistent_config.get("cloud", {})
except Exception:
    pass

# 特征库路径
SIGNATURES_DIR = os.path.join(DATA_DIR, "signatures")
SIGNATURES_DB = os.path.join(DATA_DIR, "db", "signatures.db")

# 本地病毒库目录（打包内 bingduku/），支持从源码根目录和 _internal 两种模式查找
def _get_bingduku_dir():
    # 开发模式: f:\Caelire\bingduku（BASE_DIR = backend 目录的上一层）
    if not getattr(sys, 'frozen', False):
        dev_dir = os.path.join(os.path.dirname(BASE_DIR), "bingduku")
        if os.path.isdir(dev_dir):
            return dev_dir
    # 打包模式: _internal/bingduku
    frozen_dir = os.path.join(BASE_DIR, "bingduku")
    if os.path.isdir(frozen_dir):
        return frozen_dir
    return dev_dir if not getattr(sys, 'frozen', False) else frozen_dir

BINGDUKU_DIR = _get_bingduku_dir()
BINGDUKU_MD5_TXT = os.path.join(BINGDUKU_DIR, "扫描-病毒特征库20260419.txt")
BINGDUKU_DAT = os.path.join(BINGDUKU_DIR, "virus.dat")

# 数据库目录（病毒记忆等模块使用）
# 打包模式下 _internal/ 只读，故落到可写数据目录，避免 disk I/O error；
# 开发模式沿用原 backend/database，保留既有数据。
if getattr(sys, 'frozen', False):
    DATABASE_DIR = os.path.join(DATA_DIR, "database")
else:
    DATABASE_DIR = os.path.join(BASE_DIR, "database")
os.makedirs(DATABASE_DIR, exist_ok=True)

# YARA 规则目录
def _get_yara_rules_dir():
    """获取 YARA 规则目录（兼容开发模式和 PyInstaller）"""
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, "engine", "yara_rules")
    # 开发模式：优先使用 engine 下的 yara_rules，其次用外部目录
    local_rules = os.path.join(ENGINE_DIR, "yara_rules")
    if os.path.isdir(local_rules) and os.listdir(local_rules):
        return local_rules
    # 回退到项目目录下的 Yara-rules-master
    fallback = os.path.join(os.path.dirname(BASE_DIR), "Yara-rules-master", "Yara-rules-master", "rules")
    if os.path.isdir(fallback):
        return fallback
    return local_rules  # 默认位置

YARA_RULES_DIR = _get_yara_rules_dir()

# 隔离区路径
QUARANTINE_DIR = os.path.join(DATA_DIR, "quarantine")

# 日志路径
LOGS_DIR = os.path.join(DATA_DIR, "logs")
SCAN_LOG_FILE = os.path.join(LOGS_DIR, "scan.log")
THREAT_LOG_FILE = os.path.join(LOGS_DIR, "threat.log")
SYSTEM_GUARD_LOG_FILE = os.path.join(LOGS_DIR, "system_guard.log")
FILE_GUARD_LOG_FILE = os.path.join(LOGS_DIR, "file_guard.log")

# 扫描配置
SCAN_EXTENSIONS = {
    "executables": {".exe", ".dll", ".sys", ".com", ".scr", ".pif", ".ocx", ".bin", ".drv"},
    "scripts": {".ps1", ".bat", ".cmd", ".vbs", ".js", ".vba", ".py", ".sh"},
    "documents": {".doc", ".docx", ".xls", ".xlsx", ".pdf", ".rtf"},
    "archives": {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"},
    "all_scan": set()  # empty means all extensions in quick/full scan
}

# 排除目录（快速扫描跳过）
EXCLUDED_DIRS = {
    "$Recycle.Bin", "System Volume Information",
    "Windows\\WinSxS", "Windows\\SoftwareDistribution",
    "Windows\\Installer", "Windows\\Temp", "Prefetch",
    "node_modules", "__pycache__", ".git", ".svn"
}

# ============ P0-1 并发与文件过滤 ============
# 线程池大小 - 半核封顶 8，防止 CPU 爆满
_CPU_COUNT = os.cpu_count() or 4
MAX_WORKERS = max(1, min(_CPU_COUNT // 2, 8))
# 前台有交互时自动降为 1/4
IDLE_WORKERS_FOREGROUND = max(1, MAX_WORKERS // 4)
# 所有后台 while True 循环最小休眠时间
SCHED_LOOP_SLEEP_SEC = 0.1
REALTIME_GUARD_SLEEP_SEC = 0.25
PROCESS_GUARD_SLEEP_SEC = max(3, 3)

# 扫描最大文件大小：超过此值进入"大文件模式"
MAX_FILE_SIZE = 200 * 1024 * 1024       # 200MB 全扫上限
LARGE_FILE_THRESH = 200 * 1024 * 1024   # 大文件阈值
LARGE_FILE_HEADER_READ = 4 * 1024 * 1024  # 大文件只读首 4MB
LARGE_FILE_ABS_CAP = 2 * 1024 * 1024 * 1024  # 大文件绝对上限 2GB，超过直接跳过

# 云查前置节流：单文件云查询最小间隔（秒），防止全盘扫描刷爆云端 API
CLOUD_QUERY_MIN_INTERVAL = 0.05  # 约 20 次/秒


def foreground_active() -> bool:
    """检测前台窗口是否属于其他进程（本程序被切到后台时返回 True，用于扫描降权）"""
    if os.name != "nt":
        return False
    try:
        import ctypes
        user32 = ctypes.windll.user32
        fg = user32.GetForegroundWindow()
        if not fg:
            return False
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(fg, ctypes.byref(pid))
        return bool(pid.value) and pid.value != os.getpid()
    except Exception:
        return False

# 流式扫描窗口：每收集 N 个文件就送线程池，避免一次性内存存满
SCAN_STREAM_WINDOW = 128

# 黑名单：永不扫描的系统文件/目录名
BLACKLIST_FILE_NAMES = {
    "hiberfil.sys", "pagefile.sys", "swapfile.sys",
    "hiberfile.sys", "memory.dmp"
}
BLACKLIST_DIR_PARTS = {
    "$RECYCLE.BIN", "System Volume Information",
    "WinSxS", "SoftwareDistribution\\Download",
    "Windows\\Installer", "Windows\\Temp", "Prefetch"
}

# 单文件扫描超时（秒）- 防止大文件/损坏文件卡死
SINGLE_FILE_TIMEOUT = 60

# PE文件ML扫描大小上限（超过此大小只截取前N字节）
ML_PE_MAX_READ = 32 * 1024 * 1024  # 32MB

# ============ P0-3 缓存上限 ============
# 扫描结果缓存（SHA256 → 威胁列表）
SCAN_CACHE_MAX = 32768          # 32K 条
SCAN_CACHE_TTL = 7200           # 2 小时
# AI 灰度图缓存
AI_IMAGE_CACHE_MAX = 4096       # 4K 条
AI_IMAGE_CACHE_TTL = 1800       # 30 分钟
# 云端结果缓存
CLOUD_CACHE_TTL = 7 * 24 * 3600  # 7天

# 威胁等级
THREAT_LEVELS = ["safe", "low", "medium", "high", "critical"]

# 处置动作
ACTIONS = ["ignore", "prompt", "quarantine", "delete"]

# 云端 API 配置
CLOUD_API_KEY = os.environ.get("THREATBOOK_API_KEY", "")
CLOUD_ENABLED = os.environ.get("CLOUD_SCAN_ENABLED", "true").lower() == "true"
CLOUD_CACHE_TTL = 7 * 24 * 3600  # 7天

# AVIC 社区联合情报中心配置
# 安全要求：不内置明文密钥（否则会随源码/镜像一起发布泄露）。
# 解析优先级：data/config_save.json 的 cloud.avic_api_key > 环境变量 AVIC_API_KEY > 空串。
# 为空串时 AVIC 引擎降级为「未配置」，云查功能其余引擎（微步/OTX）不受影响。
AVIC_API_KEY = os.environ.get("AVIC_API_KEY", "")
AVIC_BASE_URL = "https://avic.xiguastudio.top"
AVIC_ENABLED = True

# 云查杀引擎优先级（按顺序查询，命中即返回）
CLOUD_ENGINE_ORDER = ["avic", "threatbook", "otx"]

# 用户配置文件（data/config_save.json 的 cloud 段）优先于默认值 / 环境变量。
# 注意：必须在常量定义之后再覆盖 —— 本文件顶部的持久化加载块早于这些定义，
# 在那里赋值会被下面的默认值覆盖掉。
try:
    _persisted_cloud = globals().get("_PERSISTED_CLOUD_CFG") or {}
    if _persisted_cloud.get("avic_api_key"):
        AVIC_API_KEY = _persisted_cloud["avic_api_key"]
    if _persisted_cloud.get("engine_order"):
        CLOUD_ENGINE_ORDER = list(_persisted_cloud["engine_order"])
except Exception:
    pass

# ===== 系统进程保护配置 =====
# 进程监控扫描间隔（秒）
PROCESS_GUARD_INTERVAL = 3
# 是否启用进程名伪装检测
PROCESS_GUARD_DETECT_SPOOFING = True
# 是否启用可疑路径启动检测
PROCESS_GUARD_DETECT_SUSPICIOUS_PATH = True

# ===== 系统文件防篡改配置 =====
# 文件完整性扫描间隔（秒）
FILE_GUARD_INTERVAL = 10
# 单次扫描最大文件数
FILE_GUARD_MAX_FILES = 500
# 是否监控受保护目录中的新文件
FILE_GUARD_DETECT_NEW_FILES = True
