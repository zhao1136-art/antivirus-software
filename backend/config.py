"""
安盾 后端配置
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


BASE_DIR = _get_base_dir()
ENGINE_DIR = os.path.join(BASE_DIR, "engine")
DATA_DIR = os.path.join(ENGINE_DIR, "data")

# 确保运行时目录存在（用于 PyInstaller 模式下自动创建）
os.makedirs(os.path.join(DATA_DIR, "db"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "quarantine"), exist_ok=True)

# 特征库路径
SIGNATURES_DIR = os.path.join(DATA_DIR, "signatures")
SIGNATURES_DB = os.path.join(DATA_DIR, "db", "signatures.db")

# 漏洞数据库路径（专用数据库文件夹）
DATABASE_DIR = os.path.join(BASE_DIR, "database")
VULN_DB = os.path.join(DATABASE_DIR, "vulnerabilities.db")
os.makedirs(DATABASE_DIR, exist_ok=True)

# YARA 规则目录
def _get_yara_rules_dir():
    """获取 YARA 规则目录（兼容开发模式和 PyInstaller）"""
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, "yara_rules")
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
    "node_modules", "__pycache__", ".git", ".svn"
}

# 扫描最大文件大小 (100MB)
MAX_FILE_SIZE = 100 * 1024 * 1024

# 线程池大小
MAX_WORKERS = 4

# 威胁等级
THREAT_LEVELS = ["safe", "low", "medium", "high", "critical"]

# 处置动作
ACTIONS = ["ignore", "prompt", "quarantine", "delete"]

# 云端 API 配置
CLOUD_API_KEY = os.environ.get("THREATBOOK_API_KEY", "")
CLOUD_ENABLED = os.environ.get("CLOUD_SCAN_ENABLED", "true").lower() == "true"
CLOUD_CACHE_TTL = 7 * 24 * 3600  # 7天

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
