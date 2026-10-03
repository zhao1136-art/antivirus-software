"""
御天 持久化存储模块
管理 data/ 目录下的 config_save.json / guard_days.json / scan_cache.db
启动时加载、运行时自动保存、退出时强制写入
"""
import os
import sys
import json
import time
import sqlite3
import threading
from datetime import datetime, date
from typing import Optional

# ── 数据目录定位 ──────────────────────────────────────────

def _get_data_dir():
    """获取持久化数据目录

    打包模式：_internal/ 与 exe 所在目录都可能是只读位置（如 Program Files），
    统一落到 %LOCALAPPDATA%\\Andun\\data，且与 config.py 的运行时数据目录保持一致。
    开发模式：项目根目录 data/。
    """
    if getattr(sys, 'frozen', False):
        # %LOCALAPPDATA% 当前用户一定可写（%ProgramData% 可能权限受限，
        # 导致 SQLite WAL / 持久化写入失败）
        local_app_data = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(local_app_data, "Andun", "data")
    # 开发模式：项目根目录
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "data")

DATA_DIR = _get_data_dir()
CONFIG_SAVE_PATH = os.path.join(DATA_DIR, "config_save.json")
GUARD_DAYS_PATH = os.path.join(DATA_DIR, "guard_days.json")
CACHE_DB_PATH = os.path.join(DATA_DIR, "scan_cache.db")

# 确保目录存在
os.makedirs(DATA_DIR, exist_ok=True)

_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════
#  1. config_save.json — 用户自定义扫描设置
# ══════════════════════════════════════════════════════════════

DEFAULT_CONFIG_SAVE = {
    "scan": {
        "max_workers": 0,            # 0 = 自动（根据 CPU 核心数）
        "single_file_timeout": 60,   # 单文件扫描超时（秒）
        "ml_pe_max_read_mb": 32,     # ML 扫描文件大小上限（MB）
        "yara_enabled": True,
        "ml_enabled": True,
        "cloud_enabled": True,
        "scan_archives": True,
        "max_file_size_mb": 100,
    },
    "protection": {
        "file_shield": True,
        "network_shield": True,
        "behavior_shield": True,
        "ransomware_shield": True,
        "process_guard": True,
        "file_guard": True,
    },
    "features": {
        "auto_start": False,
        "shell_menu": False,
        "game_mode": True,
        "usb_scan": True,
        "tray_icon": True,
        "etw_guard": True,
        "amsi_provider": True,
    },
    "network": {
        "monitor_interval": 5,
        "alert_level": "high",
    },
    "cloud": {
        # 云查杀引擎优先级（用户可在设置页选择，按顺序降级查询）
        "engine_order": ["avic", "threatbook", "otx"],
        # AVIC 情报中心 API Key（用户可选填；为空则读环境变量 AVIC_API_KEY）
        "avic_api_key": "",
    },
    "policy": {
        "threat_action": "quarantine",
        "auto_update_signatures": True,
        "log_retention_days": 30,
    },
}


def load_config_save() -> dict:
    """加载用户自定义配置，缺失字段用默认值补全"""
    if not os.path.isfile(CONFIG_SAVE_PATH):
        return dict(DEFAULT_CONFIG_SAVE)
    try:
        with open(CONFIG_SAVE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        # 递归合并默认值，确保新版本新增字段不会丢失
        merged = dict(DEFAULT_CONFIG_SAVE)
        _deep_merge(merged, data)
        return merged
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_CONFIG_SAVE)


def save_config_save(config: dict):
    """保存用户自定义配置到磁盘"""
    with _lock:
        try:
            with open(CONFIG_SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except OSError:
            pass


def _deep_merge(base: dict, override: dict):
    """递归合并字典，override 中的值覆盖 base"""
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


# ══════════════════════════════════════════════════════════════
#  2. guard_days.json — 守护起始时间 & 累计守护天数
# ══════════════════════════════════════════════════════════════

DEFAULT_GUARD_DAYS = {
    "first_start_date": "",       # 首次启动日期 YYYY-MM-DD
    "last_start_date": "",        # 上次启动日期
    "accumulated_days": 0,        # 累计守护天数
}


def load_guard_days() -> dict:
    """加载守护天数记录"""
    if not os.path.isfile(GUARD_DAYS_PATH):
        return dict(DEFAULT_GUARD_DAYS)
    try:
        with open(GUARD_DAYS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = dict(DEFAULT_GUARD_DAYS)
        merged.update(data)
        return merged
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_GUARD_DAYS)


def save_guard_days(guard_data: dict):
    """保存守护天数记录到磁盘"""
    with _lock:
        try:
            with open(GUARD_DAYS_PATH, "w", encoding="utf-8") as f:
                json.dump(guard_data, f, ensure_ascii=False, indent=2)
        except OSError:
            pass


def update_guard_days() -> dict:
    """
    每日更新守护天数逻辑：
    - 首次启动：记录 first_start_date = 今天
    - 非首次：对比 last_start_date 与今天
      - 同一天：不增加天数
      - 不同天：accumulated_days + 1
    - 更新 last_start_date = 今天
    - 返回更新后的数据
    """
    guard = load_guard_days()
    today_str = date.today().isoformat()

    if not guard["first_start_date"]:
        # 首次启动
        guard["first_start_date"] = today_str
        guard["last_start_date"] = today_str
        guard["accumulated_days"] = 1
    else:
        if guard["last_start_date"] != today_str:
            # 新的一天，增加守护天数
            guard["accumulated_days"] += 1
            guard["last_start_date"] = today_str
        # 同一天启动不做任何修改

    save_guard_days(guard)
    return guard


# ══════════════════════════════════════════════════════════════
#  3. scan_cache.db — 持久化扫描缓存（替代纯内存 LRU）
# ══════════════════════════════════════════════════════════════

_CACHE_DB_INIT = False
_CACHE_DB_LOCK = threading.Lock()


def _init_cache_db():
    """初始化扫描缓存数据库"""
    global _CACHE_DB_INIT
    if _CACHE_DB_INIT:
        return
    with _CACHE_DB_LOCK:
        if _CACHE_DB_INIT:
            return
        conn = sqlite3.connect(CACHE_DB_PATH, timeout=5)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_cache (
                cache_key TEXT PRIMARY KEY,
                result_json TEXT NOT NULL,
                file_size INTEGER DEFAULT 0,
                file_mtime REAL DEFAULT 0,
                hit_count INTEGER DEFAULT 1,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cache_expires
            ON scan_cache(expires_at)
        """)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")
        conn.commit()
        conn.close()
        _CACHE_DB_INIT = True


def cache_get(cache_key: str) -> Optional[dict]:
    """从缓存获取扫描结果，命中时增加 hit_count"""
    _init_cache_db()
    now = time.time()
    try:
        conn = sqlite3.connect(CACHE_DB_PATH, timeout=5)
        row = conn.execute(
            "SELECT result_json, expires_at FROM scan_cache WHERE cache_key = ?",
            (cache_key,)
        ).fetchone()
        if row:
            result_json, expires_at = row
            if now < expires_at:
                # 未过期，增加 hit_count
                conn.execute(
                    "UPDATE scan_cache SET hit_count = hit_count + 1 WHERE cache_key = ?",
                    (cache_key,)
                )
                conn.commit()
                conn.close()
                return json.loads(result_json)
            else:
                # 已过期，删除
                conn.execute("DELETE FROM scan_cache WHERE cache_key = ?", (cache_key,))
                conn.commit()
        conn.close()
    except (sqlite3.Error, json.JSONDecodeError):
        pass
    return None


def cache_set(cache_key: str, result: dict, file_size: int = 0,
              file_mtime: float = 0, ttl: int = 300):
    """写入扫描结果到缓存"""
    _init_cache_db()
    now = time.time()
    try:
        conn = sqlite3.connect(CACHE_DB_PATH, timeout=5, check_same_thread=False)
        conn.execute(
            """INSERT OR REPLACE INTO scan_cache
               (cache_key, result_json, file_size, file_mtime, hit_count, created_at, expires_at)
               VALUES (?, ?, ?, ?, 1, ?, ?)""",
            (cache_key, json.dumps(result), file_size, file_mtime, now, now + ttl)
        )
        conn.commit()
        conn.close()
    except sqlite3.Error:
        pass


def cache_clear():
    """清空所有缓存"""
    _init_cache_db()
    try:
        conn = sqlite3.connect(CACHE_DB_PATH, timeout=5)
        conn.execute("DELETE FROM scan_cache")
        conn.commit()
        conn.close()
    except sqlite3.Error:
        pass


def cache_stats() -> dict:
    """缓存统计信息"""
    _init_cache_db()
    try:
        conn = sqlite3.connect(CACHE_DB_PATH, timeout=5)
        row = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(hit_count), 0), "
            "COALESCE(SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END), 0) "
            "FROM scan_cache",
            (time.time(),)
        ).fetchone()
        conn.close()
        total = row[0] if row else 0
        total_hits = row[1] if row else 0
        valid = row[2] if row else 0
        return {
            "total_entries": total,
            "valid_entries": valid,
            "expired_entries": total - valid,
            "total_hits": total_hits,
        }
    except sqlite3.Error:
        return {"total_entries": 0, "valid_entries": 0, "expired_entries": 0, "total_hits": 0}


def cache_cleanup(max_entries: int = 10000):
    """
    缓存清理：删除过期条目，如果总数超过 max_entries 则淘汰最久未命中条目
    """
    _init_cache_db()
    try:
        conn = sqlite3.connect(CACHE_DB_PATH, timeout=5)
        # 删除过期
        conn.execute("DELETE FROM scan_cache WHERE expires_at < ?", (time.time(),))
        # 检查总数
        row = conn.execute("SELECT COUNT(*) FROM scan_cache").fetchone()
        if row and row[0] > max_entries:
            excess = row[0] - max_entries
            conn.execute(
                "DELETE FROM scan_cache WHERE rowid IN ("
                "SELECT rowid FROM scan_cache ORDER BY hit_count ASC, created_at ASC LIMIT ?"
                ")", (excess,)
            )
        conn.commit()
        conn.close()
    except sqlite3.Error:
        pass


# ══════════════════════════════════════════════════════════════
#  统一退出保存
# ══════════════════════════════════════════════════════════════

def save_all(config_override: dict = None, guard_override: dict = None):
    """
    统一保存所有持久化状态
    在程序退出时调用
    """
    if config_override:
        save_config_save(config_override)
    if guard_override:
        save_guard_days(guard_override)
    # 缓存清理
    cache_cleanup()