"""
御天 数据恢复引擎

基于文件快照的数据恢复系统，为重要文件建立历史版本，支持任意版本回滚。

功能：
  1. 监控指定目录的文件变化（mtime 轮询）
  2. 文件被修改时自动创建版本快照（SHA256 + 内容备份 + 元数据）
  3. 支持恢复到任意历史版本
  4. 支持删除指定版本
  5. 自动清理过期快照（按天数）
  6. 提供快照统计信息（数量、存储占用）
  7. 索引持久化到 index.json，重启后可继续使用
"""
import os
import sys
import time
import json
import shutil
import hashlib
import threading
from datetime import datetime, timedelta
from pathlib import Path

IS_WINDOWS = sys.platform == 'win32'

# ── 默认配置 ──
# 快照存储根目录：engine/data/recovery
RECOVERY_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "data", "recovery"
)
SNAPSHOTS_DIR = os.path.join(RECOVERY_ROOT, "snapshots")
INDEX_FILE = os.path.join(RECOVERY_ROOT, "index.json")
# 设置持久化文件（watch_dirs、保留天数、存储上限）
SETTINGS_FILE = os.path.join(RECOVERY_ROOT, "settings.json")

# 监控轮询间隔 (秒)
MONITOR_INTERVAL = 5
# 默认快照保留天数
DEFAULT_RETENTION_DAYS = 30
# 单文件最大保留版本数（防止无限增长）
MAX_VERSIONS_PER_FILE = 50
# 跳过的大文件阈值 (100MB)，超过此大小不自动快照
MAX_AUTO_SNAPSHOT_SIZE = 100 * 1024 * 1024

# 跳过的扩展名（临时文件、缓存等）
SKIP_EXTENSIONS = {
    '.tmp', '.temp', '.bak', '.log', '.cache', '.lock',
    '.part', '.download', '.crdownload', '.swp', '.swo',
}
# 跳过的目录名
SKIP_DIR_NAMES = {
    '.git', '.svn', '__pycache__', 'node_modules', '$Recycle.Bin',
    'System Volume Information', 'temp', 'cache', 'AppData',
}


# ── 工具函数 ──

class _RestoreCancelled(Exception):
    """内部信号：恢复过程被用户取消（正常路径，非错误）"""


def _cancelled(cancel) -> bool:
    """判断取消令牌是否已置位（兼容 is_cancelled() / is_set() 两种约定）"""
    if cancel is None:
        return False
    if hasattr(cancel, "is_cancelled"):
        return bool(cancel.is_cancelled())
    if hasattr(cancel, "is_set"):
        return bool(cancel.is_set())
    return False


def _get_logger():
    """获取数据恢复专用日志记录器"""
    log_dir = os.path.join(RECOVERY_ROOT, "logs")
    os.makedirs(log_dir, exist_ok=True)
    import logging
    logger = logging.getLogger("data_recovery")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(
            os.path.join(log_dir, "recovery.log"), encoding="utf-8"
        )
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(fh)
    return logger


def _file_hash(path: str) -> str:
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


def _path_to_hash_key(file_path: str) -> str:
    """将文件路径转换为索引哈希键（用于唯一标识文件路径）"""
    return hashlib.sha1(file_path.encode("utf-8")).hexdigest()


def _safe_filename(file_path: str) -> str:
    """将文件路径转换为安全的目录名（用于 snapshots 子目录）"""
    return _path_to_hash_key(file_path)


# ══════════════════════════════════════════════════════════════
#  DataRecovery — 数据恢复引擎主类
# ══════════════════════════════════════════════════════════════

class DataRecovery:
    """数据恢复引擎

    基于文件快照的数据恢复系统：
    - 监控指定目录的文件变化
    - 文件被修改时自动创建版本快照
    - 支持恢复到任意历史版本
    - 自动清理过期快照
    """

    def __init__(self):
        self._running = False
        self._stop_event = threading.Event()
        self._logger = None

        # 监控目录列表
        self._watch_dirs: list[str] = []
        self._watch_lock = threading.Lock()

        # 文件状态缓存 {file_path: mtime}，用于检测变化
        self._file_states: dict[str, float] = {}
        self._state_lock = threading.Lock()

        # 索引结构：
        # {file_path: [{"version_id": str, "version_num": int,
        #                "timestamp": float, "hash": str,
        #                "size": int, "backup_path": str}]}
        self._index: dict[str, list[dict]] = {}
        self._index_lock = threading.Lock()

        # 统计信息
        self._stats = {
            "snapshots_taken": 0,
            "files_restored": 0,
            "versions_deleted": 0,
            "monitor_cycles": 0,
        }
        self._stats_lock = threading.Lock()

        # 线程引用
        self._threads: list[threading.Thread] = []

        # 用户设置（watch 目录、保留天数、存储上限），持久化到 settings.json
        self._settings = {
            "watch_dirs": [],
            "retain_days": DEFAULT_RETENTION_DAYS,
            "storage_limit": 5000,
        }
        self._settings_lock = threading.Lock()
        self._load_settings()

    # ── 属性 ──

    @property
    def running(self) -> bool:
        return self._running

    # ── 启停 ──

    def start(self, directories: list[str]):
        """启动文件快照监控

        对每个目录建立初始快照，并启动监控线程。

        Args:
            directories: 要监控的目录列表
        """
        if self._running:
            return

        # 规范化目录路径并去重
        norm_dirs = []
        for d in directories:
            abs_d = os.path.abspath(d)
            if os.path.isdir(abs_d) and abs_d not in norm_dirs:
                norm_dirs.append(abs_d)

        with self._watch_lock:
            self._watch_dirs = norm_dirs

        if not norm_dirs:
            return

        # 确保存储目录存在
        os.makedirs(SNAPSHOTS_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(INDEX_FILE), exist_ok=True)

        self._logger = _get_logger()
        self._load_index()
        self._running = True
        self._stop_event.clear()

        # 为每个目录的文件建立初始快照
        self._log("info", f"开始为 {len(norm_dirs)} 个目录建立初始快照")
        for d in norm_dirs:
            self._initial_snapshot_dir(d)

        # 启动监控线程
        t = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="DataRecovery-Monitor"
        )
        t.start()
        self._threads.append(t)

        self._log("info", f"数据恢复引擎已启动, 监控 {len(norm_dirs)} 个目录")

    def stop(self):
        """停止监控"""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        self._threads.clear()
        self._save_index()
        self._log("info", "数据恢复引擎已停止")

    # ── 快照管理 ──

    def take_snapshot(self, file_path: str) -> dict | None:
        """为单个文件创建快照

        Args:
            file_path: 文件绝对路径

        Returns:
            成功返回版本信息字典，失败返回 None
        """
        file_path = os.path.abspath(file_path)
        if not os.path.isfile(file_path):
            return None

        try:
            # 计算文件哈希和大小
            file_hash = _file_hash(file_path)
            if not file_hash:
                return None
            file_size = os.path.getsize(file_path)

            # 检查内容是否与上一个版本相同（避免重复快照）
            with self._index_lock:
                versions = self._index.get(file_path, [])
                if versions and versions[-1].get("hash") == file_hash:
                    # 内容未变化，跳过
                    return None

            # 计算版本号和存储路径
            version_num = len(versions) + 1
            timestamp = time.time()
            version_id = f"v{version_num}_{int(timestamp)}"
            dir_key = _safe_filename(file_path)
            snap_dir = os.path.join(SNAPSHOTS_DIR, dir_key)
            os.makedirs(snap_dir, exist_ok=True)

            bak_path = os.path.join(snap_dir, f"{version_id}.bak")
            meta_path = os.path.join(snap_dir, f"{version_id}.meta.json")

            # 备份文件内容（保留元数据）
            shutil.copy2(file_path, bak_path)

            # 写入元数据
            meta = {
                "version_id": version_id,
                "version_num": version_num,
                "original_path": file_path,
                "timestamp": timestamp,
                "datetime": datetime.fromtimestamp(timestamp).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "hash": file_hash,
                "size": file_size,
                "backup_path": bak_path,
            }
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, ensure_ascii=False, indent=2)

            # 更新索引
            with self._index_lock:
                if file_path not in self._index:
                    self._index[file_path] = []
                self._index[file_path].append(meta)

                # 限制单文件版本数
                if len(self._index[file_path]) > MAX_VERSIONS_PER_FILE:
                    removed = self._index[file_path].pop(0)
                    self._delete_backup_files(removed)

            with self._stats_lock:
                self._stats["snapshots_taken"] += 1

            self._save_index()
            self._log("info", f"创建快照: {file_path} -> {version_id}")
            return meta

        except Exception as e:
            self._log("error", f"创建快照失败: {file_path} -> {e}")
            return None

    def get_versions(self, file_path: str) -> list[dict]:
        """获取文件所有版本

        Args:
            file_path: 文件路径

        Returns:
            版本信息列表（按时间升序），每项包含 version_id, timestamp, hash 等
        """
        file_path = os.path.abspath(file_path)
        with self._index_lock:
            versions = list(self._index.get(file_path, []))
        return versions

    def restore_version(self, file_path: str, version_id: str, cancel=None,
                        progress_callback=None) -> bool:
        """恢复文件到指定版本

        Args:
            file_path: 文件路径
            version_id: 版本ID（如 v1_1785839159）
            cancel: 可选取消令牌（is_cancelled()/is_set()）；置位后立即
                    停止复制并清理未写完的目标文件（回滚）
            progress_callback: 可选 (percent, current) 进度回调

        Returns:
            成功返回 True，失败或取消返回 False
        """
        file_path = os.path.abspath(file_path)
        with self._index_lock:
            versions = self._index.get(file_path, [])
            target = None
            for v in versions:
                if v.get("version_id") == version_id:
                    target = v
                    break
            if not target:
                return False
            backup_path = target.get("backup_path", "")

        if not os.path.isfile(backup_path):
            self._log("error", f"备份文件不存在: {backup_path}")
            return False

        try:
            # 恢复前先为当前文件创建一个快照（如果存在）
            if os.path.isfile(file_path):
                self.take_snapshot(file_path)
                if _cancelled(cancel):
                    self._log("info", f"恢复已取消（快照阶段）: {file_path}")
                    return False

            # 恢复内容：分块复制，保证大文件可被中途取消
            self._copy_file_chunked(backup_path, file_path, cancel, progress_callback)
            if _cancelled(cancel):
                self._log("info", f"恢复已取消: {file_path} <- {version_id}")
                return False
            try:
                shutil.copystat(backup_path, file_path)
            except OSError:
                pass
            with self._stats_lock:
                self._stats["files_restored"] += 1
            self._log("info", f"文件已恢复: {file_path} <- {version_id}")
            return True
        except _RestoreCancelled:
            # 取消是正常路径：不记为失败，也不写错误日志
            self._log("info", f"恢复已取消: {file_path} <- {version_id}")
            return False
        except Exception as e:
            self._log("error", f"恢复文件失败: {file_path} <- {version_id} -> {e}")
            return False

    @staticmethod
    def _copy_file_chunked(src: str, dst: str, cancel=None,
                           progress_callback=None, chunk_size: int = 1024 * 1024):
        """分块复制文件（1MB/块），每块之间检查取消令牌

        取消时不留下半截目标文件：删除写入中的临时文件后原样退出。
        目标文件采用同目录临时文件 + 原子替换，避免破坏现有内容。
        """
        import tempfile
        total = os.path.getsize(src) or 1
        done = 0
        tmp_dir = os.path.dirname(os.path.abspath(dst)) or "."
        fh, tmp_path = tempfile.mkstemp(prefix=".yt_restore_", dir=tmp_dir)
        try:
            try:
                fin = open(src, "rb")
            except OSError:
                os.close(fh)
                raise
            with fin, os.fdopen(fh, "wb") as fout:
                while True:
                    if _cancelled(cancel):
                        raise _RestoreCancelled()
                    chunk = fin.read(chunk_size)
                    if not chunk:
                        break
                    fout.write(chunk)
                    done += len(chunk)
                    if progress_callback:
                        progress_callback(min(99, int(done / total * 100)), dst)
                fout.flush()
                os.fsync(fout.fileno())
            if _cancelled(cancel):
                raise _RestoreCancelled()
            os.replace(tmp_path, dst)
            tmp_path = None
            if progress_callback:
                progress_callback(100, dst)
        finally:
            if tmp_path and os.path.isfile(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def delete_version(self, file_path: str, version_id: str) -> bool:
        """删除指定版本

        Args:
            file_path: 文件路径
            version_id: 版本ID

        Returns:
            成功返回 True，失败返回 False
        """
        file_path = os.path.abspath(file_path)
        with self._index_lock:
            versions = self._index.get(file_path, [])
            target = None
            for v in versions:
                if v.get("version_id") == version_id:
                    target = v
                    break
            if not target:
                return False
            versions.remove(target)
            self._delete_backup_files(target)

        with self._stats_lock:
            self._stats["versions_deleted"] += 1
        self._save_index()
        self._log("info", f"删除版本: {file_path} -> {version_id}")
        return True

    def get_recovery_stats(self) -> dict:
        """获取统计信息

        Returns:
            包含快照数、存储占用、文件数等的统计字典
        """
        with self._index_lock:
            file_count = len(self._index)
            total_versions = sum(len(v) for v in self._index.values())
            total_size = 0
            for versions in self._index.values():
                for v in versions:
                    total_size += v.get("size", 0)

        with self._stats_lock:
            stats = dict(self._stats)

        with self._watch_lock:
            watch_dirs = list(self._watch_dirs)

        return {
            "watched_directories": len(watch_dirs),
            "watch_dirs": watch_dirs,
            "files_tracked": file_count,
            "total_versions": total_versions,
            "total_storage_bytes": total_size,
            "total_storage_mb": round(total_size / (1024 * 1024), 2),
            "running": self._running,
            "stats": stats,
            "config": {
                "monitor_interval": MONITOR_INTERVAL,
                "retention_days": DEFAULT_RETENTION_DAYS,
                "max_versions_per_file": MAX_VERSIONS_PER_FILE,
            },
        }

    def cleanup_old_versions(self, days: int = DEFAULT_RETENTION_DAYS) -> int:
        """清理超过指定天数的旧版本

        Args:
            days: 保留天数，超过此天数的版本将被删除

        Returns:
            清理的版本数量
        """
        cutoff = time.time() - days * 86400
        removed_count = 0

        with self._index_lock:
            # 遍历所有文件的版本
            empty_files = []
            for file_path, versions in self._index.items():
                # 至少保留最新一个版本
                if len(versions) <= 1:
                    continue
                to_remove = []
                to_keep = []
                # 最新的版本总是保留
                latest = versions[-1]
                for v in versions[:-1]:
                    if v.get("timestamp", 0) < cutoff:
                        to_remove.append(v)
                    else:
                        to_keep.append(v)
                to_keep.append(latest)
                # 删除过期版本的备份文件
                for v in to_remove:
                    self._delete_backup_files(v)
                self._index[file_path] = to_keep
                removed_count += len(to_remove)
                if not to_keep:
                    empty_files.append(file_path)

            for fp in empty_files:
                self._index.pop(fp, None)

        with self._stats_lock:
            self._stats["versions_deleted"] += removed_count

        if removed_count > 0:
            self._save_index()
            self._log("info", f"清理过期版本: {removed_count} 个 (>{days}天)")

        return removed_count

    # ── 监控线程 ──

    def _monitor_loop(self):
        """监控线程：检测文件修改（mtime 变化），自动创建快照"""
        # 初始化文件状态
        with self._state_lock:
            self._file_states = self._scan_all_dirs()

        while not self._stop_event.is_set():
            self._stop_event.wait(MONITOR_INTERVAL)
            if not self._running:
                continue

            try:
                curr_state = self._scan_all_dirs()
                with self._state_lock:
                    prev_state = dict(self._file_states)
                    self._file_states = curr_state

                # 检测修改的文件
                modified = []
                for fpath, mtime in curr_state.items():
                    prev_mtime = prev_state.get(fpath)
                    if prev_mtime is None:
                        # 新文件，首次发现也建快照
                        modified.append(fpath)
                    elif abs(prev_mtime - mtime) > 0.5:
                        modified.append(fpath)

                # 为修改的文件创建快照
                for fpath in modified:
                    # 跳过大文件
                    try:
                        size = os.path.getsize(fpath)
                        if size > MAX_AUTO_SNAPSHOT_SIZE:
                            continue
                    except OSError:
                        continue
                    self.take_snapshot(fpath)

                with self._stats_lock:
                    self._stats["monitor_cycles"] += 1

            except Exception as e:
                self._log("error", f"监控循环异常: {e}")

    def _scan_all_dirs(self) -> dict[str, float]:
        """扫描所有监控目录的文件状态

        Returns:
            {file_path: mtime} 字典
        """
        state: dict[str, float] = {}
        with self._watch_lock:
            dirs = list(self._watch_dirs)
        for d in dirs:
            if not os.path.isdir(d):
                continue
            self._scan_dir_state(d, state)
        return state

    def _scan_dir_state(self, directory: str, state: dict):
        """扫描单个目录下的文件状态，写入 state 字典"""
        try:
            for root, dirs, files in os.walk(directory):
                # 跳过指定目录
                dirs[:] = [
                    d for d in dirs
                    if d not in SKIP_DIR_NAMES and not d.startswith(".")
                ]
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in SKIP_EXTENSIONS:
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        state[fpath] = os.path.getmtime(fpath)
                    except OSError:
                        continue
        except Exception:
            pass

    def _initial_snapshot_dir(self, directory: str):
        """为目录中的所有文件建立初始快照"""
        try:
            file_count = 0
            for root, dirs, files in os.walk(directory):
                dirs[:] = [
                    d for d in dirs
                    if d not in SKIP_DIR_NAMES and not d.startswith(".")
                ]
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in SKIP_EXTENSIONS:
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        size = os.path.getsize(fpath)
                        if size > MAX_AUTO_SNAPSHOT_SIZE:
                            continue
                    except OSError:
                        continue
                    if self.take_snapshot(fpath):
                        file_count += 1
            self._log("info", f"目录初始快照完成: {directory} ({file_count} 个文件)")
        except Exception as e:
            self._log("error", f"初始快照失败: {directory} -> {e}")

    # ── 索引持久化 ──

    def _load_index(self):
        """从索引文件加载索引"""
        with self._index_lock:
            self._index = {}
            if os.path.isfile(INDEX_FILE):
                try:
                    with open(INDEX_FILE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, dict):
                        self._index = data
                except Exception as e:
                    self._log("error", f"加载索引失败: {e}")
                    self._index = {}

    def _save_index(self):
        """保存索引到文件"""
        with self._index_lock:
            data = dict(self._index)
        try:
            os.makedirs(os.path.dirname(INDEX_FILE), exist_ok=True)
            with open(INDEX_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self._log("error", f"保存索引失败: {e}")

    def _delete_backup_files(self, version: dict):
        """删除版本对应的备份文件和元数据文件（调用方需自行持锁）"""
        backup_path = version.get("backup_path", "")
        if backup_path and os.path.isfile(backup_path):
            try:
                os.remove(backup_path)
            except Exception:
                pass
        # 删除对应的 meta.json
        if backup_path:
            meta_path = backup_path.replace(".bak", ".meta.json")
            if os.path.isfile(meta_path):
                try:
                    os.remove(meta_path)
                except Exception:
                    pass

    # ── 状态 ──

    def get_status(self) -> dict:
        """获取数据恢复引擎状态"""
        with self._watch_lock:
            dirs = list(self._watch_dirs)
        with self._stats_lock:
            stats = dict(self._stats)
        with self._index_lock:
            file_count = len(self._index)
            total_versions = sum(len(v) for v in self._index.values())

        return {
            "running": self._running,
            "watch_dirs": dirs,
            "files_tracked": file_count,
            "total_versions": total_versions,
            "stats": stats,
        }

    # ── 设置与文件列表（供前端契约对齐） ──

    def get_files(self) -> list[dict]:
        """返回被监控文件列表 [{name, path}]"""
        with self._index_lock:
            paths = list(self._index.keys())
        return [
            {"name": os.path.basename(p) or p, "path": p}
            for p in sorted(paths)
        ]

    def get_settings(self) -> dict:
        """返回恢复设置（watch 目录、保留天数、存储上限）"""
        with self._settings_lock:
            return dict(self._settings)

    def add_watch_dir(self, directory: str) -> bool:
        """新增监控目录并持久化"""
        directory = directory.strip().rstrip("\\/")
        if not directory:
            return False
        with self._settings_lock:
            if directory not in self._settings["watch_dirs"]:
                self._settings["watch_dirs"].append(directory)
                self._save_settings()
            saved = list(self._settings["watch_dirs"])
        # 同步到运行时监控列表
        with self._watch_lock:
            for d in saved:
                if d not in self._watch_dirs:
                    self._watch_dirs.append(d)
        return True

    def remove_watch_dir(self, directory: str) -> bool:
        """移除监控目录并持久化"""
        with self._settings_lock:
            if directory not in self._settings["watch_dirs"]:
                return False
            self._settings["watch_dirs"].remove(directory)
            self._save_settings()
        with self._watch_lock:
            if directory in self._watch_dirs:
                self._watch_dirs.remove(directory)
        self._file_states.pop(directory, None)
        return True

    def save_settings(self, retain_days: int = 0, storage_limit: int = 0) -> dict:
        """保存保留天数与存储上限，返回更新后的设置"""
        with self._settings_lock:
            if retain_days:
                self._settings["retain_days"] = max(1, min(int(retain_days), 3650))
            if storage_limit:
                self._settings["storage_limit"] = max(128, int(storage_limit))
            self._save_settings()
            return dict(self._settings)

    def _save_settings(self) -> bool:
        try:
            with self._settings_lock:
                os.makedirs(RECOVERY_ROOT, exist_ok=True)
                with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                    json.dump(self._settings, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            self._log("error", f"保存设置失败: {e}")
            return False

    def _load_settings(self) -> bool:
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self._settings = {
                        "watch_dirs": [d for d in data.get("watch_dirs", []) if isinstance(d, str)],
                        "retain_days": int(data.get("retain_days", DEFAULT_RETENTION_DAYS)),
                        "storage_limit": int(data.get("storage_limit", 5000)),
                    }
        except Exception as e:
            self._log("error", f"加载设置失败: {e}")
        return True

    # ── 日志 ──

    def _log(self, level: str, message: str):
        if self._logger:
            getattr(self._logger, level, self._logger.info)(message)


# ══════════════════════════════════════════════════════════════
#  单例
# ══════════════════════════════════════════════════════════════

_data_recovery_instance: DataRecovery | None = None
_data_recovery_lock = threading.Lock()


def get_data_recovery() -> DataRecovery:
    """获取 DataRecovery 单例实例"""
    global _data_recovery_instance
    if _data_recovery_instance is None:
        with _data_recovery_lock:
            if _data_recovery_instance is None:
                _data_recovery_instance = DataRecovery()
    return _data_recovery_instance
