"""
御天卫士 - 垃圾清理引擎
扫描并清理系统垃圾文件（仅限白名单根目录，保守策略）：
- 系统临时文件（仅删除修改时间 >24h 的文件）
- 浏览器缓存（Chrome / Edge / Firefox）
- 缩略图缓存
- 回收站
- 崩溃转储
- Windows 更新缓存
"""
import os
import sys
import json
import time
import ctypes
import threading
import uuid
from datetime import datetime

# ── 数据目录（沿用 engine/data 约定，兼容打包模式） ──
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_HISTORY_FILE = os.path.join(_DATA_DIR, "cleanup_history.json")

# 仅删除修改时间早于该阈值的文件（秒），避免误删使用中的文件
MIN_FILE_AGE_SECONDS = 24 * 3600

# 前端展示时每个分类最多携带的明细条目数
MAX_ITEMS_PER_CATEGORY = 200


def _get_env_path(name: str) -> str:
    """读取环境变量路径，无效时返回空串"""
    return os.environ.get(name, "").strip().strip('"')


def _win_dir() -> str:
    """Windows 目录（默认 C:\\Windows）"""
    return os.environ.get("SystemRoot", "C:\\Windows")


# ── 分类定义：白名单根目录 + 文件匹配规则 ──
def _temp_roots():
    roots = []
    user_temp = _get_env_path("TEMP")
    if user_temp and os.path.isdir(user_temp):
        roots.append(user_temp)
    sys_temp = os.path.join(_win_dir(), "Temp")
    if os.path.isdir(sys_temp):
        roots.append(sys_temp)
    return roots


def _browser_cache_roots():
    """定位 Chrome/Edge/Firefox 缓存目录"""
    roots = []
    local = _get_env_path("LOCALAPPDATA")
    if not local:
        return roots
    browsers = [
        ("Google", "Chrome", "User Data"),
        ("Microsoft", "Edge", "User Data"),
    ]
    for vendor, name, sub in browsers:
        base = os.path.join(local, vendor, name, sub)
        if not os.path.isdir(base):
            continue
        # 默认配置目录 + 所有 Profile 目录下的 Cache / Code Cache
        for entry in os.listdir(base):
            p = os.path.join(base, entry)
            if os.path.isdir(p):
                for cache_name in ("Cache", "Code Cache", "CachedData"):
                    c = os.path.join(p, cache_name)
                    if os.path.isdir(c):
                        roots.append(c)
    # Firefox
    ff = os.path.join(local, "Mozilla", "Firefox", "Profiles")
    if os.path.isdir(ff):
        for entry in os.listdir(ff):
            p = os.path.join(ff, entry)
            cache2 = os.path.join(p, "cache2")
            if os.path.isdir(cache2):
                roots.append(cache2)
    return roots


def _thumbnail_roots():
    """缩略图缓存目录"""
    roots = []
    local = _get_env_path("LOCALAPPDATA")
    if local:
        p = os.path.join(local, "Microsoft", "Windows", "Explorer")
        if os.path.isdir(p):
            roots.append(p)
    return roots


def _crash_dump_roots():
    roots = []
    minidump = os.path.join(_win_dir(), "Minidump")
    if os.path.isdir(minidump):
        roots.append(minidump)
    local = _get_env_path("LOCALAPPDATA")
    if local:
        p = os.path.join(local, "CrashDumps")
        if os.path.isdir(p):
            roots.append(p)
    return roots


def _update_cache_roots():
    p = os.path.join(_win_dir(), "SoftwareDistribution", "Download")
    return [p] if os.path.isdir(p) else []


CATEGORY_DEFS = [
    {
        "id": "temp_files",
        "name": "系统临时文件",
        "desc": "用户与系统临时目录中超过 24 小时未使用的文件",
        "roots": _temp_roots,
        "file_patterns": None,          # 全部文件
    },
    {
        "id": "browser_cache",
        "name": "浏览器缓存",
        "desc": "Chrome / Edge / Firefox 网页缓存文件",
        "roots": _browser_cache_roots,
        "file_patterns": None,
    },
    {
        "id": "thumbnail_cache",
        "name": "缩略图缓存",
        "desc": "资源管理器缩略图数据库（thumbcache_*.db）",
        "roots": _thumbnail_roots,
        "file_patterns": lambda fn: fn.lower().startswith("thumbcache_") and fn.lower().endswith(".db"),
    },
    {
        "id": "recycle_bin",
        "name": "回收站",
        "desc": "清空回收站中的已删除文件",
        "roots": None,
        "file_patterns": None,
    },
    {
        "id": "crash_dumps",
        "name": "崩溃转储",
        "desc": "系统与应用崩溃生成的 .dmp / .dmp.* 转储文件",
        "roots": _crash_dump_roots,
        "file_patterns": lambda fn: fn.lower().endswith(".dmp") or ".dmp." in fn.lower(),
    },
    {
        "id": "update_cache",
        "name": "Windows 更新缓存",
        "desc": "Windows 更新下载缓存（占用的文件将自动跳过）",
        "roots": _update_cache_roots,
        "file_patterns": None,
    },
]


def format_size(num: float) -> str:
    """字节数转可读字符串"""
    try:
        num = float(num or 0)
    except (TypeError, ValueError):
        num = 0.0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024
    return "0 B"


class CleanTask:
    """单个清理扫描任务（模型与 ScanTask 对齐）"""

    def __init__(self, task_id: str):
        self.task_id = task_id
        self.status = "queued"   # queued | running | completed | failed
        self.progress = 0
        self.current_item = ""
        self.result = None       # {"categories": [...], "total_bytes": n, "total_files": n}
        self.error = None
        self.created_at = datetime.now().isoformat()
        self.completed_at = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "progress": self.progress,
            "current_item": self.current_item,
            "result": self.result,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "error": self.error,
        }


class JunkCleaner:
    """垃圾清理引擎"""

    def __init__(self):
        self._tasks = {}
        self._lock = threading.Lock()
        self._history = None
        os.makedirs(_DATA_DIR, exist_ok=True)

    # ── 任务管理 ──

    def start_scan(self, progress_callback=None) -> CleanTask:
        """启动异步清理扫描任务"""
        task_id = "clean_" + uuid.uuid4().hex[:8]
        task = CleanTask(task_id)
        with self._lock:
            self._tasks[task_id] = task
        threading.Thread(
            target=self._scan_worker, args=(task, progress_callback),
            daemon=True,
        ).start()
        return task

    def get_task(self, task_id: str):
        return self._tasks.get(task_id)

    # ── 扫描 ──

    def _scan_worker(self, task: CleanTask, progress_callback=None):
        """后台扫描线程"""
        task.status = "running"
        try:
            def cb(progress: int, item: str):
                task.progress = progress
                task.current_item = item
                if progress_callback:
                    progress_callback(task.task_id, progress, item)

            categories = self._scan_all(cb)
            task.result = {
                "categories": categories,
                "total_bytes": sum(c["total_bytes"] for c in categories),
                "total_files": sum(c["file_count"] for c in categories),
            }
            task.status = "completed"
            task.completed_at = datetime.now().isoformat()
        except Exception as e:  # 兜底，保证任务状态可查询
            task.status = "failed"
            task.error = str(e)
            task.completed_at = datetime.now().isoformat()

    def _scan_all(self, progress_callback) -> list:
        """按分类依次扫描，进度按分类数量均分"""
        defs = CATEGORY_DEFS
        results = []
        total = len(defs)
        for idx, cat in enumerate(defs):
            if progress_callback:
                progress_callback(int(idx / total * 100), cat["name"])
            results.append(self._scan_category(cat))
            if progress_callback:
                progress_callback(int((idx + 1) / total * 100), "")
        return results

    def _scan_category(self, cat: dict) -> dict:
        """扫描单个分类，返回统计与明细"""
        cat_id = cat["id"]
        if cat_id == "recycle_bin":
            # 回收站无法直接统计大小，仅标记为可清空
            return {
                "id": cat_id,
                "name": cat["name"],
                "desc": cat["desc"],
                "file_count": 1,
                "total_bytes": 0,
                "size_text": "可清空",
                "items": [],
                "skipped": 0,
            }

        roots = cat["roots"]() if callable(cat["roots"]) else (cat["roots"] or [])
        pattern = cat.get("file_patterns")
        total_bytes = 0
        file_count = 0
        skipped = 0
        items = []
        cutoff = time.time() - MIN_FILE_AGE_SECONDS

        for root in roots:
            for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda _e: None):
                for fn in filenames:
                    if pattern and not pattern(fn):
                        continue
                    full = os.path.join(dirpath, fn)
                    try:
                        st = os.stat(full)
                    except OSError:
                        continue
                    if st.st_mtime > cutoff:
                        continue
                    total_bytes += st.st_size
                    file_count += 1
                    if len(items) < MAX_ITEMS_PER_CATEGORY:
                        items.append({
                            "path": full,
                            "size": st.st_size,
                            "size_text": format_size(st.st_size),
                        })

        return {
            "id": cat_id,
            "name": cat["name"],
            "desc": cat["desc"],
            "file_count": file_count,
            "total_bytes": total_bytes,
            "size_text": format_size(total_bytes),
            "items": items,
            "skipped": skipped,
        }

    # ── 清理执行 ──

    def execute_clean(self, category_ids: list) -> dict:
        """执行清理：仅允许清理白名单分类，返回释放统计"""
        if not category_ids:
            return {"success": False, "error": "未选择任何清理项"}

        allowed = {c["id"] for c in CATEGORY_DEFS}
        for cid in category_ids:
            if cid not in allowed:
                return {"success": False, "error": f"未知清理分类: {cid}"}

        freed_bytes = 0
        cleaned_files = 0
        failed = []
        cat_records = []

        for cid in category_ids:
            cat = next(c for c in CATEGORY_DEFS if c["id"] == cid)
            if cid == "recycle_bin":
                ok, err = self._empty_recycle_bin()
                if ok:
                    cat_records.append({"id": cid, "name": cat["name"],
                                        "freed_bytes": 0, "cleaned_files": 1})
                else:
                    failed.append({"category": cid, "error": err or "回收站清空失败"})
                continue

            roots = cat["roots"]() if callable(cat["roots"]) else (cat["roots"] or [])
            pattern = cat.get("file_patterns")
            cutoff = time.time() - MIN_FILE_AGE_SECONDS
            cat_freed = 0
            cat_files = 0

            for root in roots:
                root_real = os.path.realpath(root)
                for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda _e: None):
                    for fn in filenames:
                        if pattern and not pattern(fn):
                            continue
                        full = os.path.join(dirpath, fn)
                        # 路径前缀校验：必须位于白名单根目录内（防路径穿越）
                        if not self._is_under(full, root_real):
                            failed.append({"category": cid, "error": f"拒绝清理白名单外路径: {full}"})
                            continue
                        try:
                            st = os.stat(full)
                            if st.st_mtime > cutoff:
                                continue
                        except OSError:
                            continue
                        try:
                            size = os.path.getsize(full)
                            os.remove(full)
                            cat_freed += size
                            cat_files += 1
                        except OSError as e:
                            # 占用/权限不足：跳过并记录
                            failed.append({"category": cid, "path": full, "error": str(e)})

            freed_bytes += cat_freed
            cleaned_files += cat_files
            cat_records.append({"id": cid, "name": cat["name"],
                                "freed_bytes": cat_freed, "cleaned_files": cat_files})

        record = {
            "timestamp": datetime.now().isoformat(),
            "categories": cat_records,
            "total_freed": freed_bytes,
            "freed_text": format_size(freed_bytes),
            "cleaned_files": cleaned_files,
            "failed_count": len(failed),
        }
        self._append_history(record)

        return {
            "success": True,
            "freed_bytes": freed_bytes,
            "freed_text": format_size(freed_bytes),
            "cleaned_files": cleaned_files,
            "categories": cat_records,
            "failed": failed[:50],
            "record": record,
        }

    @staticmethod
    def _is_under(path: str, root: str) -> bool:
        """校验路径是否位于白名单根目录内"""
        try:
            real = os.path.realpath(path)
            return real.startswith(root + os.sep)
        except OSError:
            return False

    @staticmethod
    def _empty_recycle_bin() -> tuple:
        """通过 shell API 清空回收站"""
        try:
            shell32 = ctypes.windll.shell32
            # SHERB_NOCONFIRMATION=0x1 | SHERB_NOPROGRESSUI=0x2 | SHERB_NOSOUND=0x4
            hr = shell32.SHEmptyRecycleBinW(None, None, 0x1 | 0x2 | 0x4)
            if hr == 0:
                return True, None
            return False, f"shell 返回错误码 {hr}"
        except Exception as e:
            return False, str(e)

    # ── 历史记录 ──

    def _append_history(self, record: dict):
        """追加清理历史（保留最近 50 条）"""
        try:
            records = self.get_history(100)
            records.insert(0, record)
            with open(_HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(records[:50], f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def get_history(self, limit: int = 20) -> list:
        """读取清理历史记录（倒序，最新在前）"""
        if not os.path.isfile(_HISTORY_FILE):
            return []
        try:
            with open(_HISTORY_FILE, "r", encoding="utf-8") as f:
                records = json.load(f)
            return records[:limit]
        except (OSError, json.JSONDecodeError):
            return []
