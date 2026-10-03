"""
扫描调度器 - 任务管理、进度追踪、结果聚合
支持：本地引擎 + 云端引擎 联动扫描
"""
import os
import uuid
import time
import atexit
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from engine.local_scanner import LocalScanner
from engine.cloud_scanner import CloudScanner
from engine.quarantine import QuarantineManager
from engine.report_logger import ReportLogger
from engine.signature_manager import get_signature_manager
from engine.yara_scanner import YaraScanner
from engine.history_manager import get_virus_memory
from engine.notification import threat_alert
from config import (
    CLOUD_API_KEY, YARA_RULES_DIR, MAX_WORKERS,
    SCHED_LOOP_SLEEP_SEC, foreground_active,
    AVIC_API_KEY, CLOUD_ENGINE_ORDER,
)

# 任务 TTL（秒）：完成后保留 1 小时
TASK_TTL_SECONDS = 3600
MAX_SCAN_THREADS = max(1, MAX_WORKERS)  # 最多同时扫描任务数
# 健康巡检间隔（秒）：后台巡检线程必须休眠，杜绝空转
SCHED_HEALTH_INTERVAL = 30
# 任务硬超时（秒）：超过该时长仍 running 的任务视为僵尸，强制标记失败
TASK_HARD_TIMEOUT = 6 * 3600

# 统一调度线程池：所有扫描任务提交复用，避免每实例/每任务新建线程
_SCHED_EXECUTOR = ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS, thread_name_prefix="yutian-sched")
atexit.register(lambda: _SCHED_EXECUTOR.shutdown(wait=False, cancel_futures=True))


class ScanTask:
    """单个扫描任务"""

    def __init__(self, task_id: str, scan_type: str, paths: list[str]):
        self.task_id = task_id
        self.scan_type = scan_type
        self.paths = paths
        self.status = "queued"  # queued | running | completed | cancelled | failed
        self.progress = 0
        self.current_file = ""
        self.result = None
        self.created_at = datetime.now().isoformat()
        self.completed_at = None
        self._created_ts = time.time()
        self._completed_ts = 0.0
        self.error = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "scan_type": self.scan_type,
            "status": self.status,
            "progress": self.progress,
            "current_file": self.current_file,
            "result": self.result,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "error": self.error
        }


class Scheduler:
    """扫描任务调度器"""

    def __init__(self):
        self.sig_mgr = get_signature_manager()  # 全局共享单连接 + 内存索引
        self.yara = YaraScanner(YARA_RULES_DIR)
        self.scanner = LocalScanner(self.sig_mgr, self.yara)
        self.cloud = CloudScanner(
            api_key=CLOUD_API_KEY,
            avic_key=AVIC_API_KEY,
            engine_order=CLOUD_ENGINE_ORDER,
        )
        self.quarantine = QuarantineManager()
        self.logger = ReportLogger()
        self.tasks: dict[str, ScanTask] = {}
        self._progress_callbacks: dict[str, callable] = {}
        self._lock = threading.Lock()
        self._active_count = 0
        self._priority = "normal"   # normal | low（游戏模式/前台繁忙时降权）
        self._health_started = False
        self._health_lock = threading.Lock()
        self._start_health_loop()

    def _start_health_loop(self):
        """启动后台健康巡检（唯一线程，带休眠防空转）：
        1. 周期性清理过期任务
        2. 强杀超时的僵尸 running 任务（防线程/任务堆积）
        """
        with self._health_lock:
            if self._health_started:
                return
            self._health_started = True

        def _loop():
            while True:
                try:
                    self._cleanup_expired_tasks()
                    self._force_expire_stuck_tasks()
                except Exception:
                    pass
                time.sleep(SCHED_HEALTH_INTERVAL)  # 必须休眠，杜绝空转

        threading.Thread(target=_loop, daemon=True, name="yutian-sched-health").start()

    def _force_expire_stuck_tasks(self):
        """超过硬超时仍处于 running 的任务 → 标记 failed（防僵尸任务堆积）"""
        now = time.time()
        with self._lock:
            for t in self.tasks.values():
                if t.status == "running" and now - t._created_ts > TASK_HARD_TIMEOUT:
                    t.status = "failed"
                    t.error = "扫描任务超时，已强制结束"
                    t._completed_ts = now

    def set_priority(self, priority: str = "normal"):
        """设置扫描优先级：low 时任务提交前休眠让出 CPU（供游戏模式/前台降权调用）"""
        self._priority = priority if priority in ("normal", "low") else "normal"

    def _cleanup_expired_tasks(self):
        """清理超过 TTL 的已完成/已取消任务"""
        now = time.time()
        expired = []
        with self._lock:
            for tid, t in list(self.tasks.items()):
                if t.status in ("completed", "cancelled", "failed") and t._completed_ts > 0:
                    if now - t._completed_ts > TASK_TTL_SECONDS:
                        expired.append(tid)
                elif t.status in ("completed", "cancelled", "failed") and t._completed_ts == 0:
                    t._completed_ts = now  # 修复旧任务没有时间戳的情况
            for tid in expired:
                del self.tasks[tid]
        return len(expired)

    def create_task(self, scan_type: str, paths: list[str] = None) -> ScanTask:
        """创建扫描任务"""
        self._cleanup_expired_tasks()
        task_id = str(uuid.uuid4())[:8]

        if scan_type == "quick":
            paths = self._get_quick_scan_paths()
        elif scan_type == "full":
            paths = self._get_full_scan_paths()
        elif not paths:
            paths = ["C:\\"]

        task = ScanTask(task_id, scan_type, paths)
        with self._lock:
            # 限制任务总数不超过500
            if len(self.tasks) >= 500:
                oldest = min(
                    (t for t in self.tasks.values() if t.status in ("completed", "cancelled", "failed")),
                    key=lambda t: t._completed_ts, default=None
                )
                if oldest:
                    del self.tasks[oldest.task_id]
            self.tasks[task_id] = task
        return task

    def run_task(self, task_id: str, progress_callback=None):
        """执行扫描任务（线程池控制并发）"""
        task = self.tasks.get(task_id)
        if not task or task.status == "running":
            return

        with self._lock:
            if self._active_count >= MAX_SCAN_THREADS:
                return  # 达到最大并发数，忽略
            self._active_count += 1

        task.status = "running"
        self.logger.log_scan_start(task_id, task.scan_type)

        def on_progress(progress: int, current_file: str):
            task.progress = progress
            task.current_file = current_file
            if progress_callback:
                progress_callback(task_id, progress, current_file)

        def _do_scan():
            try:
                # 前台降权（优先级低 或 前台有其他程序）
                if self._priority == "low" or foreground_active():
                    time.sleep(SCHED_LOOP_SLEEP_SEC)

                # 1. 本地引擎扫描
                result = self.scanner.scan_paths(
                    task.paths, task.scan_type,
                    progress_callback=on_progress
                )

                # 2. 云端引擎联动
                cloud_hits = []
                cloud_checked = 0
                if self.cloud.available and result.get("threats_found", 0) == 0:
                    cloud_checked = self._cloud_verify_scan(result, cloud_hits)

                # 3. 合并结果
                all_threats = result.get("threats", []) + cloud_hits

                # 4. 隔离检出威胁 + 记录到病毒记忆库
                quarantined = 0
                virus_memory = get_virus_memory()
                for threat in all_threats:
                    if threat.get("action") == "quarantine" and threat.get("path"):
                        qr = self.quarantine.quarantine_file(
                            threat["path"],
                            threat_name=threat.get("signature", "Unknown"),
                            threat_level=threat.get("threat_level", "medium"),
                            file_hash=threat.get("sha256", ""),
                            hash_type="sha256"
                        )
                        if qr.get("success"):
                            quarantined += 1
                            threat["quarantined"] = True
                    self.logger.log_threat(task_id, threat)
                    # 记录病毒类型到记忆库
                    virus_memory.add_threat(threat, task_id=task_id)

                result["threats"] = all_threats
                result["threats_found"] = len(all_threats)
                result["quarantined"] = quarantined
                result["cloud_checked"] = cloud_checked
                result["cloud_hits"] = len(cloud_hits)
                result["cloud_available"] = self.cloud.available
                # v2.0: 附加扫描引擎性能统计
                try:
                    result["perf_stats"] = self.scanner.get_perf_stats()
                except Exception:
                    result["perf_stats"] = {}
                task.result = result
                task.status = "completed"
                task.progress = 100
                self.logger.log_scan_complete(task_id, result)

                # 5. 系统弹窗通知
                if all_threats:
                    threat_alert(all_threats, quarantined)

            except Exception as e:
                task.status = "failed"
                task.error = str(e)

            task.completed_at = datetime.now().isoformat()
            task._completed_ts = time.time()
            with self._lock:
                self._active_count = max(0, self._active_count - 1)

        _SCHED_EXECUTOR.submit(_do_scan)

    def _cloud_verify_scan(self, result: dict, cloud_hits: list) -> int:
        """对本地扫描结果中的文件做云端补充查询（优化：批量查询）
        result 来自 LocalScanner.scan_paths()，其中：
          - files_scanned: int（已扫描文件数）
          - threats: list（检出威胁列表，每个威胁含 path）
        """
        threats = result.get("threats", [])
        if not threats:
            return 0

        # 从威胁列表提取文件路径，去重，计算哈希（优先复用扫描期已算好的 sha256）
        seen = set()
        hash_to_path = {}
        scanned_hashes = result.get("_scanned_hashes", {})
        for t in threats:
            fpath = t.get("path", "")
            if fpath and fpath not in seen and os.path.isfile(fpath):
                seen.add(fpath)
                sha256 = scanned_hashes.get(fpath) or self._sha256_file(fpath)
                if sha256:
                    hash_to_path[sha256] = fpath

        # 也取已扫描文件中 non-threat 的样本做补充查询
        for fpath in result.get("_scanned_files", []):
            if fpath and fpath not in seen and os.path.isfile(fpath):
                seen.add(fpath)
                sha256 = scanned_hashes.get(fpath) or self._sha256_file(fpath)
                if sha256:
                    hash_to_path[sha256] = fpath

        if not hash_to_path:
            return 0

        # 批量查询云端（一次请求查多个，大幅提升性能）
        hashes = list(hash_to_path.keys())[:50]  # 最多查50个
        try:
            batch_results = self.cloud.lookup_hashes_batch(hashes)
        except Exception:
            # 批量查询失败时回退到逐个查询
            batch_results = {}
            for h in hashes:
                try:
                    result = self.cloud.lookup_hash(sha256=h)
                    batch_results[h] = result
                except Exception:
                    batch_results[h] = None

        checked = 0
        for h, threat in batch_results.items():
            if threat:
                threat["path"] = hash_to_path.get(h, "")
                threat["engine"] = threat.get("engine", "cloud_hash")
                cloud_hits.append(threat)
            checked += 1

        return checked

    def _sha256_file(self, path: str) -> str:
        try:
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha.update(chunk)
            return sha.hexdigest()
        except Exception:
            return ""

    def cancel_task(self, task_id: str) -> bool:
        """取消扫描任务"""
        task = self.tasks.get(task_id)
        if not task or task.status not in ("queued", "running"):
            return False
        self.scanner.cancel()
        task.status = "cancelled"
        task.completed_at = datetime.now().isoformat()
        task._completed_ts = time.time()
        return True

    def get_task(self, task_id: str) -> ScanTask | None:
        return self.tasks.get(task_id)

    def get_all_tasks(self) -> list[dict]:
        with self._lock:
            return [t.to_dict() for t in self.tasks.values()]

    # ---------- 扫描路径 ----------

    def _get_quick_scan_paths(self) -> list[str]:
        """快速扫描 - 系统关键目录 + 当前目录"""
        paths = []
        cwd = os.getcwd()
        if os.path.isdir(cwd):
            paths.append(cwd)

        system_root = os.environ.get("SystemRoot", "C:\\Windows")
        system32 = os.path.join(system_root, "System32")
        if os.path.isdir(system32):
            paths.append(system32)

        for pf in ["C:\\Program Files", "C:\\Program Files (x86)"]:
            if os.path.isdir(pf):
                paths.append(pf)

        userprofile = os.environ.get("USERPROFILE", "")
        if userprofile:
            downloads = os.path.join(userprofile, "Downloads")
            if os.path.isdir(downloads):
                paths.append(downloads)
            desktop = os.path.join(userprofile, "Desktop")
            if os.path.isdir(desktop):
                paths.append(desktop)

        return paths if paths else ["."]

    def _get_full_scan_paths(self) -> list[str]:
        """全盘扫描 - 所有磁盘分区 + 当前目录"""
        import string
        paths = []
        cwd = os.getcwd()
        if os.path.isdir(cwd):
            paths.append(cwd)
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive) and drive not in paths:
                paths.append(drive)
        return paths if paths else ["."]


