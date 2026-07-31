"""
扫描调度器 - 任务管理、进度追踪、结果聚合
支持：本地引擎 + 云端引擎 联动扫描
"""
import os
import uuid
import time
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from engine.local_scanner import LocalScanner
from engine.cloud_scanner import CloudScanner
from engine.quarantine import QuarantineManager
from engine.report_logger import ReportLogger
from engine.signature_manager import SignatureManager
from engine.yara_scanner import YaraScanner
from engine.history_manager import get_virus_memory
from config import CLOUD_API_KEY, YARA_RULES_DIR, MAX_WORKERS

# 任务 TTL（秒）：完成后保留 1 小时
TASK_TTL_SECONDS = 3600
MAX_SCAN_THREADS = max(1, MAX_WORKERS)  # 最多同时扫描线程数


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
        self.sig_mgr = SignatureManager()
        self.yara = YaraScanner(YARA_RULES_DIR)
        self.scanner = LocalScanner(self.sig_mgr, self.yara)
        self.cloud = CloudScanner(api_key=CLOUD_API_KEY)
        self.quarantine = QuarantineManager()
        self.logger = ReportLogger()
        self.tasks: dict[str, ScanTask] = {}
        self._progress_callbacks: dict[str, callable] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=MAX_SCAN_THREADS)
        self._active_count = 0

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
                task.result = result
                task.status = "completed"
                task.progress = 100
                self.logger.log_scan_complete(task_id, result)

            except Exception as e:
                task.status = "failed"
                task.error = str(e)

            task.completed_at = datetime.now().isoformat()
            task._completed_ts = time.time()
            with self._lock:
                self._active_count = max(0, self._active_count - 1)

        self._executor.submit(_do_scan)

    def _cloud_verify_scan(self, result: dict, cloud_hits: list) -> int:
        """对本地扫描结果中的文件做云端补充查询
        result 来自 LocalScanner.scan_paths()，其中：
          - files_scanned: int（已扫描文件数）
          - threats: list（检出威胁列表，每个威胁含 path）
        """
        checked = 0
        threats = result.get("threats", [])
        if not threats:
            return 0

        # 从威胁列表中提取文件路径，去重
        seen = set()
        file_paths = []
        for t in threats:
            fpath = t.get("path", "")
            if fpath and fpath not in seen:
                seen.add(fpath)
                file_paths.append(fpath)

        # 此外，也取已扫描文件中 non-threat 的样本做补充查询
        # 从本地扫描器传入的已扫描文件列表
        scanned_files = result.get("_scanned_files", [])
        for fpath in scanned_files:
            if fpath and fpath not in seen and os.path.isfile(fpath):
                seen.add(fpath)
                file_paths.append(fpath)

        for fpath in file_paths[:30]:  # 最多查30个文件
            try:
                sha256 = self._sha256_file(fpath)
                if sha256:
                    threat = self.cloud.lookup_hash(sha256=sha256)
                    if threat:
                        threat["path"] = fpath
                        threat["engine"] = "cloud_hash"
                        cloud_hits.append(threat)
                    checked += 1
            except Exception:
                continue
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


