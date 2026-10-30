"""
鉴察引擎 - 文件遍历、哈希计算、启发式分析、特征库匹配（鉴辨奸邪，明察秋毫）
v2.1 - P0 优化版
  1. 流式遍历 + 窗口化提交：不再一次性生成全量文件列表，内存有界
  2. 两档读取：>200MB 只读首 4MB 头 + 全量流式哈希；>2GB 直接跳过
  3. 云查前置：哈希计算后先云查询，命中即短路，再走本地特征/YARA
  4. ML 引擎融合判定
  5. 缓存上限取自 config（LRU + TTL 自动淘汰）
  6. 共享线程池 + 前台降权（避免无限建线程 / 前台卡顿）
  7. 全部文件操作用 with open()，杜绝句柄泄漏
"""
import os
import re
import math
import time
import hashlib
import zipfile
import tempfile
import shutil
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from config import (
    SCAN_EXTENSIONS, EXCLUDED_DIRS, MAX_FILE_SIZE, MAX_WORKERS, SINGLE_FILE_TIMEOUT,
    LARGE_FILE_THRESH, LARGE_FILE_HEADER_READ, LARGE_FILE_ABS_CAP,
    SCAN_STREAM_WINDOW, SCAN_CACHE_MAX, SCAN_CACHE_TTL,
    BLACKLIST_FILE_NAMES, BLACKLIST_DIR_PARTS,
    IDLE_WORKERS_FOREGROUND, SCHED_LOOP_SLEEP_SEC, CLOUD_QUERY_MIN_INTERVAL,
    foreground_active,
)
try:
    from config import HUORONG_CONTENT_SIGS_ENABLED
except Exception:                      # 配置缺失时保持启用，由引擎自身兜底
    HUORONG_CONTENT_SIGS_ENABLED = True
from engine.signature_manager import SignatureManager
from engine.yara_scanner import YaraScanner
from engine.dex_parser import DexParser
from engine.heuristic_engine import get_heuristic_engine

# 递归解压扫描的安全上限（防 zip bomb）
_MAX_ARCHIVE_DEPTH = 4
_MAX_ARCHIVE_ENTRIES = 200
_MAX_ENTRY_SIZE = 50 * 1024 * 1024  # 单条目解压后上限 50MB
_BUFFER_LIMIT = 32 * 1024 * 1024  # 单次读取缓冲上限 32MB（覆盖绝大多数文件）
_ARCHIVE_EXTS = {".zip", ".apk", ".jar", ".rar"}
_ARCHIVE_MAGIC = {b"PK\x03\x04": "zip", b"PK\x05\x06": "zip", b"Rar!\x1a\x07": "rar"}

# 扫描结果缓存（SHA256 → 结果，LRU + TTL，上限取自 config）
_SCAN_CACHE_MAX = SCAN_CACHE_MAX
_SCAN_CACHE_TTL = SCAN_CACHE_TTL

# 已扫描文件路径保留上限（供上层聚合，避免长期持有全量列表）
_MAX_RETAINED_PATHS = 2000

# 共享线程池：所有扫描任务复用，避免每次扫描新建线程池
_SHARED_POOL = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="yutian-scan")

# 云查节流（模块级，全实例共享）
_cloud_throttle_lock = threading.Lock()
_cloud_last_query = 0.0


class LocalScanner:
    """鉴察引擎（v2.1 P0 优化版）"""

    def __init__(self, signature_manager: SignatureManager, yara_scanner: YaraScanner = None,
                 cloud_scanner=None, content_sig=None):
        self.sig_mgr = signature_manager
        self.yara = yara_scanner
        self.cloud = cloud_scanner          # 云查前置引擎（可选）
        # 火绒内容特征串引擎（方案 B：不经 YARA 的字符串匹配，可选、懒加载单例）
        self.content_sig = content_sig
        if self.content_sig is None and HUORONG_CONTENT_SIGS_ENABLED:
            try:
                from engine.huorong_intel import get_content_sig_engine
                self.content_sig = get_content_sig_engine()
            except Exception:
                self.content_sig = None
        self.heuristic_engine = get_heuristic_engine()  # 独立启发式引擎（逻辑已抽取）
        self._cancel_flag = threading.Event()  # 全局取消标志（兼容旧接口）
        self._active_cancel: threading.Event | None = None  # 当前活跃扫描的本地取消标志
        self._cache: OrderedDict[str, tuple[float, list]] = OrderedDict()  # sha256 → (timestamp, threats)
        self._cache_lock = threading.Lock()
        # 性能统计
        self.perf_stats = {
            "hash_time": 0.0, "yara_time": 0.0, "heuristic_time": 0.0,
            "ml_time": 0.0, "archive_time": 0.0, "signature_time": 0.0,
            "content_sig_time": 0.0,
            "cache_hits": 0, "cache_misses": 0, "total_scans": 0,
            "total_bytes_read": 0, "total_scan_time": 0.0,
            "threats_found": 0,  # 累计检出威胁数（跨任务）
        }
        self._stats_lock = threading.Lock()

    def cancel(self):
        """取消当前活跃的扫描任务"""
        if self._active_cancel:
            self._active_cancel.set()
        self._cancel_flag.set()

    def _is_cancelled(self) -> bool:
        """检查是否被取消（本地标志优先）"""
        if self._active_cancel and self._active_cancel.is_set():
            return True
        return self._cancel_flag.is_set()

    # ════════════════════════════════════════════════════════════
    # 扫描入口（流式 + 窗口化 + 前台降权）
    # ════════════════════════════════════════════════════════════

    def scan_paths(self, paths: list[str], scan_type: str = "quick",
                   progress_callback=None) -> dict:
        """
        扫描指定路径列表（流式遍历，不再一次性生成全量文件列表）
        progress_callback(task_id, progress_percent, current_file) -> None
        返回扫描报告
        """
        # 为本次扫描创建独立的取消标志，避免多个任务互相干扰
        local_cancel = threading.Event()
        self._active_cancel = local_cancel
        self._cancel_flag.clear()

        threats = []
        files_scanned = 0
        total_bytes = 0
        discovered = 0
        scanned_files = []  # 仅保留最近 _MAX_RETAINED_PATHS 个（供上层聚合）

        futures: dict = {}  # future -> file_path（有界窗口）
        window = SCAN_STREAM_WINDOW * max(1, MAX_WORKERS // 2)
        gen = self._iter_files(paths, scan_type, progress_callback)
        scan_hashes: dict[str, str] = {}  # path → sha256（供上层云端复核复用）

        def _drain(done_futs):
            nonlocal files_scanned, total_bytes
            for f in done_futs:
                fp = futures.pop(f, None)
                if fp is None:
                    continue
                try:
                    res = f.result(timeout=SINGLE_FILE_TIMEOUT)
                except Exception:
                    res = []
                threats.extend(res)
                files_scanned += 1
                if res:
                    self._add_perf("threats_found", len(res))
                try:
                    total_bytes += os.path.getsize(fp)
                except Exception:
                    pass
                if len(scanned_files) < _MAX_RETAINED_PATHS:
                    scanned_files.append(fp)
                if progress_callback and discovered > 0:
                    pct = min(99, int(files_scanned / max(1, discovered) * 100))
                    progress_callback(pct, fp)

        try:
            for fp in gen:
                if self._is_cancelled():
                    break
                discovered += 1
                if len(futures) < window:
                    futures[_SHARED_POOL.submit(self._scan_single_file, fp, scan_hashes)] = fp
                    continue
                # 窗口已满：等待至少一个完成，回收内存
                # 分片等待（0.2s）而不是阻塞到某个任务完成：单文件最长可能
                # 跑 SINGLE_FILE_TIMEOUT(60s)，整体阻塞会让取消请求最多延迟
                # 60s 才被主循环看到（用户看到"取消无效"）。
                done = set()
                while True:
                    if self._is_cancelled():
                        break
                    done, _ = wait(futures, timeout=0.2, return_when=FIRST_COMPLETED)
                    if done:
                        break
                if self._is_cancelled():
                    break
                _drain(done)
                # 前台降权：有其他程序在前台时降低扫描对 CPU 的占用
                if foreground_active():
                    time.sleep(SCHED_LOOP_SLEEP_SEC)

            # 收尾：处理剩余全部 future
            if futures and not self._is_cancelled():
                for f in as_completed(futures):
                    if self._is_cancelled():
                        break
                    _drain({f})
            # 取消时不再逐个等待剩余 future：每个 f.result() 最长等
            # SINGLE_FILE_TIMEOUT(60s)，窗口内可能积压数百个，会让取消后的
            # 扫描线程被占住几分钟，进而占满调度线程池、后续扫描排不上队。
            # 尚未开始执行的任务直接取消（释放线程池额度）；已开始的只能在
            # 共享池里自行结束（正在读文件无法安全中断），但这里不再阻塞等待。
            for f in list(futures):
                if self._is_cancelled():
                    f.cancel()
                    continue
                if not f.done():
                    continue
                try:
                    f.result(timeout=0)
                except Exception:
                    pass
        finally:
            self._active_cancel = None

        return {
            "scan_type": scan_type,
            "files_scanned": files_scanned,
            "total_files": discovered,
            "total_bytes": total_bytes,
            "threats_found": len(threats),
            "threats": threats,
            "_scanned_files": scanned_files,
            "_scanned_hashes": scan_hashes,
            "cancelled": self._is_cancelled()
        }

    # ── 流式文件遍历（迭代式 DFS，无递归深度限制）──────────

    def _iter_files(self, paths: list[str], scan_type: str, progress_callback=None):
        """迭代式遍历文件（生成器），内存有界"""
        stack = []
        for p in paths:
            if os.path.isfile(p):
                yield p
            elif os.path.isdir(p):
                stack.append(p)

        collected = 0
        while stack:
            if self._is_cancelled():
                return
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    for entry in it:
                        if self._is_cancelled():
                            return
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                dir_name = os.path.basename(entry.path)
                                if self._is_excluded_dir(entry.path, dir_name, scan_type):
                                    continue
                                stack.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                if self._should_scan_file(entry.path, scan_type):
                                    yield entry.path
                                    collected += 1
                                    if progress_callback and collected % 100 == 0:
                                        progress_callback(0, f"正在收集文件... ({collected} 个)")
                        except (OSError, PermissionError):
                            continue
            except (OSError, PermissionError):
                continue

    def _is_excluded_dir(self, path: str, dir_name: str, scan_type: str) -> bool:
        """判断目录是否需要排除"""
        if dir_name.startswith(".") or dir_name.startswith("$"):
            return True
        if dir_name in EXCLUDED_DIRS:
            return True
        # 系统目录黑名单（P0-1）：跳过系统还原/回收站/更新缓存等无效 I/O 目录
        if dir_name in BLACKLIST_DIR_PARTS:
            return True
        # 快速扫描时跳过用户数据目录
        if scan_type == "quick":
            skip_dirs = {"AppData", "node_modules", "__pycache__", ".git",
                         "Windows.old", "PerfLogs", "Temp"}
            if dir_name in skip_dirs:
                return True
        return False

    def _should_scan_file(self, file_path: str, scan_type: str) -> bool:
        """判断文件是否需要扫描"""
        name = os.path.basename(file_path).lower()
        if name in BLACKLIST_FILE_NAMES:
            return False  # 休眠/页面/回收站等系统文件，跳过减少无效 I/O
        try:
            size = os.path.getsize(file_path)
            if size == 0 or size > LARGE_FILE_ABS_CAP:
                return False
        except (OSError, PermissionError):
            return False

        if scan_type == "quick":
            # 快速扫描关注可疑扩展名。
            # ⚠️ 压缩包必须纳入：恶意样本最常见的投递方式就是压缩包
            # （邮件附件/网盘分享），而 _scan_single_file 本来就支持递归解压
            # 并返回包内威胁。此前 quick 不含 archives，等于对这类投递完全不设防
            # —— 用户手动点"快速扫描"却扫不到一个装满木马的 zip。
            ext = os.path.splitext(file_path)[1].lower()
            all_sus = (SCAN_EXTENSIONS["executables"] |
                       SCAN_EXTENSIONS["scripts"] |
                       SCAN_EXTENSIONS["documents"] |
                       SCAN_EXTENSIONS["archives"])
            return ext in all_sus
        # 全盘/自定义扫描：所有文件
        return True

    def scan_single(self, file_path: str, hash_store: dict | None = None) -> list:
        """扫描单个文件的**公开入口**（实时防护等外部调用方用这个）。

        为什么必须存在：``engine/realtime_guard.py`` 的扫描线程一直在调
        ``scanner.scan_single(path)``，但本类此前只有私有的
        ``_scan_single_file`` / ``_scan_single_file_impl``。于是**每个实时事件**
        都抛 AttributeError，又被 ``except Exception: continue`` 吞掉 ——
        实时文件防护的检测率实际为 0，界面上却只显示"没发现威胁"。
        补上这个别名把契约坐实；返回值与 ``_scan_single_file`` 一致：
        始终是 list[dict]，可能包含归档解压出的多个内部威胁。
        """
        return self._scan_single_file(file_path, hash_store=hash_store)

    def _scan_single_file(self, file_path: str, hash_store: dict | None = None) -> list:
        """扫描单个文件，返回威胁列表（含递归解压命中）。

        公开入口：始终返回 list[dict]，便于上层用 extend 聚合，
        也支持一个归档文件解压出多个内部威胁。
        hash_store: 可选顶层哈希记录 dict（path→sha256），供上层避免重复算哈希。
        """
        return self._scan_single_file_impl(file_path, depth=0, hash_store=hash_store)

    # ── 智能文件读取（单次 I/O：哈希 + 分析缓冲）───────────────

    def _read_file_smart(self, file_path: str, size: int) -> tuple[bytes, str, str]:
        """
        一次文件打开完成：哈希计算（全量流式）+ 分析缓冲
        返回: (data_buffer, md5_hex, sha256_hex)
        - 普通文件：缓冲首 32MB
        - 大文件（>200MB）：只缓冲首 4MB（文件头），避免大文件全量载入内存
        """
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        buffer_limit = LARGE_FILE_HEADER_READ if size > LARGE_FILE_THRESH else _BUFFER_LIMIT
        data = bytearray()
        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha256.update(chunk)
                    if len(data) < buffer_limit:
                        remaining = buffer_limit - len(data)
                        data.extend(chunk[:remaining])
            return bytes(data), md5.hexdigest(), sha256.hexdigest()
        except (OSError, PermissionError):
            return b"", "", ""

    # ── 扫描结果缓存（SHA256 TTL 缓存，LRU + 上限淘汰）──────────

    def _cache_lookup(self, sha256: str) -> list | None:
        """查缓存，返回 None 表示未命中"""
        with self._cache_lock:
            if sha256 in self._cache:
                ts, result = self._cache[sha256]
                if time.time() - ts < _SCAN_CACHE_TTL:
                    self._cache.move_to_end(sha256)  # LRU 提升
                    self.perf_stats["cache_hits"] += 1
                    return result
                else:
                    del self._cache[sha256]
            self.perf_stats["cache_misses"] += 1
            return None

    def _cache_store(self, sha256: str, threats: list):
        """写入缓存（LRU 淘汰，上限 _SCAN_CACHE_MAX）"""
        with self._cache_lock:
            if sha256 in self._cache:
                self._cache.move_to_end(sha256)
            self._cache[sha256] = (time.time(), threats)
            while len(self._cache) > _SCAN_CACHE_MAX:
                self._cache.popitem(last=False)

    def get_perf_stats(self) -> dict:
        """返回扫描性能统计快照（线程安全）"""
        with self._stats_lock:
            s = dict(self.perf_stats)
        # 计算衍生指标
        if s["total_scans"] > 0:
            s["avg_scan_time_ms"] = round(s["total_scan_time"] / s["total_scans"] * 1000, 2)
            s["cache_hit_rate"] = round(s["cache_hits"] / (s["cache_hits"] + s["cache_misses"]) * 100, 1) if (s["cache_hits"] + s["cache_misses"]) > 0 else 0.0
        return s

    # ── 云查前置（带节流，防刷爆云端 API）─────────────────────

    def _cloud_lookup_throttled(self, md5: str, sha256: str) -> dict | None:
        global _cloud_last_query
        with _cloud_throttle_lock:
            now = time.time()
            if now - _cloud_last_query < CLOUD_QUERY_MIN_INTERVAL:
                return None
            _cloud_last_query = now
        try:
            return self.cloud.lookup_hash(md5=md5, sha256=sha256)
        except Exception:
            return None

    def _scan_single_file_impl(self, file_path: str, depth: int = 0,
                               hash_store: dict | None = None) -> list:
        """扫描单个文件（含递归解压）；返回威胁列表（可能为空）
        
        v2.1 优化：
        - 单次文件打开完成哈希+分析缓冲（消除 5→1 次 I/O）
        - SHA256 扫描结果缓存（同文件短期免扫）
        - 云查前置：命中即短路（再走本地特征/YARA）
        - 大文件两档读取，内存有界
        - ML 引擎融合判定
        """
        threats: list = []
        t0 = time.perf_counter()
        try:
            size = os.path.getsize(file_path)
            if size > LARGE_FILE_ABS_CAP or size == 0:
                return threats
        except (OSError, PermissionError):
            return threats

        # 0. 递归解压扫描（受深度/条目上限保护，防 zip bomb）
        t_arch = time.perf_counter()
        if depth < _MAX_ARCHIVE_DEPTH:
            arc_type = self._detect_archive(file_path, size)
            if arc_type and arc_type == "zip":
                # APK 走专用路径（classes.dex → DexParser + YARA），非 APK 走通用解压
                if self._is_apk(file_path):
                    apk_threats = self._scan_apk(file_path, depth)
                    if apk_threats:
                        self._add_perf("archive_time", time.perf_counter() - t_arch)
                        self._add_perf("total_scans", 1)
                        self._add_perf("total_scan_time", time.perf_counter() - t0)
                        return apk_threats
                inner = self._unpack_and_scan(file_path, arc_type, depth)
                if inner:
                    self._add_perf("archive_time", time.perf_counter() - t_arch)
                    self._add_perf("total_scans", 1)
                    self._add_perf("total_scan_time", time.perf_counter() - t0)
                    return inner
        self._add_perf("archive_time", time.perf_counter() - t_arch)

        # 1. 智能读取：一次打开，全量哈希 + 分析缓冲（首32MB / 大文件首4MB）
        t_hash = time.perf_counter()
        data, md5_hash, sha256_hash = self._read_file_smart(file_path, size)
        if not md5_hash and not sha256_hash:
            return threats
        self._add_perf("hash_time", time.perf_counter() - t_hash)
        self._add_perf("total_bytes_read", size)

        # 记录顶层哈希供上层复用（避免云端复核时重读文件），有界防止内存膨胀
        if depth == 0 and hash_store is not None and sha256_hash:
            if len(hash_store) < _MAX_RETAINED_PATHS:
                hash_store[file_path] = sha256_hash

        # 缓存检查（深度0时才缓存，避免归档解压干扰）
        if depth == 0:
            cached = self._cache_lookup(sha256_hash)
            if cached is not None:
                self._add_perf("total_scans", 1)
                self._add_perf("total_scan_time", time.perf_counter() - t0)
                return cached

        # 2. 云查前置（命中即短路；仅顶层文件 + 节流）
        if depth == 0 and self.cloud and getattr(self.cloud, "available", False):
            cloud_threat = self._cloud_lookup_throttled(md5_hash, sha256_hash)
            if cloud_threat:
                cloud_threat["path"] = os.path.abspath(file_path)
                cloud_threat["md5"] = md5_hash
                cloud_threat["sha256"] = sha256_hash
                threats.append(cloud_threat)
                self._cache_store(sha256_hash, threats)
                self._add_perf("total_scans", 1)
                self._add_perf("total_scan_time", time.perf_counter() - t0)
                return threats

        # 3. 特征库匹配
        t_sig = time.perf_counter()
        sig = self.sig_mgr.lookup(md5=md5_hash, sha256=sha256_hash)
        self._add_perf("signature_time", time.perf_counter() - t_sig)
        if sig:
            threats.append({
                "path": os.path.abspath(file_path),
                "md5": md5_hash,
                "sha256": sha256_hash,
                "threat_level": sig["threat_level"],
                "engine": "signature",
                "signature": sig["threat_name"],
                "category": sig["category"],
                "details": {
                    "matched_hash": sig["matched_hash"],
                    "source": sig["source"],
                    "file_size": size
                },
                "action": "quarantine"
            })
            if depth == 0: self._cache_store(sha256_hash, threats)
            self._add_perf("total_scans", 1)
            self._add_perf("total_scan_time", time.perf_counter() - t0)
            return threats

        # 4. YARA 规则匹配（使用内存缓冲，避免二次 I/O）
        t_yara = time.perf_counter()
        if self.yara and self.yara.rules:
            # 使用整块已缓冲数据（普通≤32MB / 大文件4MB），零额外 I/O，提升检出
            yara_hits = self.yara.scan_content(data, file_path)
            self._add_perf("yara_time", time.perf_counter() - t_yara)
            if yara_hits:
                level_map = {"RANSOMWARE": "critical", "BACKDOOR": "high", "INFOSTEALER": "high",
                             "BANKING": "high", "MALWARE": "high", "TROJAN": "high",
                             "HACKTOOL": "medium", "INFO": "low"}
                best = yara_hits[0]
                yara_level = level_map.get(best.get("malware_type", ""), "medium")
                threats.append({
                    "path": os.path.abspath(file_path),
                    "md5": md5_hash,
                    "sha256": sha256_hash,
                    "threat_level": yara_level,
                    "engine": "yara",
                    "signature": f"YARA.{best['rule']}",
                    "category": best.get("malware_type", "MALWARE").lower(),
                    "details": {
                        "rule": best["rule"],
                        "description": best["description"],
                        "matched_patterns": best["matched_patterns"],
                        "yara_source": best.get("source_file", ""),
                        "file_size": size
                    },
                    # 规则质量分级由 yara_scanner 算出；这里必须显式带过去，
                    # 否则处置层拿到的永远是默认值 —— 闸门零会形同虚设。
                    "confidence": best.get("confidence", "medium"),
                    "quality_reason": best.get("quality_reason", ""),
                    "action": "quarantine"
                })
                if depth == 0: self._cache_store(sha256_hash, threats)
                self._add_perf("total_scans", 1)
                self._add_perf("total_scan_time", time.perf_counter() - t0)
                return threats
        else:
            self._add_perf("yara_time", time.perf_counter() - t_yara)

        # 4.5 火绒内容特征串（方案 B：不经 YARA 的字符串匹配）
        #     与 YARA 的区别：命中默认只告警（confidence=low），不短路，后续引擎照常跑；
        #     仅当 config.HUORONG_CONTENT_AUTO_QUARANTINE=True 且字面量够长时才允许处置。
        t_hr = time.perf_counter()
        if self.content_sig is not None:
            hr_hits = self.content_sig.scan_content(data)
            self._add_perf("content_sig_time", time.perf_counter() - t_hr)
            if hr_hits:
                best = hr_hits[0]                       # 已按字面量长度降序
                confidence = best.get("confidence", "low")
                hr_level = {"high": "high", "medium": "medium"}.get(best.get("tier"), "low")
                threats.append({
                    "path": os.path.abspath(file_path),
                    "md5": md5_hash,
                    "sha256": sha256_hash,
                    "threat_level": hr_level,
                    "engine": "huorong_sig",
                    "signature": "Huorong.ContentSig",
                    "category": "content_signature",
                    "details": {
                        "matched_literal": best["literal"][:200],
                        "literal_length": best["length"],
                        "hit_count": len(hr_hits),
                        "matched_literals": [h["literal"][:120] for h in hr_hits],
                        "source": "huorong_extract",
                        "file_size": size,
                    },
                    # 默认 low -> 处置层降级为仅告警；开启自动处置后才给真实档位
                    "confidence": confidence,
                    "quality_reason": "火绒内容特征串命中，字面量 %d 字节" % best["length"],
                    "action": "quarantine",
                })
                # 仅高置信度才短路；默认仅告警时继续走启发式/ML，避免单条字面量一票否决
                if confidence != "low":
                    if depth == 0: self._cache_store(sha256_hash, threats)
                    self._add_perf("total_scans", 1)
                    self._add_perf("total_scan_time", time.perf_counter() - t0)
                    return threats
        else:
            self._add_perf("content_sig_time", time.perf_counter() - t_hr)

        # 5. 通用启发式分析（使用内存缓冲）
        t_heur = time.perf_counter()
        generic = self._generic_heuristic_from_data(data[:65536], file_path, md5_hash, sha256_hash, size)
        self._add_perf("heuristic_time", time.perf_counter() - t_heur)
        if generic:
            threats.append(generic)
            if depth == 0: self._cache_store(sha256_hash, threats)
            self._add_perf("total_scans", 1)
            self._add_perf("total_scan_time", time.perf_counter() - t0)
            return threats

        # 6. PE 启发式分析
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SCAN_EXTENSIONS["executables"]:
            t_pe = time.perf_counter()
            heuristic = self._pe_heuristic_from_data(data[:64], file_path, md5_hash, sha256_hash, size)
            self._add_perf("heuristic_time", time.perf_counter() - t_pe)
            if heuristic:
                threats.append(heuristic)
                if depth == 0: self._cache_store(sha256_hash, threats)
                self._add_perf("total_scans", 1)
                self._add_perf("total_scan_time", time.perf_counter() - t0)
                return threats

        # 7. ML 检测（PE 文件；缓冲内 32MB/4MB 截取）
        if ext in SCAN_EXTENSIONS["executables"]:
            t_ml = time.perf_counter()
            ml_result = self._ml_scan_from_data(data, file_path, md5_hash, sha256_hash, size)
            self._add_perf("ml_time", time.perf_counter() - t_ml)
            if ml_result and ml_result.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
                threats.append(ml_result)
                if depth == 0: self._cache_store(sha256_hash, threats)
                self._add_perf("total_scans", 1)
                self._add_perf("total_scan_time", time.perf_counter() - t0)
                return threats

        if depth == 0: self._cache_store(sha256_hash, threats)
        self._add_perf("total_scans", 1)
        self._add_perf("total_scan_time", time.perf_counter() - t0)
        return threats

    def _add_perf(self, key: str, value: float):
        """线程安全地累加性能统计"""
        with self._stats_lock:
            if key == "total_scans":
                self.perf_stats[key] += int(value)
            else:
                self.perf_stats[key] += value

    # ── APK 专用检测路径 ─────────────────────────────────────────

    @staticmethod
    def _is_apk(file_path: str) -> bool:
        """判断文件是否为 APK（扩展名 .apk 或 zip 内含 classes.dex）"""
        if os.path.splitext(file_path)[1].lower() == ".apk":
            return True
        # zip 但含 classes.dex → 也按 APK 处理
        try:
            with zipfile.ZipFile(file_path) as zf:
                names = zf.namelist()
                return any("classes.dex" in n for n in names)
        except Exception:
            return False

    def _scan_apk(self, file_path: str, depth: int) -> list:
        """APK 专用扫描：解压提取 classes.dex → DexParser 分析 + YARA 扫描"""
        threats: list = []
        tmpdir = None
        try:
            with zipfile.ZipFile(file_path) as zf:
                # 查找 classes.dex（可能有多个 multidex）
                dex_entries = [n for n in zf.namelist()
                               if n.endswith("classes.dex") or n.endswith(".dex")]
                if not dex_entries:
                    return threats

                tmpdir = tempfile.mkdtemp(prefix="andun_apk_")
                abspath = os.path.abspath(file_path)

                for dex_name in dex_entries[:5]:  # 最多处理 5 个 dex
                    info = zf.getinfo(dex_name)
                    if info.file_size > _MAX_ENTRY_SIZE:
                        continue
                    dest = os.path.join(tmpdir, os.path.basename(dex_name) or "classes.dex")
                    with zf.open(info) as src, open(dest, "wb") as out:
                        shutil.copyfileobj(src, out, 65536)

                    # 1. DexParser 特征分析
                    try:
                        with open(dest, "rb") as f:
                            dex_data = f.read()
                        dp = DexParser(dex_data, file_path)
                        result = dp.detect()
                        if result:
                            result["path"] = abspath
                            result.setdefault("details", {})["extracted_from"] = dex_name
                            threats.append(result)
                    except Exception:
                        pass

                    # 2. YARA 扫描 DEX 字节码
                    if self.yara and self.yara.rules:
                        try:
                            yara_hits = self.yara.scan_file(dest)
                            if yara_hits:
                                level_map = {
                                    "RANSOMWARE": "critical", "BACKDOOR": "high",
                                    "INFOSTEALER": "high", "BANKING": "high",
                                    "MALWARE": "high", "TROJAN": "high",
                                    "HACKTOOL": "medium", "INFO": "low",
                                }
                                for hit in yara_hits:
                                    yl = level_map.get(hit.get("malware_type", ""), "medium")
                                    threats.append({
                                        "path": abspath,
                                        "md5": "", "sha256": "",
                                        "threat_level": yl,
                                        "engine": "yara",
                                        "signature": f"YARA.{hit['rule']}",
                                        "category": hit.get("malware_type", "MALWARE").lower(),
                                        "details": {
                                            "rule": hit["rule"],
                                            "description": hit.get("description", ""),
                                            "matched_patterns": hit.get("matched_patterns", []),
                                            "extracted_from": dex_name,
                                        },
                                        # 同上：置信度必须带过去
                                        "confidence": hit.get("confidence", "medium"),
                                        "quality_reason": hit.get("quality_reason", ""),
                                        "action": "quarantine",
                                    })
                        except Exception:
                            pass

                    if self._is_cancelled():
                        break
        except Exception:
            pass
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)
        return threats

    def _detect_archive(self, file_path: str, size: int) -> str | None:
        """按文件头 magic / 扩展名判断归档类型；返回 'zip'/'rar'/None"""
        try:
            with open(file_path, "rb") as f:
                magic = f.read(8)
        except (OSError, PermissionError):
            return None
        for sig, t in _ARCHIVE_MAGIC.items():
            if magic.startswith(sig):
                return t
        ext = os.path.splitext(file_path)[1].lower()
        if ext in _ARCHIVE_EXTS:
            return "zip" if ext != ".rar" else "rar"
        return None

    def _unpack_and_scan(self, file_path: str, arc_type: str, depth: int) -> list:
        """解压归档并递归扫描内部条目；返回内部威胁列表（path 重写回原始归档）。

        仅支持 zip 系列（zip/apk/jar，标准库 zipfile）。rar 需要第三方库，暂不展开。
        """
        if arc_type != "zip":
            return []
        try:
            zf = zipfile.ZipFile(file_path)
        except Exception:
            return []
        tmp = tempfile.mkdtemp(prefix="andun_unpack_")
        found: list = []
        try:
            entries = zf.infolist()
            if len(entries) > _MAX_ARCHIVE_ENTRIES:
                # 条目过多 → 疑似 zip bomb，直接不展开
                return []
            for info in entries:
                if info.is_dir():
                    continue
                name = info.filename
                # 防路径穿越
                if name.startswith("/") or name.startswith("\\") or ".." in name:
                    continue
                if info.file_size > _MAX_ENTRY_SIZE:
                    continue
                try:
                    dest = os.path.join(tmp, os.path.basename(name) or "_entry")
                    with zf.open(info) as src, open(dest, "wb") as out:
                        shutil.copyfileobj(src, out, 65536)
                except Exception:
                    continue
                res = self._scan_single_file_impl(dest, depth + 1)
                for t in res:
                    # 把命中归属回原始归档，保证按家族统计正确
                    t["path"] = os.path.abspath(file_path)
                    t.setdefault("details", {})["extracted_from"] = name
                    found.append(t)
                if self._is_cancelled():
                    break
        except Exception:
            pass
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            try:
                zf.close()
            except Exception:
                pass
        return found

    def _compute_hashes(self, file_path: str) -> tuple[str, str]:
        """计算 MD5 和 SHA256（保留兼容性）"""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            return md5.hexdigest(), sha256.hexdigest()
        except (OSError, PermissionError):
            return "", ""

    # ── 基于内存缓冲的启发式变体（零额外 I/O）──────────────

    def _generic_heuristic_from_data(self, header: bytes, file_path: str,
                                      md5: str, sha256: str, size: int) -> dict | None:
        """通用启发式分析 - 使用内存缓冲数据（零额外 I/O）"""
        return self.heuristic_engine.analyze_generic(header, file_path, md5, sha256, size)

    def _generic_heuristic_core(self, header: bytes, file_path: str,
                                 md5: str, sha256: str, size: int) -> dict | None:
        """通用文件启发式检测核心逻辑（委托给独立启发式引擎）"""
        return self.heuristic_engine.analyze_generic(header, file_path, md5, sha256, size)

    def _generic_heuristic(self, file_path: str, md5: str, sha256: str, size: int) -> dict | None:
        """通用文件启发式检测（保留兼容性，委托给独立启发式引擎）"""
        return self.heuristic_engine.analyze_generic_file(file_path, md5, sha256, size)

    def _pe_heuristic_from_data(self, header: bytes, file_path: str,
                                  md5: str, sha256: str, size: int) -> dict | None:
        """PE 文件启发式检测 - 使用内存缓冲（委托给独立启发式引擎）"""
        return self.heuristic_engine.analyze_pe(header, file_path, md5, sha256, size)

    def _pe_heuristic(self, file_path: str, md5: str, sha256: str, size: int) -> dict | None:
        """PE 文件启发式检测（保留兼容性，委托给独立启发式引擎）"""
        return self.heuristic_engine.analyze_pe_file(file_path, md5, sha256, size)

    def _ml_scan_from_data(self, data: bytes, file_path: str,
                            md5: str, sha256: str, size: int) -> dict | None:
        """使用 ML 引擎扫描 PE 文件 - 使用内存缓冲数据"""
        try:
            from engine.ml_scanner import scan_pe as ml_scan_pe
            result = ml_scan_pe(data, sha256)
            verdict = result.get("verdict", "CLEAN")
            confidence = result.get("confidence", 0.0)

            if verdict == "MALICIOUS":
                threat_level = "critical" if confidence >= 0.85 else "high"
                return {
                    "path": os.path.abspath(file_path),
                    "md5": md5,
                    "sha256": sha256,
                    # ⚠️ verdict 必须带上：调用方（第 7 步）用
                    # `ml_result.get("verdict") in ("MALICIOUS","SUSPICIOUS")`
                    # 判断是否采纳。此前这里没有该键 → get() 恒为 None →
                    # **每一次 ML 检出都被静默丢弃**（而 ml_time 照常消耗）。
                    "verdict": verdict,
                    "threat_level": threat_level,
                    "engine": "ml",
                    "signature": f"ML.{verdict}",
                    "category": "ml_detected",
                    "details": {
                        "ml_verdict": verdict,
                        "ml_confidence": confidence,
                        "ml_reasons": result.get("reasons", []),
                        "suspicious_apis": result.get("features", {}).get("suspicious_apis", []),
                        "pe_info": result.get("features", {}).get("pe_info", {}),
                        "file_size": size
                    },
                    # ⚠️ 2026-10-17 由 "quarantine" 改为 "alert"。
                    # 实测（936 个合法系统文件：System32 636 + SysWOW64 300）：
                    #     SUSPICIOUS 52.5% + MALICIOUS 5.8% = **误报 48%**，
                    # 两个独立语料一致。这 5.8% 的 MALICIOUS 原先直接拿到
                    # action="quarantine" 进闸门链。
                    # 病根在特征而非阈值：理由里 "PE 文件无导入表或使用动态 API
                    # 解析" 一条就命中 452/936（LoadLibrary+GetProcAddress 是极常见
                    # 的正常用法），另有 "缺少数字签名" 这类本不该进 ML 的特征。
                    # 在特征重校准之前，这个引擎不该有搬走用户文件的能力。
                    # 现在闸门二也已经拦住它，这里改成 alert 是把意图写明确。
                    "action": "alert"
                }
            elif verdict == "SUSPICIOUS":
                return {
                    "path": os.path.abspath(file_path),
                    "md5": md5,
                    "sha256": sha256,
                    "verdict": verdict,      # 同上：调用方靠这个键决定是否采纳
                    "threat_level": "medium",
                    "engine": "ml",
                    "signature": f"ML.{verdict}",
                    "category": "ml_suspicious",
                    "details": {
                        "ml_verdict": verdict,
                        "ml_confidence": confidence,
                        "ml_reasons": result.get("reasons", []),
                        "suspicious_apis": result.get("features", {}).get("suspicious_apis", []),
                        "pe_info": result.get("features", {}).get("pe_info", {}),
                        "file_size": size
                    },
                    "action": "prompt"
                }
        except Exception:
            pass
        return None
