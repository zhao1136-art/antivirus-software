"""
实时文件监控模块 —— 使用 ReadDirectoryChangesW 监控文件系统变更

架构：
  监控线程(每目录) → 变更事件队列 → 防抖引擎(300ms) → 扫描线程池 → 自动隔离/告警

默认监控路径：
  Desktop, Downloads, %TEMP%, %APPDATA%, 用户自定义路径
"""
import os
import sys
import time
import json
import ctypes
import ctypes.wintypes as wt
import threading
import queue
from collections import deque
from datetime import datetime

IS_WINDOWS = sys.platform == 'win32'

# ── Win32 常量 ──
FILE_LIST_DIRECTORY = 0x0001
FILE_NOTIFY_CHANGE_FILE_NAME = 0x0001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x0002
FILE_NOTIFY_CHANGE_SIZE = 0x0008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x0010
FILE_NOTIFY_CHANGE_CREATION = 0x0040
FILE_ACTION_ADDED = 1
FILE_ACTION_REMOVED = 2
FILE_ACTION_MODIFIED = 3
FILE_ACTION_RENAMED_OLD = 4
FILE_ACTION_RENAMED_NEW = 5
INVALID_HANDLE_VALUE = -1
# 64 位下 CreateFileW 失败返回 (HANDLE)-1 = 0xFFFFFFFFFFFFFFFF，与 -1 比不中。
# ctypes 的 HANDLE(c_void_p) restype 把 NULL 转成 None、-1 转成无符号大整数，
# 所以判定失败必须同时覆盖 None / 0 / -1 / 0xFFFF...，否则失败句柄会被当成有效句柄。
_INVALID_HANDLE_VALUES = frozenset({
    None, 0, -1,
    (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1,   # 0xFFFFFFFFFFFFFFFF (x64)
})

# ── 配置 ──
MONITOR_FILTERS = (
    FILE_NOTIFY_CHANGE_FILE_NAME |
    FILE_NOTIFY_CHANGE_SIZE |
    FILE_NOTIFY_CHANGE_LAST_WRITE |
    FILE_NOTIFY_CHANGE_CREATION
)
DEBOUNCE_MS = 300          # 防抖窗口
SCAN_THREADS = 2           # 扫描线程数
BUFFER_SIZE = 65536        # ReadDirectoryChangesW 缓冲区
MAX_FILE_SIZE_MB = 50      # 最大扫描文件(MB)，超过跳过
WATCH_SUBTREE = True
# 事件背压队列上限：生产者(监控线程)→消费者(扫描线程)之间的有界队列。
# 防止磁盘大量变更时积压无界事件，避免内存暴涨（超出即丢弃并计数，消费者侧优先取舍）。
RT_EVENT_QUEUE_MAX = 10000
# 防抖缓存上限：超过后裁剪过期项，避免无限增长的内存泄漏
_DEBOUNCE_CACHE_MAX = 50000
_DEBOUNCE_TTL = DEBOUNCE_MS / 1000 * 4  # 超过 4 倍防抖窗口的条目视为过期

# ── 扫描优先级（游戏模式等场景由 app.py 切换）──
# "low"    扫描线程降为 BELOW_NORMAL + 每个文件补眠，把 CPU 让给前台
# "normal" 恢复默认
# 注：与 scheduler.set_priority 同名同参，游戏模式会同时调用两者（app.py:866）。
#     此前 RealtimeGuard 没有该方法，AttributeError 被 _init_game_mode 的
#     except 静默吞掉 —— 游戏模式实际上只降了扫描调度器，没降实时防护。
PRIORITY_LEVELS = ("low", "normal")
PRIORITY_SLEEP_S = {"low": 0.02, "normal": 0.0}   # low: 每文件额外补眠
PRIORITY_WIN32 = {"low": -1, "normal": 0}         # THREAD_PRIORITY_BELOW_NORMAL / NORMAL

# 监控线程读取被打断后的重连退避（秒），封顶 30s
_RECONNECT_BACKOFF_START = 1.0
_RECONNECT_BACKOFF_MAX = 30.0
# 唤醒阻塞中的 ReadDirectoryChangesW 用的探针文件（.tmp 已在排除表里，不会触发扫描）
_WAKE_PROBE_NAME = ".andun_rt_wake.tmp"

# 默认监控路径
DEFAULT_WATCH_DIRS = [
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%APPDATA%"),
]

# 排除的扩展名（不扫描）
# .lnk 保持排除：整套 LNK_Ruleset.yar 已在 _disabled/（88% 误报），当前没有活跃
# 规则检测 .lnk，扫了也没有规则能命中。与 config.SCAN_EXTENSIONS 保持一致。
EXCLUDE_EXTENSIONS = {'.tmp', '.log', '.lnk', '.ini', '.db', '.dmp', '.lock'}

# 感兴趣的扩展名（仅扫描这些）
SCAN_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.com', '.scr', '.pif',
    '.zip', '.rar', '.7z', '.gz', '.tar',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.pdf', '.js', '.vbs', '.ps1', '.bat', '.cmd',
    '.apk', '.jar', '.dex',
    '.hta', '.wsf', '.wsc',
}

# ── Win32 DLL ──
kernel32 = None
if IS_WINDOWS:
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE]
    kernel32.CreateFileW.restype = wt.HANDLE
    kernel32.ReadDirectoryChangesW.argtypes = [
        wt.HANDLE, wt.LPVOID, wt.DWORD, wt.BOOL, wt.DWORD,
        ctypes.POINTER(wt.DWORD), wt.LPVOID, wt.LPVOID
    ]
    kernel32.ReadDirectoryChangesW.restype = wt.BOOL
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.CloseHandle.restype = wt.BOOL
    kernel32.GetLastError.restype = wt.DWORD
    # 扫描线程自降优先级（游戏模式）：GetCurrentThread 返回伪句柄 -2
    kernel32.GetCurrentThread.restype = wt.HANDLE
    kernel32.SetThreadPriority.argtypes = [wt.HANDLE, ctypes.c_int]
    kernel32.SetThreadPriority.restype = wt.BOOL

    # CreateFileW 常量
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 1
    FILE_SHARE_WRITE = 2
    FILE_SHARE_DELETE = 4
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OVERLAPPED = 0x40000000


class FILE_NOTIFY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", wt.DWORD),
        ("Action", wt.DWORD),
        ("FileNameLength", wt.DWORD),
        ("FileName", ctypes.c_wchar * 1),
    ]


class RealtimeGuard:
    """实时文件监控引擎"""

    def __init__(self):
        self._enabled = True
        self._running = False
        self._monitor_threads: list[threading.Thread] = []
        self._scan_threads: list[threading.Thread] = []
        # 目录 -> 监控记录 {"stop": Event, "handle": HANDLE|None, "lock": Lock}
        # 每个目录一条记录：stop 用于要求该目录的监控线程退出（remove/全局 stop），
        # handle 用于在目录只读、探针写不进去时从外部关句柄取消阻塞中的读取。
        self._monitors: dict[str, dict] = {}
        self._monitors_lock = threading.Lock()
        self._priority = "normal"          # 扫描优先级（游戏模式切换）
        self._event_queue: queue.Queue[dict] = queue.Queue(maxsize=RT_EVENT_QUEUE_MAX)
        self._dropped_events = 0  # 背压丢弃计数（队列满时 put_nowait 抛 Full）
        self._debounce_cache: dict[str, float] = {}  # filepath → last_event_time
        self._debounce_lock = threading.Lock()
        self._stats = {
            "files_scanned": 0,
            "threats_found": 0,
            "files_blocked": 0,
        }
        self._events: deque[dict] = deque(maxlen=200)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._watch_dirs: list[str] = list(DEFAULT_WATCH_DIRS)

        # 外部注入（由 app.py 初始化时传入）
        self._scanner = None
        self._quarantine = None

    def set_scanner(self, scanner):
        self._scanner = scanner

    def set_quarantine(self, quarantine):
        self._quarantine = quarantine

    # ── 启停 ──

    def start(self):
        if not IS_WINDOWS or not self._enabled:
            return
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._add_event("info", "实时监控启动")

        # 启动每个目录的监控线程
        for d in self._watch_dirs:
            if not os.path.isdir(d):
                continue
            self._spawn_monitor(d)

        # 启动扫描线程池
        for i in range(SCAN_THREADS):
            t = threading.Thread(
                target=self._scan_worker, daemon=True,
                name=f"RTScan-{i}"
            )
            t.start()
            self._scan_threads.append(t)

        self._add_event("info", f"监控 {len(self._monitor_threads)} 个目录, {SCAN_THREADS} 个扫描线程")

    def stop(self):
        self._running = False
        self._stop_event.set()
        # 先给每个目录的监控记录发停止信号，再逐个唤醒阻塞中的读取，
        # 否则线程会卡在 ReadDirectoryChangesW 里直到下一个文件变更才退出。
        with self._monitors_lock:
            monitors = list(self._monitors.items())
            self._monitors.clear()
        for directory, rec in monitors:
            rec["stop"].set()
            self._wake_monitor(directory, rec)
        for _directory, rec in monitors:
            t = rec.get("thread")
            if t is not None:
                t.join(timeout=2.0)
        self._monitor_threads.clear()
        self._scan_threads.clear()

    # ── 监控线程生命周期 ──

    def _spawn_monitor(self, directory: str):
        """为单个目录创建监控记录并拉起线程（start 与 add_watch_dir 共用）"""
        rec = {"stop": threading.Event(), "handle": None,
               "lock": threading.Lock(), "thread": None}
        with self._monitors_lock:
            if directory in self._monitors:
                return False        # 已有记录，不重复起线程
            self._monitors[directory] = rec
        t = threading.Thread(
            target=self._monitor_dir_loop, args=(directory, rec), daemon=True,
            name=f"RTMon-{os.path.basename(directory)}"
        )
        rec["thread"] = t
        with self._lock:
            self._monitor_threads.append(t)
        t.start()
        return True

    def _wake_monitor(self, directory: str, rec: dict):
        """唤醒阻塞中的 ReadDirectoryChangesW：往目录写一个探针文件（事件即返回）。

        探针名 .andun_rt_wake.tmp 命中 EXCLUDE_EXTENSIONS，不会进扫描队列；
        目录只读/已失效时写不进去，退化为从外部关句柄取消阻塞的读取。
        """
        woke = False
        try:
            probe = os.path.join(directory, _WAKE_PROBE_NAME)
            with open(probe, "wb"):
                pass
            try:
                os.remove(probe)
            except OSError:
                pass
            woke = True
        except OSError:
            woke = False

        if not woke:
            # 兜底：关句柄取消阻塞中的读取（关掉句柄会让挂起的 ReadDirectoryChangesW 返回）。
            # 摘句柄在锁内完成并置 None，监控线程 finally 里的 _close_monitor_handle
            # 就会看到 None —— 两边都靠这个约定保证同一只句柄只关一次。
            # 线程侧在 stop 置位后不会再下发新读取，因此不存在"关了还拿去用"的窗口。
            with rec["lock"]:
                h = rec["handle"]
                rec["handle"] = None
            if h:
                try:
                    kernel32.CloseHandle(h)
                except Exception:
                    pass

    def _retire_monitor(self, directory: str) -> bool:
        """停止并摘除某个目录的监控（remove_watch_dir 用）"""
        with self._monitors_lock:
            rec = self._monitors.pop(directory, None)
        if rec is None:
            return False
        rec["stop"].set()
        self._wake_monitor(directory, rec)
        t = rec.get("thread")
        if t is not None:
            t.join(timeout=2.0)
            with self._lock:
                if t in self._monitor_threads:
                    self._monitor_threads.remove(t)
        return True

    @property
    def enabled(self) -> bool:
        return self._enabled

    def get_queue_stats(self) -> dict:
        """返回事件背压队列与防抖缓存的实时水位（线程安全快照）"""
        try:
            qsize = self._event_queue.qsize()
        except Exception:
            qsize = 0
        return {
            "queue_depth": max(0, qsize),
            "queue_max": RT_EVENT_QUEUE_MAX,
            "dropped_events": self._dropped_events,
            "debounce_cache_size": len(self._debounce_cache),
            "debounce_cache_max": _DEBOUNCE_CACHE_MAX,
            "scan_threads": len(self._scan_threads),
        }

    def enable(self):
        self._enabled = True
        self.start()

    def disable(self):
        self._enabled = False
        self.stop()

    def add_watch_dir(self, path: str) -> bool:
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            return False
        # 大小写/尾随分隔符不同的同一目录视为同一个，避免起两条监控线程
        norm = os.path.normcase(path)
        if any(os.path.normcase(d) == norm for d in self._watch_dirs):
            return True
        self._watch_dirs.append(path)
        if self._running:
            self._spawn_monitor(path)
        self._add_event("info", f"新增监控目录: {path}")
        return True

    def remove_watch_dir(self, path: str) -> bool:
        path = os.path.abspath(path)
        if path not in self._watch_dirs or path in DEFAULT_WATCH_DIRS:
            return False
        self._watch_dirs.remove(path)
        # 旧实现只摘列表不停线程：监控还在跑、事件还在入队。这里真正停掉线程。
        self._retire_monitor(path)
        self._add_event("info", f"移除监控目录: {path}")
        return True

    def get_watch_dirs(self) -> list[str]:
        return list(self._watch_dirs)

    def set_priority(self, priority: str = "normal") -> str:
        """设置扫描线程优先级（游戏模式调用，与 scheduler.set_priority 同参）。

        "low" 扫描线程降为 BELOW_NORMAL 且每个文件补眠 20ms，把 CPU 让给前台游戏；
        "normal" 恢复默认。非法值归一为 normal。返回生效的档位。
        """
        level = (priority or "").strip().lower()
        if level not in PRIORITY_LEVELS:
            level = "normal"
        self._priority = level
        self._add_event("info", f"扫描优先级切换为: {level}")
        return level

    # ── 状态 ──

    def get_status(self) -> dict:
        with self._lock:
            # 只数活着的线程：线程因任何原因退出后不应继续报在监控
            alive = sum(1 for t in self._monitor_threads if t.is_alive())
            return {
                "enabled": self._enabled,
                "running": self._running,
                "watching_dirs": alive,
                "watch_dirs": self._watch_dirs,
                "priority": self._priority,
                "stats": dict(self._stats),
                "recent_events": list(self._events),
            }

    # ── 目录监控线程 ──

    @staticmethod
    def _close_monitor_handle(rec: dict):
        """关掉记录里保存的目录句柄（幂等，锁内置 None 防双关）"""
        with rec["lock"]:
            handle = rec["handle"]
            rec["handle"] = None
        if handle:
            try:
                kernel32.CloseHandle(handle)
            except Exception:
                pass

    def _monitor_dir_loop(self, directory: str, rec: dict):
        """监控单个目录的变更事件，读取被打断时按退避自动重连。

        旧实现 ReadDirectoryChangesW 返回失败或解析抛异常就 break → CloseHandle →
        线程结束，**没有任何重连**：一次句柄错误（目录被删/拔盘/权限变化）后该目录
        就永久失明，而 get_status() 里 watching_dirs 还在报旧数字。这里改成外层
        重连循环：单次会话存活越久退避越短地重置，连续失败则 1s→30s 退避。
        """
        stop = rec["stop"]
        backoff = _RECONNECT_BACKOFF_START
        while not stop.is_set() and not self._stop_event.is_set():
            try:
                lived = self._monitor_once(directory, rec)
            except Exception as e:
                self._add_event("error", f"监控线程异常 [{os.path.basename(directory)}]: {e}")
                lived = -1.0
            # 会话因停止而结束：不再重连
            if stop.is_set() or self._stop_event.is_set():
                break
            if lived >= 5.0:
                backoff = _RECONNECT_BACKOFF_START   # 稳定跑过，重置退避
            if lived < 0.0:
                # 打不开目录：可能是暂时的（目录重建中/权限未就绪），退避重试
                if stop.wait(backoff) or self._stop_event.is_set():
                    break
                backoff = min(backoff * 2, _RECONNECT_BACKOFF_MAX)
                continue
            self._add_event(
                "error",
                f"监控中断 [{os.path.basename(directory)}]，{backoff:.0f}s 后重连"
            )
            if stop.wait(backoff) or self._stop_event.is_set():
                break
            backoff = min(backoff * 2, _RECONNECT_BACKOFF_MAX)

    def _monitor_once(self, directory: str, rec: dict) -> float:
        """打开目录并阻塞读取一轮变更；返回本次会话存活秒数，打开失败返回 -1。

        与旧版的差别：句柄存进 rec（供外部关句柄唤醒）、每次读取前清零
        bytes_returned、退出前在锁内关句柄（与外部唤醒方互斥，不会双关）。
        """
        stop = rec["stop"]
        handle = kernel32.CreateFileW(
            directory, FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, None
        )
        if handle in _INVALID_HANDLE_VALUES:
            self._add_event("error", f"无法打开目录: {directory}")
            return -1.0
        with rec["lock"]:
            if stop.is_set():
                # 打开期间已被要求停止：直接关掉，不进入阻塞读取
                try:
                    kernel32.CloseHandle(handle)
                except Exception:
                    pass
                return -1.0
            rec["handle"] = handle

        began = time.time()
        try:
            buf = ctypes.create_string_buffer(BUFFER_SIZE)
            bytes_returned = wt.DWORD(0)

            while not stop.is_set() and not self._stop_event.is_set():
                bytes_returned.value = 0
                ok = kernel32.ReadDirectoryChangesW(
                    handle, buf, BUFFER_SIZE, WATCH_SUBTREE,
                    MONITOR_FILTERS, ctypes.byref(bytes_returned), None, None
                )
                if not ok:
                    # 被外部关句柄唤醒（remove/stop 兜底）属正常退出；
                    # 其余情况（缓冲区溢出、句柄失效）交给外层重连。
                    break

                offset = 0
                while offset < bytes_returned.value:
                    fni = ctypes.cast(
                        ctypes.addressof(buf) + offset,
                        ctypes.POINTER(FILE_NOTIFY_INFORMATION)
                    ).contents

                    name_len = fni.FileNameLength // 2
                    if name_len > 0 and name_len < 512:
                        # 从原始缓冲区读取宽字符串
                        char_arr = (ctypes.c_wchar * name_len).from_address(
                            ctypes.addressof(buf) + offset + 12
                        )
                        file_name = ''.join(char_arr)
                    else:
                        file_name = ""

                    full_path = os.path.join(directory, file_name) if file_name else ""

                    if fni.Action in (FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_RENAMED_NEW):
                        self._enqueue_file(full_path)

                    if fni.NextEntryOffset == 0:
                        break
                    offset += fni.NextEntryOffset

        finally:
            # 锁内摘句柄：外部 _wake_monitor 可能已经把它关了，这里只负责兜底
            self._close_monitor_handle(rec)
        return time.time() - began

    def _enqueue_file(self, path: str):
        """文件加入扫描队列（带防抖）"""
        now = time.time()
        ext = os.path.splitext(path)[1].lower()

        # 路径过滤
        if not os.path.isfile(path):
            return
        if ext in EXCLUDE_EXTENSIONS:
            return
        if SCAN_EXTENSIONS and ext not in SCAN_EXTENSIONS:
            return
        try:
            if os.path.getsize(path) > MAX_FILE_SIZE_MB * 1024 * 1024:
                return
        except OSError:
            return

        with self._debounce_lock:
            last = self._debounce_cache.get(path, 0)
            if now - last < DEBOUNCE_MS / 1000:
                return
            self._debounce_cache[path] = now
            # 有界裁剪：超出上限时移除过期项，仍超则清空（最坏情况退化为全量重建）
            if len(self._debounce_cache) > _DEBOUNCE_CACHE_MAX:
                stale = [p for p, ts in self._debounce_cache.items()
                         if now - ts > _DEBOUNCE_TTL]
                for p in stale:
                    del self._debounce_cache[p]
                if len(self._debounce_cache) > _DEBOUNCE_CACHE_MAX:
                    self._debounce_cache.clear()

        # 有界背压入队：满则丢弃并计数，绝不阻塞监控线程
        try:
            self._event_queue.put_nowait({"path": path, "time": now})
        except queue.Full:
            self._dropped_events += 1

    # ── 扫描线程 ──

    def _scan_worker(self):
        """从队列取文件，调用本地引擎扫描"""
        from engine.local_scanner import LocalScanner
        from engine.quarantine import QuarantineManager
        from engine.signature_manager import get_signature_manager
        from engine.yara_scanner import YaraScanner

        # 如果外部注入则使用，否则自建（复用全局共享特征库实例，避免重复连接/索引）
        scanner = self._scanner
        quarantine = self._quarantine
        if scanner is None:
            sm = get_signature_manager()
            y = YaraScanner(os.path.join(os.path.dirname(__file__), "yara_rules"))
            scanner = LocalScanner(sm, y)
        if quarantine is None:
            quarantine = QuarantineManager()

        # 2026-10-03：实时防护原先"YARA 命中即自动隔离"，会在用户毫不知情的情况下
        # 把文件直接搬走。现在与扫描路径共用同一套闸门：
        #   闸门一 系统目录文件二次复核（不使用 YARA）
        #   闸门二 用户决定，15 秒内无决定则自动处理
        from engine.threat_decision import (is_system_path, second_opinion,
                                            QUEUE as decision_queue,
                                            ACTION_QUARANTINE)

        applied_prio = None   # 本线程当前已应用的档位（变化时才调 SetThreadPriority）

        while not self._stop_event.is_set():
            # ── 应用扫描优先级（游戏模式切到 low 时降线程优先级 + 补眠让出 CPU）──
            prio = self._priority
            if prio != applied_prio:
                applied_prio = prio
                if IS_WINDOWS:
                    try:
                        kernel32.SetThreadPriority(
                            kernel32.GetCurrentThread(), PRIORITY_WIN32.get(prio, 0)
                        )
                    except Exception:
                        pass
            if PRIORITY_SLEEP_S.get(prio, 0.0) > 0:
                # 可被 stop 立即打断的睡眠（stop 后 1s 内线程退出）
                if self._stop_event.wait(PRIORITY_SLEEP_S[prio]):
                    break

            try:
                item = self._event_queue.get(timeout=1)
            except queue.Empty:
                continue

            path = item["path"]
            if not os.path.isfile(path):
                continue

            try:
                threats = scanner.scan_single(path)
            except Exception:
                continue

            with self._lock:
                self._stats["files_scanned"] += 1

            if threats:
                with self._lock:
                    self._stats["threats_found"] += 1

                # 闸门零：低置信度规则只告警（与扫描路径同一套判据）
                _first = threats[0] if threats and isinstance(threats[0], dict) else {}
                if (_first.get("confidence") or "medium").lower() == "low":
                    with self._lock:
                        self._stats["suppressed"] = self._stats.get("suppressed", 0) + 1
                    self._add_event("info", "低置信度规则，仅告警: " + os.path.basename(path))
                    continue

                # 闸门一：系统目录文件的二次复核（不使用 YARA）。
                # 复核不出结论时不自动隔离 —— 交给人，宁漏勿滥。
                op = second_opinion(path) if is_system_path(path) else {"trusted": False}
                if op.get("trusted"):
                    with self._lock:
                        self._stats["suppressed"] = self._stats.get("suppressed", 0) + 1
                    self._add_event("info", "已放行（系统文件二次复核）: " + os.path.basename(path))
                    continue

                # 闸门二：跨引擎确认 —— YARA 之外至少一个引擎也命中。
                # 与扫描路径同一套判据（闸门零=规则弱、闸门一=可信系统文件、
                # 本道=YARA 一家说了算）。未确认就**不进用户决定流程**，
                # 这样即便用户没看弹窗、超时自动处理，也不会被隔离。
                first = threats[0] if threats and isinstance(threats[0], dict) else {}
                try:
                    from engine.cross_check import cross_check
                    # 提出威胁的引擎排除在确认集合外（防"自己确认自己"）
                    _eng = str(first.get("engine") or "").lower()
                    _excl = (("heuristic",) if _eng == "heuristic"
                             else ("hash",) if _eng in ("signature", "hash")
                             else ())
                    cc = cross_check(path,
                                     md5=first.get("md5", "") or "",
                                     sha1=first.get("sha1", "") or "",
                                     sha256=first.get("sha256", "") or "",
                                     size=first.get("file_size") or 0,
                                     exclude=_excl)
                except Exception as exc:
                    cc = {"confirmed": False,
                          "note": "跨引擎确认不可用（%s），按未确认处理" % exc}
                first["cross_check"] = cc
                if not cc.get("confirmed"):
                    with self._lock:
                        self._stats["suppressed"] = self._stats.get("suppressed", 0) + 1
                    self._add_event("info",
                                    "跨引擎未确认，仅告警: %s（%s）"
                                    % (os.path.basename(path), cc.get("note", "")))
                    continue

                # 闸门三：用户决定，DECISION_TIMEOUT 秒内无决定则自动处理
                pd = decision_queue.ask(path, first)
                decision_queue.wait_all([pd])
                if decision_queue.finalize(pd) != ACTION_QUARANTINE:
                    self._add_event("info", "用户选择忽略: " + os.path.basename(path))
                    continue

                # 自动隔离
                try:
                    quarantine.quarantine_file(
                        path,
                        threat_name=first.get("signature", "Unknown"),
                        threat_level=first.get("threat_level", "medium"),
                        file_hash=first.get("sha256", ""),
                    )
                    with self._lock:
                        self._stats["files_blocked"] += 1
                    self._add_event("danger", f"已隔离: {os.path.basename(path)} ({first.get('signature','?')})")
                except Exception as e:
                    self._add_event("error", f"隔离失败: {os.path.basename(path)}: {e}")

    # ── 事件日志 ──

    def _add_event(self, level: str, message: str):
        event = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        }
        with self._lock:
            self._events.append(event)
