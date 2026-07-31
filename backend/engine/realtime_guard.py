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

# 默认监控路径
DEFAULT_WATCH_DIRS = [
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%TEMP%"),
]

# 排除的扩展名（不扫描）
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
        self._event_queue: queue.Queue[dict] = queue.Queue()
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
            t = threading.Thread(
                target=self._monitor_dir_loop, args=(d,), daemon=True,
                name=f"RTMon-{os.path.basename(d)}"
            )
            t.start()
            self._monitor_threads.append(t)

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
        self._monitor_threads.clear()
        self._scan_threads.clear()

    @property
    def enabled(self) -> bool:
        return self._enabled

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
        if path in self._watch_dirs:
            return True
        self._watch_dirs.append(path)
        if self._running:
            t = threading.Thread(
                target=self._monitor_dir_loop, args=(path,), daemon=True
            )
            t.start()
            self._monitor_threads.append(t)
        self._add_event("info", f"新增监控目录: {path}")
        return True

    def remove_watch_dir(self, path: str) -> bool:
        path = os.path.abspath(path)
        if path not in self._watch_dirs or path in DEFAULT_WATCH_DIRS:
            return False
        self._watch_dirs.remove(path)
        self._add_event("info", f"移除监控目录: {path}")
        return True

    def get_watch_dirs(self) -> list[str]:
        return list(self._watch_dirs)

    # ── 状态 ──

    def get_status(self) -> dict:
        with self._lock:
            return {
                "enabled": self._enabled,
                "running": self._running,
                "watching_dirs": len(self._monitor_threads),
                "watch_dirs": self._watch_dirs,
                "stats": dict(self._stats),
                "recent_events": list(self._events),
            }

    # ── 目录监控线程 ──

    def _monitor_dir_loop(self, directory: str):
        """监控单个目录的变更事件"""
        try:
            handle = kernel32.CreateFileW(
                directory, FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, None
            )
            if handle == INVALID_HANDLE_VALUE or not handle:
                self._add_event("error", f"无法打开目录: {directory}")
                return

            buf = ctypes.create_string_buffer(BUFFER_SIZE)
            bytes_returned = wt.DWORD(0)

            while not self._stop_event.is_set():
                try:
                    ok = kernel32.ReadDirectoryChangesW(
                        handle, buf, BUFFER_SIZE, WATCH_SUBTREE,
                        MONITOR_FILTERS, ctypes.byref(bytes_returned), None, None
                    )
                    if not ok:
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

                except Exception:
                    break

            kernel32.CloseHandle(handle)
        except Exception as e:
            self._add_event("error", f"监控线程异常 [{os.path.basename(directory)}]: {e}")

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

        self._event_queue.put({"path": path, "time": now})

    # ── 扫描线程 ──

    def _scan_worker(self):
        """从队列取文件，调用本地引擎扫描"""
        from engine.local_scanner import LocalScanner
        from engine.quarantine import QuarantineManager
        from engine.signature_manager import SignatureManager
        from engine.yara_scanner import YaraScanner

        # 如果外部注入则使用，否则自建
        scanner = self._scanner
        quarantine = self._quarantine
        if scanner is None:
            sm = SignatureManager()
            y = YaraScanner(os.path.join(os.path.dirname(__file__), "yara_rules"))
            scanner = LocalScanner(sm, y)
        if quarantine is None:
            quarantine = QuarantineManager()

        while not self._stop_event.is_set():
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
                # 自动隔离
                try:
                    quarantine.quarantine_file(path, threats)
                    self._stats["files_blocked"] += 1
                    self._add_event("danger", f"已隔离: {os.path.basename(path)} ({threats[0].get('signature','?')})")
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
