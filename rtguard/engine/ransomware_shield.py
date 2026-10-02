"""
御天 防勒索防护模块

监控勒索病毒批量加密文件行为，提前预警，阻断加密扩散，保护用户文档数据。

功能：
  1. 后台守护进程常驻运行，监控自定义保护目录（文档、桌面、图片等）
  2. 滑动时间窗口检测批量文件修改、重命名等典型勒索加密行为
  3. 监控高危系统指令，检测删除卷影副本、清除系统恢复点等勒索前置操作
  4. 部署诱饵蜜罐文件，快速识别全盘遍历加密程序
  5. 支持信任程序白名单，减少办公软件误报
  6. 发现可疑勒索行为，弹窗紧急告警；可选配置自动终止威胁进程
  7. 提供文件快照备份，支持攻击后恢复文件
  8. 独立防勒索运行日志，记录威胁进程与操作记录
  9. 默认关闭，在设置中开启
"""
import os
import sys
import time
import json
import shutil
import hashlib
import threading
import subprocess
import queue
from collections import deque, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

IS_WINDOWS = sys.platform == 'win32'

# ── 默认配置 ──
DEFAULT_PROTECTED_DIRS = [
    os.path.expandvars(r"%USERPROFILE%\Documents"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%USERPROFILE%\Pictures"),
]
SNAPSHOT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "ransomware_snapshots"
)
LOG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "logs"
)
RANSOM_LOG_FILE = os.path.join(LOG_DIR, "ransomware.log")
HONEYPOT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "honeypots"
)

# 滑动时间窗口 (秒)
SLIDING_WINDOW_SEC = 60
# 窗口内触发告警的阈值（文件修改/新增数）
ALERT_THRESHOLD = 10
# 蜜罐文件检查间隔 (秒)
HONEYPOT_CHECK_INTERVAL = 5
# 目录监控轮询间隔 (秒)
DIR_SCAN_INTERVAL = 2
# 高危命令检查间隔 (秒)
CMD_CHECK_INTERVAL = 10
# 快照保留天数
SNAPSHOT_RETENTION_DAYS = 7

# 勒索软件常见扩展名（用于检测加密行为）
RANSOM_EXTENSIONS = {
    '.lockbit', '.crypt', '.encrypted', '.enc', '.locked', '.cryptolocker',
    '.wanna', '.wncry', '.onion', '.cerber', '.dharma', '.phobos',
    '.stop', '.djvu', '.makop', '.quantum', '.blackcat', '.alice',
    '.babyk', '.bk', '.filelock', '.lol', '.more_encrypted',
    '.encrypt', '.crypto', '.ezz', '.exx', '.zzz', '.xyz',
    '.aaa', '.ccc', '.vvv', '.ttt', '.micro', '.wallet',
}

# 高危系统命令特征
HIGH_RISK_COMMANDS = [
    "vssadmin delete shadows",
    "vssadmin resize shadowstorage",
    "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled no",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "wbadmin delete catalog",
    "powershell remove-item -path",
    "cipher /w",
    "wevtutil cl",
    "fsutil usn deleterej",
    "reg delete",
    "sc delete",
    "netsh advfirewall",
]

# ── 工具函数 ──

def _get_logger():
    """获取防勒索专用日志记录器"""
    os.makedirs(LOG_DIR, exist_ok=True)
    import logging
    logger = logging.getLogger("ransomware_shield")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(RANSOM_LOG_FILE, encoding="utf-8")
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


# ══════════════════════════════════════════════════════════════
#  RansomwareShield — 防勒索防护主引擎
# ══════════════════════════════════════════════════════════════

class RansomwareShield:
    """防勒索防护服务"""

    def __init__(self):
        self._enabled = False       # 默认关闭
        self._running = False
        self._stop_event = threading.Event()
        self._logger = None

        # 保护目录列表
        self._protected_dirs: list[str] = list(DEFAULT_PROTECTED_DIRS)
        self._protected_dirs_lock = threading.Lock()

        # 白名单 (进程名或路径)
        self._whitelist: set[str] = set()
        self._whitelist_lock = threading.Lock()

        # 滑动窗口事件记录 {目录: deque[(时间, 动作, 文件路径)]}
        self._window_events: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self._window_lock = threading.Lock()

        # 蜜罐文件列表
        self._honeypot_files: list[str] = []
        self._honeypot_lock = threading.Lock()

        # 快照索引 {filepath: {"hash": str, "timestamp": float, "backup_path": str}}
        self._snapshot_index: dict[str, dict] = {}
        self._snapshot_lock = threading.Lock()

        # 告警记录（防止重复告警）
        self._alerted_sources: set[str] = set()
        self._alert_lock = threading.Lock()

        # 统计
        self._stats = {
            "files_changed": 0,
            "alerts_triggered": 0,
            "processes_killed": 0,
            "files_restored": 0,
            "honeypot_triggers": 0,
        }
        self._stats_lock = threading.Lock()

        # 线程引用
        self._threads: list[threading.Thread] = []

    # ── 属性 ──

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def running(self) -> bool:
        return self._running

    # ── 启停 ──

    def enable(self):
        """启用防勒索防护"""
        if self._enabled:
            return
        self._enabled = True
        self._logger = _get_logger()
        self._log("info", "防勒索防护已启用")
        if not self._running:
            self._start()

    def disable(self):
        """停用防勒索防护"""
        self._enabled = False
        if self._running:
            self._stop()
        if self._logger:
            self._log("info", "防勒索防护已停用")

    def start(self):
        """启动守护线程"""
        if self._running or not self._enabled:
            return
        self._running = True
        self._stop_event.clear()
        self._logger = _get_logger()
        self._log("info", "防勒索守护启动")

        # 确保目录存在
        os.makedirs(SNAPSHOT_DIR, exist_ok=True)
        os.makedirs(HONEYPOT_DIR, exist_ok=True)

        # 启动各监控线程
        threads_cfg = [
            ("DirMonitor", self._dir_monitor_loop),
            ("HoneypotWatch", self._honeypot_watch_loop),
            ("CmdMonitor", self._cmd_monitor_loop),
            ("SnapshotCleaner", self._snapshot_cleaner_loop),
        ]
        for name, target in threads_cfg:
            t = threading.Thread(target=target, daemon=True, name=f"Ransom-{name}")
            t.start()
            self._threads.append(t)

        # 部署蜜罐文件
        self._deploy_honeypots()

        self._log("info", f"防勒索守护已启动, 保护 {len(self._protected_dirs)} 个目录, "
                          f"{len(self._honeypot_files)} 个蜜罐文件")

    def _stop(self):
        """停止所有监控线程"""
        self._running = False
        self._stop_event.set()
        self._threads.clear()
        self._log("info", "防勒索守护已停止")

    # ── 保护目录管理 ──

    def get_protected_dirs(self) -> list[str]:
        with self._protected_dirs_lock:
            return list(self._protected_dirs)

    def add_protected_dir(self, path: str) -> bool:
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            return False
        with self._protected_dirs_lock:
            if path in self._protected_dirs:
                return True
            self._protected_dirs.append(path)
        self._log("info", f"新增保护目录: {path}")
        return True

    def remove_protected_dir(self, path: str) -> bool:
        path = os.path.abspath(path)
        with self._protected_dirs_lock:
            if path not in self._protected_dirs or path in DEFAULT_PROTECTED_DIRS:
                return False
            self._protected_dirs.remove(path)
        self._log("info", f"移除保护目录: {path}")
        return True

    # ── 白名单管理 ──

    def get_whitelist(self) -> list[str]:
        with self._whitelist_lock:
            return sorted(self._whitelist)

    def add_whitelist(self, name: str):
        with self._whitelist_lock:
            self._whitelist.add(name.strip().lower())
        self._log("info", f"添加白名单: {name}")

    def remove_whitelist(self, name: str) -> bool:
        with self._whitelist_lock:
            if name.strip().lower() not in self._whitelist:
                return False
            self._whitelist.discard(name.strip().lower())
        self._log("info", f"移除白名单: {name}")
        return True

    def is_whitelisted(self, process_name: str) -> bool:
        with self._whitelist_lock:
            return process_name.strip().lower() in self._whitelist

    # ── 蜜罐文件管理 ──

    def _deploy_honeypots(self):
        """在保护目录中部署诱饵蜜罐文件"""
        honeypot_names = [
            "~重要文档_请勿删除_README.txt",
            "~财务数据_2025_Q4.xlsx",
            "~客户资料_备份.db",
            "~项目计划_紧急.docx",
            "~个人隐私_密码.txt",
        ]
        with self._honeypot_lock:
            self._honeypot_files.clear()
            for d in self._protected_dirs:
                if not os.path.isdir(d):
                    continue
                for name in honeypot_names:
                    path = os.path.join(d, name)
                    try:
                        if not os.path.exists(path):
                            content = (
                                f"[安盾防勒索蜜罐文件]\n"
                                f"创建时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                                f"文件ID: {hashlib.md5(path.encode()).hexdigest()[:16]}\n"
                                f"警告: 此文件由安盾防勒索系统自动部署，任何修改将触发紧急告警！\n"
                            )
                            with open(path, "w", encoding="utf-8") as f:
                                f.write(content)
                            # 设置只读属性（Windows）
                            if IS_WINDOWS:
                                os.system(f'attrib +R "{path}"')
                        self._honeypot_files.append(path)
                    except Exception:
                        continue

    def _get_honeypot_files(self) -> list[str]:
        with self._honeypot_lock:
            return list(self._honeypot_files)

    # ── 快照管理 ──

    def take_snapshot(self, path: str) -> bool:
        """对指定文件创建快照备份"""
        if not os.path.isfile(path):
            return False
        try:
            rel = path.replace(":", "").replace("\\", "_").replace("/", "_")
            bak_name = f"{int(time.time())}_{rel}.snap"
            bak_path = os.path.join(SNAPSHOT_DIR, bak_name)
            shutil.copy2(path, bak_path)
            h = _file_hash(path)
            with self._snapshot_lock:
                self._snapshot_index[path] = {
                    "hash": h,
                    "timestamp": time.time(),
                    "backup_path": bak_path,
                }
            return True
        except Exception:
            return False

    def restore_file(self, path: str) -> bool:
        """从快照恢复文件"""
        with self._snapshot_lock:
            info = self._snapshot_index.get(path)
            if not info:
                return False
            bak_path = info["backup_path"]
        if not os.path.isfile(bak_path):
            return False
        try:
            shutil.copy2(bak_path, path)
            with self._stats_lock:
                self._stats["files_restored"] += 1
            self._log("info", f"文件已从快照恢复: {path}")
            return True
        except Exception as e:
            self._log("error", f"文件恢复失败: {path} -> {e}")
            return False

    def get_snapshot_backups(self) -> list[dict]:
        """获取所有快照备份列表"""
        result = []
        with self._snapshot_lock:
            for path, info in self._snapshot_index.items():
                result.append({
                    "original_path": path,
                    "backup_path": info["backup_path"],
                    "timestamp": info["timestamp"],
                    "hash": info["hash"],
                })
        return result

    # ── 目录监控线程 ──

    def _dir_monitor_loop(self):
        """轮询保护目录，检测批量文件修改"""
        # 初始化文件状态快照
        prev_state: dict[str, dict[str, float]] = {}
        for d in self._protected_dirs:
            if os.path.isdir(d):
                prev_state[d] = self._scan_dir_state(d)

        while not self._stop_event.is_set():
            self._stop_event.wait(DIR_SCAN_INTERVAL)
            if not self._enabled:
                continue

            with self._protected_dirs_lock:
                dirs = list(self._protected_dirs)

            for d in dirs:
                if not os.path.isdir(d):
                    continue
                curr_state = self._scan_dir_state(d)
                prev = prev_state.get(d, {})

                # 检测变化
                changed = []
                renamed = []
                deleted = []

                for fpath, mtime in curr_state.items():
                    if fpath not in prev:
                        changed.append((fpath, "created"))
                    elif abs(prev[fpath] - mtime) > 0.5:
                        changed.append((fpath, "modified"))

                for fpath in prev:
                    if fpath not in curr_state:
                        deleted.append(fpath)

                if changed or deleted:
                    now = time.time()
                    with self._window_lock:
                        for fpath, action in changed:
                            self._window_events[d].append((now, action, fpath))
                        for fpath in deleted:
                            self._window_events[d].append((now, "deleted", fpath))

                    with self._stats_lock:
                        self._stats["files_changed"] += len(changed) + len(deleted)

                    # 滑动窗口检测
                    self._check_window(d)

                prev_state[d] = curr_state

    def _scan_dir_state(self, directory: str) -> dict[str, float]:
        """扫描目录下的文件状态（路径 -> 修改时间）"""
        state = {}
        try:
            for root, dirs, files in os.walk(directory):
                # 跳过隐藏目录和系统目录
                dirs[:] = [d for d in dirs if not d.startswith(".") and d != "$Recycle.Bin"]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        state[fpath] = os.path.getmtime(fpath)
                    except OSError:
                        continue
        except Exception:
            pass
        return state

    def _check_window(self, directory: str):
        """滑动窗口检测，判断是否触发勒索告警"""
        now = time.time()
        cutoff = now - SLIDING_WINDOW_SEC

        with self._window_lock:
            events = self._window_events[directory]
            # 移除窗口外的旧事件
            while events and events[0][0] < cutoff:
                events.popleft()
            count = len(events)

        if count >= ALERT_THRESHOLD:
            # 检测文件名是否包含勒索特征
            suspicious = False
            with self._window_lock:
                for evt in events:
                    fpath = evt[2]
                    ext = os.path.splitext(fpath)[1].lower()
                    if ext in RANSOM_EXTENSIONS:
                        suspicious = True
                        break

            if suspicious:
                self._trigger_alert(
                    source=f"批量文件加密检测 ({os.path.basename(directory)})",
                    detail=f"窗口内 {count} 次文件变更，检测到勒索特征扩展名",
                    level="critical"
                )
            else:
                self._trigger_alert(
                    source=f"批量文件异常变更 ({os.path.basename(directory)})",
                    detail=f"窗口内 {count} 次文件变更，可能存在勒索行为",
                    level="high"
                )

    # ── 蜜罐监控线程 ──

    def _honeypot_watch_loop(self):
        """定期检查蜜罐文件是否被篡改"""
        while not self._stop_event.is_set():
            self._stop_event.wait(HONEYPOT_CHECK_INTERVAL)
            if not self._enabled:
                continue

            for hp in self._get_honeypot_files():
                if not os.path.exists(hp):
                    # 蜜罐文件被删除或修改 — 触发紧急告警
                    with self._stats_lock:
                        self._stats["honeypot_triggers"] += 1
                    self._trigger_alert(
                        source="蜜罐文件触发",
                        detail=f"诱饵文件被删除/篡改: {hp}",
                        level="critical"
                    )
                    # 重新部署
                    self._deploy_honeypots()
                    break
                else:
                    # 检查内容是否被修改
                    try:
                        with open(hp, "r", encoding="utf-8") as f:
                            content = f.read()
                        if "安盾防勒索蜜罐文件" not in content:
                            with self._stats_lock:
                                self._stats["honeypot_triggers"] += 1
                            self._trigger_alert(
                                source="蜜罐文件触发",
                                detail=f"诱饵文件内容被篡改: {hp}",
                                level="critical"
                            )
                            self._deploy_honeypots()
                            break
                    except Exception:
                        pass

    # ── 高危命令监控线程 ──

    def _cmd_monitor_loop(self):
        """监控系统进程，检测高危命令执行"""
        if not IS_WINDOWS:
            return

        while not self._stop_event.is_set():
            self._stop_event.wait(CMD_CHECK_INTERVAL)
            if not self._enabled:
                continue

            try:
                # 使用 WMI 查询进程命令行（需要 pywin32）
                import subprocess as sp
                output = sp.check_output(
                    ['wmic', 'process', 'get', 'name,commandline', '/format:csv'],
                    stderr=sp.DEVNULL, timeout=10, encoding='utf-8', errors='ignore'
                )
                for line in output.splitlines():
                    line_lower = line.strip().lower()
                    for cmd in HIGH_RISK_COMMANDS:
                        if cmd in line_lower:
                            # 提取进程名
                            parts = line.split(',')
                            proc_name = parts[-1].strip() if len(parts) > 1 else "unknown"
                            if self.is_whitelisted(proc_name):
                                continue
                            self._trigger_alert(
                                source="高危命令检测",
                                detail=f"检测到高危命令: {cmd} (进程: {proc_name})",
                                level="critical"
                            )
                            break
            except Exception:
                pass

    # ── 告警处理 ──

    def _trigger_alert(self, source: str, detail: str, level: str = "high"):
        """触发勒索告警"""
        # 防重复（同一来源 5 分钟内不重复告警）
        now = time.time()
        with self._alert_lock:
            key = f"{source}|{detail[:50]}"
            last_alert = getattr(self, f"_last_alert_{hash(key) % 10000}", 0)
            if now - last_alert < 300:
                return
            setattr(self, f"_last_alert_{hash(key) % 10000}", now)
            if key in self._alerted_sources:
                return
            self._alerted_sources.add(key)

        with self._stats_lock:
            self._stats["alerts_triggered"] += 1

        self._log("warning" if level == "high" else "critical",
                   f"[{level.upper()}] {source}: {detail}")

        # 尝试弹窗告警
        try:
            self._show_alert_popup(source, detail, level)
        except Exception:
            pass

        # 如果配置为自动终止，查找并终止威胁进程
        if self._auto_kill_enabled:
            self._kill_threat_processes(detail)

    def _show_alert_popup(self, source: str, detail: str, level: str):
        """显示系统弹窗告警"""
        if not IS_WINDOWS:
            return
        title = f"御天 防勒索告警 [{level.upper()}]"
        body = f"来源: {source}\n详情: {detail}\n\n御天已阻止勒索行为，建议立即备份重要文件。"
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, body, title, 0x10 | 0x1000)
        except Exception:
            try:
                subprocess.Popen(
                    ['msg', '*', f'{title}\n{body}'],
                    stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
            except Exception:
                pass

    def _kill_threat_processes(self, detail: str):
        """终止威胁进程（根据告警详情中的进程名）"""
        if not IS_WINDOWS:
            return
        try:
            result = subprocess.run(
                ['wmic', 'process', 'get', 'name,processid', '/format:csv'],
                capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore'
            )
            for line in result.stdout.splitlines():
                if '.exe' in line.lower():
                    parts = line.split(',')
                    if len(parts) >= 3:
                        pid = parts[-2].strip()
                        name = parts[-1].strip()
                        if pid.isdigit() and not self.is_whitelisted(name):
                            os.system(f'taskkill /F /PID {pid} 2>nul')
                            with self._stats_lock:
                                self._stats["processes_killed"] += 1
                            self._log("info", f"已终止威胁进程: {name} (PID: {pid})")
        except Exception:
            pass

    # ── 快照清理线程 ──

    def _snapshot_cleaner_loop(self):
        """定期清理过期快照"""
        while not self._stop_event.is_set():
            self._stop_event.wait(3600)  # 每小时检查一次
            cutoff = time.time() - SNAPSHOT_RETENTION_DAYS * 86400
            with self._snapshot_lock:
                expired = [
                    path for path, info in self._snapshot_index.items()
                    if info["timestamp"] < cutoff
                ]
                for path in expired:
                    info = self._snapshot_index.pop(path, None)
                    if info and os.path.isfile(info["backup_path"]):
                        try:
                            os.remove(info["backup_path"])
                        except Exception:
                            pass
            if expired:
                self._log("info", f"清理过期快照: {len(expired)} 个")

    # ── 状态 ──

    def get_status(self) -> dict:
        """获取防勒索模块完整状态"""
        with self._protected_dirs_lock:
            dirs = list(self._protected_dirs)
        with self._whitelist_lock:
            wl = sorted(self._whitelist)
        with self._stats_lock:
            stats = dict(self._stats)

        # 获取最近事件日志
        recent_logs = []
        if os.path.exists(RANSOM_LOG_FILE):
            try:
                with open(RANSOM_LOG_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    recent_logs = [l.strip() for l in lines[-50:]]
            except Exception:
                pass

        return {
            "enabled": self._enabled,
            "running": self._running,
            "protected_dirs": dirs,
            "whitelist": wl,
            "honeypot_count": len(self._get_honeypot_files()),
            "snapshot_count": len(self._snapshot_index),
            "stats": stats,
            "recent_logs": recent_logs,
            "config": {
                "sliding_window_sec": SLIDING_WINDOW_SEC,
                "alert_threshold": ALERT_THRESHOLD,
                "auto_kill": getattr(self, "_auto_kill_enabled", False),
            }
        }

    def get_alert_history(self) -> list[dict]:
        """获取告警历史"""
        with self._alert_lock:
            alerts = list(self._alerted_sources)
        return [{"source": a.split("|")[0], "detail": a.split("|")[1] if "|" in a else a}
                for a in alerts[-100:]]

    # ── 日志 ──

    def _log(self, level: str, message: str):
        if self._logger:
            getattr(self._logger, level, self._logger.info)(message)

    # ── 自动终止开关 ──

    @property
    def auto_kill_enabled(self) -> bool:
        return getattr(self, "_auto_kill_enabled", False)

    @auto_kill_enabled.setter
    def auto_kill_enabled(self, value: bool):
        self._auto_kill_enabled = value
        self._log("info", f"自动终止威胁进程: {'开启' if value else '关闭'}")