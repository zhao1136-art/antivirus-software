"""
御天后端 API 网关 - FastAPI + WebSocket 进度推送
"""
import os
import sys
import asyncio
import json
import time
import traceback
import logging
from logging.handlers import RotatingFileHandler
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, File, UploadFile, Body, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional

# ── 诊断模式引导（打包版 console=False 吞掉 traceback） ──
# 必须放在任何引擎/后端导入之前，否则 config.py 等早导入阶段的崩溃仍无法被捕获。
import threading as _startup_thr
_STARTUP_LOG = os.path.join(
    os.environ.get("LOCALAPPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Local")),
    "Andun", "data", "logs", "startup_traceback.txt"
)

def _log_startup(msg: str):
    """把启动阶段信息写入诊断日志（追加模式）"""
    try:
        os.makedirs(os.path.dirname(_STARTUP_LOG), exist_ok=True)
        with open(_STARTUP_LOG, "a", encoding="utf-8") as _f:
            _f.write(msg + "\n")
    except Exception:
        pass

def _mark(step: str):
    """记录当前执行到的启动步骤，便于定位崩溃位置"""
    _log_startup(f"[STEP] {step}")


# ══════════════════════════════════════════════════════════════════════════
# 界面：Tkinter（ui_tk/）—— 内嵌 WebView2 链路已移除
# ══════════════════════════════════════════════════════════════════════════
# 历史：本程序原先用 pywebview + 内嵌 WebView2 承载 HTML 界面。那条链路要求
#   pythonnet + WebView2 运行时，而且 Python.Runtime.dll / WebView2.Core.dll 的
#   **物理路径**只要落在工作区 H:\Caelire\ 之下，.NET 的 Assembly.LoadFrom /
#   FileLoadException 就会失败（对照实验见 git 历史）。当时是靠把这两个 runtime
#   复制到 %LOCALAPPDATA%\Andun\runtime\pyrt\ 再改 __file__ 指过去绕开的。
#
# 现在界面改为 ui_tk/ 下的 Tkinter 实现（纯标准库，零第三方依赖），因此：
#   · 不再需要 pythonnet / WebView2 / clr_loader
#   · 不再需要 runtime 暂存与 sys.modules 清洗
#   · 不再有 splash 启动画面 —— Tk 窗口自身就是启动流程
# 上述暂存与兜底函数（_stage_pythonnet_runtime / _stage_webview_package /
# _prepare_embedded_browser / _launch_app_window）已全部删除。
# frontend/ 下的 HTML 版界面仍可用 frontend_launcher.py 单独打开做对照。
_UI_STATE = {"window": None, "app": None}


def _show_main_window() -> bool:
    """把 Tk 主窗口重新显示并置前（托盘菜单「显示」用）。

    Tk 不是线程安全的：托盘回调跑在自己的线程里，所以**不能直接**操作
    widget，必须用 ``root.after(0, ...)`` 把动作派发回 Tk 的主线程执行。
    """
    app = _UI_STATE.get("app")
    root = getattr(app, "root", None) if app is not None else None
    if root is None:
        return False

    def _raise():
        try:
            root.deiconify()
        except Exception:
            pass
        try:
            root.lift()
        except Exception:
            pass
        try:
            root.focus_force()
        except Exception:
            pass

    try:
        root.after(0, _raise)
        return True
    except Exception:
        return False

def _startup_excepthook(tp, val, tb):
    _log_startup("=== STARTUP TRACEBACK ===" + "\n" + "".join(traceback.format_exception(tp, val, tb)))
    _log_startup("=== END TRACEBACK ===")
    sys.__excepthook__(tp, val, tb)

sys.excepthook = _startup_excepthook

def _startup_thread_excepthook(args):
    _log_startup("=== THREAD TRACEBACK ===" + "\n" + "".join(
        traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)))

_startup_thr.excepthook = _startup_thread_excepthook

_log_startup(f"=== 御天启动 {time.strftime('%Y-%m-%d %H:%M:%S')} frozen={getattr(sys,'frozen',False)} ===")

# 确保项目根在搜索路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── 持久化存储（启动时加载配置、更新守护天数） ──
from persistence import (
    load_config_save, save_config_save, save_guard_days,
    update_guard_days, cache_cleanup
)
# 更新守护天数（每日首次启动时自动累计）
_guard_data = update_guard_days()
print(f"[御天] 已守护 {_guard_data['accumulated_days']} 天")

from engine.scheduler import Scheduler
from engine.quarantine import QuarantineManager
from engine.signature_manager import get_signature_manager
from engine.report_logger import ReportLogger
from engine.signature_downloader import SignatureDownloader

from engine.ml_scanner import scan_pe as ml_scan_pe

import threading as _thr

# 威胁情报懒加载（启动时不加载，用户首次访问对应 API 时才初始化）
_c2_intel = None
_c2_intel_lock = _thr.Lock()
_threat_intel = None
_threat_intel_lock = _thr.Lock()

def _get_c2_intel():
    global _c2_intel
    if _c2_intel is None:
        with _c2_intel_lock:
            if _c2_intel is None:
                from engine.c2_intel import C2IntelEngine
                _c2_intel = C2IntelEngine()
                _thr.Thread(target=_c2_intel.reload, daemon=True).start()
    return _c2_intel

def _get_threat_intel():
    global _threat_intel
    if _threat_intel is None:
        with _threat_intel_lock:
            if _threat_intel is None:
                from engine.threat_intel import ThreatIntelEngine
                _threat_intel = ThreatIntelEngine()
                _thr.Thread(target=_threat_intel.reload, daemon=True).start()
    return _threat_intel
from engine.system_guard import SystemGuard
from engine.file_guard import FileGuard
from engine.watchdog import get_watchdog
from engine.emergency_kill import EmergencyKillManager
from engine.realtime_guard import RealtimeGuard
from engine.history_manager import get_virus_memory
from engine.tray_icon import TrayIcon
from engine.game_mode import get_game_mode
from engine.usb_scanner import get_usb_scanner
from engine.ransomware_shield import RansomwareShield
from engine.network_repair import NetworkRepair
from engine.adblock import AdBlock
from engine.download_guard import DownloadGuard
from engine.url_guard import UrlGuard
from engine.process_guard import ProcessGuard
from engine.registry_guard import RegistryGuard
from engine.behavior_block import BehaviorBlock
from engine.junk_cleaner import JunkCleaner
from engine.system_optimizer import SystemOptimizer
from engine.vuln_fix import VulnFix
from engine.usb_guard import get_usb_guard
from engine.mail_guard import get_mail_guard

# ---------- 全局实例 ----------
# 引擎版本号（更新时同步修改此处）
ENGINE_VERSION = "1.1.0"
ENGINE_VERSION_NAME = "实时防护修复版"
app = FastAPI(title="御天 Engine API", version=ENGINE_VERSION,
              docs_url=None, redoc_url=None)  # 生产环境关闭 Swagger
# 串行初始化：先建立共享特征库连接（含内存索引），再启动调度器，避免启动并发冲突 / 重复 SigMgr
_mark("串行初始化: get_signature_manager")
try:
    sig_mgr = get_signature_manager()
    _mark("串行初始化: sig_mgr 完成")
    scheduler = Scheduler()  # 内部复用同一个 sig_mgr 共享实例
    _mark("串行初始化: scheduler 完成")
except Exception:
    _log_startup("串行初始化失败:\n" + traceback.format_exc())
    raise
quarantine = QuarantineManager()
logger = ReportLogger()
sig_downloader = SignatureDownloader(sig_mgr)
# 卫士模块：垃圾清理 / 电脑优化（懒加载数据文件，不阻塞启动）
junk_cleaner = JunkCleaner()
system_optimizer = SystemOptimizer()
_mark("串行初始化完成")

# ── 全局异常处理（兜底，防止 500 裸奔） ──
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """全局异常兜底：记录完整堆栈，返回统一错误格式"""
    tb = traceback.format_exc()
    logging.getLogger("yutian").error(
        f"未捕获异常 | {request.method} {request.url.path} | {exc.__class__.__name__}: {exc}\n{tb}"
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_error",
            "message": str(exc) if not _is_production() else "服务器内部错误",
            "type": exc.__class__.__name__,
        },
    )

def _is_production() -> bool:
    """判断是否生产环境（打包模式或无 DEBUG 环境变量）"""
    return getattr(sys, 'frozen', False) or not os.environ.get("YUTIAN_DEBUG")

# ── 日志轮转（RotatingFileHandler，10MB/文件，保留 5 个备份） ──
def _setup_logging():
    """初始化日志轮转：主日志 + 错误日志分别轮转"""
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engine", "data", "logs")
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("yutian")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return  # 已初始化，避免重复

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # 主日志：app.log，10MB/文件，保留 5 个备份
    app_handler = RotatingFileHandler(
        os.path.join(log_dir, "app.log"),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding="utf-8",
    )
    app_handler.setLevel(logging.INFO)
    app_handler.setFormatter(fmt)
    logger.addHandler(app_handler)

    # 错误日志：error.log，单独轮转
    error_handler = RotatingFileHandler(
        os.path.join(log_dir, "error.log"),
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=3,
        encoding="utf-8",
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(fmt)
    logger.addHandler(error_handler)

    # 开发模式下同时输出到控制台
    if not _is_production():
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(fmt)
        logger.addHandler(console)

    logger.info(f"[御天] 引擎版本 {ENGINE_VERSION} ({ENGINE_VERSION_NAME}) 启动")
    return logger

_logger = _setup_logging()

# ── 关键错误告警 ──
def _alert_critical(event: str, detail: str = ""):
    """
    关键错误告警：引擎通信失败、签名库损坏、磁盘空间不足等。
    生产环境写入 error.log 标红，开发环境额外打印到控制台。
    """
    msg = f"[CRITICAL] {event}"
    if detail:
        msg += f" | {detail}"
    logging.getLogger("yutian").error(msg)
    # 磁盘空间不足时额外检查
    if "disk" in event.lower() or "space" in event.lower():
        try:
            import psutil
            du = psutil.disk_usage(os.path.dirname(sig_mgr.db_path))
            if du.percent > 95:
                logging.getLogger("yutian").critical(
                    f"[CRITICAL] 磁盘空间严重不足: {du.percent}% ({du.free / (1024**3):.1f}GB 可用)"
                )
        except Exception:
            pass


# ---------- 本地病毒库自动导入（首次启动，后台线程） ----------
def _auto_import_bingduku():
    try:
        import sqlite3
        import os as _os
        import time
        from config import BINGDUKU_MD5_TXT, BINGDUKU_DAT
        if not BINGDUKU_MD5_TXT or not _os.path.isfile(BINGDUKU_MD5_TXT):
            print("[御天] 本地病毒库文件不存在，跳过自动导入")
            return
        # 用 signature_meta 做幂等标记：bingduku_20260419_imported
        need_import = True
        try:
            conn = sqlite3.connect(sig_mgr.db_path)
            row = conn.execute(
                "SELECT value FROM signature_meta WHERE key='bingduku_20260419_imported'"
            ).fetchone()
            conn.close()
            if row and row[0] == "1":
                # 已导入过，统计一次总数确认
                stats = sig_mgr.get_stats()
                print("[御天] 本地病毒库已导入过，当前特征总数:", stats.get("total_signatures", 0))
                need_import = False
        except Exception:
            need_import = True
        if need_import:
            print("[御天] 首次导入本地病毒库，开始...")
            t0 = time.time()
            result = sig_mgr.import_md5_text(BINGDUKU_MD5_TXT)
            dt = int((time.time() - t0) * 1000)
            # 写入已导入标记
            try:
                conn = sqlite3.connect(sig_mgr.db_path)
                conn.execute(
                    "INSERT OR REPLACE INTO signature_meta (key, value) VALUES (?, ?)",
                    ("bingduku_20260419_imported", "1")
                )
                conn.execute(
                    "INSERT OR REPLACE INTO signature_meta (key, value) VALUES (?, ?)",
                    ("bingduku_dat_path", BINGDUKU_DAT or "")
                )
                conn.commit()
                conn.close()
            except Exception:
                pass
            print("[御天] 本地病毒库导入完成: imported=%s skipped=%s lines=%s duration=%sms" % (
                result.get("imported"), result.get("skipped"),
                result.get("total_lines"), result.get("duration_ms", dt)))
    except Exception as e:
        print("[御天] 本地病毒库导入失败:", e)


_thr.Thread(target=_auto_import_bingduku, daemon=True).start()


# ---------- 火绒内容特征串库后台预热 ----------
# 分片 Aho-Corasick 构建约 10 秒，放后台线程做，避免第一次扫描时阻塞。
def _warmup_huorong_sigs():
    try:
        from engine.huorong_intel import get_content_sig_engine, get_huorong_stats
        get_content_sig_engine().ensure_loaded()   # 本线程内同步构建，完成后统计才准确
        st = get_huorong_stats()
        print("[御天] 火绒情报库就绪: 内容特征串=%s URL黑名单=%s 检测名=%s" % (
            st["content_sigs"].get("literals"), st["url_blocklist"].get("count"),
            st["detection_names"].get("total")))
    except Exception as e:
        print("[御天] 火绒情报库预热失败:", e)


_thr.Thread(target=_warmup_huorong_sigs, daemon=True).start()


# 威胁情报引擎改为懒加载（见上方 _get_c2_intel / _get_threat_intel）

# WebSocket 连接池
ws_connections: dict[str, WebSocket] = {}
MAX_WS_CONNECTIONS = 50
_event_loop = None  # 保存事件循环引用，供跨线程广播使用

# CORS：收紧为仅允许本地同源入口，不再全放行“*”。
# 前端页面由本后端同源托管（API_BASE='' 相对路径），正常访问不受影响；
# 恶意网页跨源调用被 CORS 屏蔽，配合下方令牌中间件形成双重防护。
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8899", "http://localhost:8899"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── 本地控制面鉴权（安全产品自身安全加固） ──
# 修复：后端 API 此前无任何鉴权 + CORS 全放行，用户在浏览器里打开任意恶意网页，
# 其 JS 即可跨源调用 /api/v1/shutdown、/api/v1/response/kill-process、隔离文件等
# 破坏性接口（无法读响应，但副作用照常执行）。现通过“HttpOnly + SameSite=Strict
# 令牌 Cookie”对 /api/* 做鉴权：
#   - 页面访问（同源）时下发令牌 Cookie，浏览器自动携带，正常功能不受影响；
#   - HttpOnly 使恶意 JS 无法读取令牌；SameSite=Strict 使跨站请求不携带 Cookie，
#     配合收紧后的 CORS，恶意页面既写不成也读不到；
#   - 静态资源、健康检查、WebSocket 进度推送免鉴权。
from starlette.middleware.base import BaseHTTPMiddleware
import secrets as _secrets

_LOCAL_TOKEN_COOKIE = "yt_token"
_LOCAL_TOKEN = _secrets.token_urlsafe(32)

class _LocalAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = request.url.path
        # 免鉴权：静态资源 / 健康检查 / WebSocket 进度推送
        if path.startswith("/static/") or path == "/api/health" or path.startswith("/ws/"):
            return await call_next(request)
        # API 接口：校验本地令牌（Cookie / Header / query 三选一）
        if path.startswith("/api/"):
            token = (
                request.cookies.get(_LOCAL_TOKEN_COOKIE)
                or request.headers.get("x-yutian-token")
                or request.query_params.get("token")
            )
            if not token or token != _LOCAL_TOKEN:
                return JSONResponse({"error": "未授权访问：缺少或错误的本地令牌"}, status_code=401)
            return await call_next(request)
        # 页面访问：下发（或续期）令牌 Cookie
        response = await call_next(request)
        try:
            response.set_cookie(
                key=_LOCAL_TOKEN_COOKIE, value=_LOCAL_TOKEN,
                httponly=True, samesite="strict", path="/", max_age=7 * 24 * 3600,
            )
        except Exception:
            pass
        return response

app.add_middleware(_LocalAuthMiddleware)

# 静态文件 - 前端页面
def _get_frontend_dir():
    """获取前端文件目录（兼容开发模式和 PyInstaller 打包模式）"""
    if getattr(sys, 'frozen', False):
        # PyInstaller: 前端文件在 _internal/frontend/
        return os.path.join(sys._MEIPASS, "frontend")
    # 开发模式: backend/frontend/
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")

FRONTEND_DIR = _get_frontend_dir()
if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

# ── 用户协议确认（首次启动弹窗） ──
import json as _json
_AGREEMENT_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) if not getattr(sys, 'frozen', False) else os.path.dirname(sys.executable), "data", "agreement_accepted.json")

def _is_agreement_accepted():
    """检查用户是否已同意协议"""
    try:
        if os.path.isfile(_AGREEMENT_FILE):
            with open(_AGREEMENT_FILE, 'r', encoding='utf-8') as f:
                data = _json.load(f)
                return data.get("accepted", False)
    except Exception:
        pass
    return False

def _save_agreement():
    """保存用户同意协议的状态"""
    os.makedirs(os.path.dirname(_AGREEMENT_FILE), exist_ok=True)
    with open(_AGREEMENT_FILE, 'w', encoding='utf-8') as f:
        _json.dump({"accepted": True, "version": ENGINE_VERSION, "timestamp": __import__('datetime').datetime.now().isoformat()}, f)

# 协议页面路径
_AGREEMENT_PAGE = os.path.join(FRONTEND_DIR, "agreement.html")


# ---------- 请求模型 ----------
class CustomScanRequest(BaseModel):
    paths: list[str]


class ToggleRequest(BaseModel):
    module: str
    enabled: bool


# 防护模块状态（有状态）
_protection_modules = {
    "file_shield": True,
    "network_shield": True,
    "behavior_shield": True,
    "ransomware_shield": True,
    "process_guard": True,
    "file_guard": True
}

# 独立功能开关
_feature_toggles = {
    "auto_start": False,      # 开机自启
    "shell_menu": False,      # 右键菜单
    "game_mode": True,        # 游戏模式（默认开启）
    "usb_scan": True,         # USB 自动扫描（默认开启）
    "tray_icon": True,        # 系统托盘（默认开启）
    "etw_guard": True,        # ETW 事中检测（默认开启，需要 SYSTEM 权限）
    "amsi_provider": True,    # AMSI 无文件拦截（默认开启）
    "adblock": False,          # 弹窗拦截（默认关闭）
    "download_guard": False,   # 下载防护（默认关闭）
    "url_guard": False,        # 网址防护（默认关闭）
    "vuln_fix": False,         # 漏洞修复（默认关闭）
    "process_guard_tool": False, # 进程拦截（默认关闭）
    "registry_guard": False,   # 注册表监控（默认关闭）
    "behavior_block": False,   # 高危行为阻断（默认关闭）
}

# ETW/轮询 运行状态
_etw_state = {"running": False, "events": []}

# 初始化进程保护、文件防篡改引擎和紧急处置
sys_guard = SystemGuard()
file_guard = FileGuard()
watchdog = get_watchdog()
emergency_kill = EmergencyKillManager()
realtime_guard = RealtimeGuard()

# 初始化新增模块
tray_icon = TrayIcon()
game_mode = get_game_mode()
usb_scanner = get_usb_scanner()
ransomware_shield = RansomwareShield()

# 初始化安全工具模块
network_repair = NetworkRepair()
adblock = AdBlock()
download_guard = DownloadGuard()
url_guard = UrlGuard()
vuln_fix = VulnFix()
usb_guard = get_usb_guard()
mail_guard = get_mail_guard(url_checker=url_guard.check_url)
process_guard_tool = ProcessGuard()
registry_guard = RegistryGuard()
behavior_block = BehaviorBlock()

# === 企业级安全功能模块（懒加载代理 — 减少启动内存占用） ===
# 这些模块仅在首次访问时才导入和实例化，避免启动时一次性加载全部模块

class _LazyModule:
    """懒加载代理：首次访问任意属性时触发模块导入和实例化"""
    __slots__ = ('_factory', '_instance', '_lock')

    def __init__(self, factory):
        object.__setattr__(self, '_factory', factory)
        object.__setattr__(self, '_instance', None)
        object.__setattr__(self, '_lock', _thr.Lock())

    def __getattr__(self, name):
        if object.__getattribute__(self, '_instance') is None:
            with object.__getattribute__(self, '_lock'):
                if object.__getattribute__(self, '_instance') is None:
                    object.__setattr__(self, '_instance',
                                        object.__getattribute__(self, '_factory')())
        return getattr(object.__getattribute__(self, '_instance'), name)

    def _get_real(self):
        """获取真实实例（供其他模块工厂函数传递依赖）"""
        if object.__getattribute__(self, '_instance') is None:
            with object.__getattribute__(self, '_lock'):
                if object.__getattribute__(self, '_instance') is None:
                    object.__setattr__(self, '_instance',
                                        object.__getattribute__(self, '_factory')())
        return object.__getattribute__(self, '_instance')


def _make_anti_rootkit():
    from engine.anti_rootkit import get_anti_rootkit
    return get_anti_rootkit()


def _make_custom_rules():
    from engine.custom_rules import get_custom_rules
    return get_custom_rules()


def _make_honeypot():
    from engine.honeypot_manager import get_honeypot_manager
    return get_honeypot_manager()


def _make_browser_guard():
    from engine.browser_guard import get_browser_guard
    return get_browser_guard()


def _make_camera_guard():
    from engine.camera_guard import get_camera_guard
    return get_camera_guard()


def _make_privacy_shield():
    from engine.privacy_shield import get_privacy_shield
    return get_privacy_shield()


def _make_data_recovery():
    from engine.data_recovery import get_data_recovery
    return get_data_recovery()


def _make_sandbox():
    from engine.sandbox import get_sandbox
    return get_sandbox()


def _make_self_protect():
    from engine.self_protect import SelfProtect
    return SelfProtect()


def _make_response_center():
    from engine.response_center import ResponseCenter
    return ResponseCenter()


anti_rootkit = _LazyModule(_make_anti_rootkit)
custom_rules = _LazyModule(_make_custom_rules)
honeypot_manager = _LazyModule(_make_honeypot)
browser_guard = _LazyModule(_make_browser_guard)
camera_guard = _LazyModule(_make_camera_guard)
privacy_shield = _LazyModule(_make_privacy_shield)
data_recovery = _LazyModule(_make_data_recovery)
sandbox = _LazyModule(_make_sandbox)
self_protect = _LazyModule(_make_self_protect)
response_center = _LazyModule(_make_response_center)

# 启动监控
def _start_guards():
    try:
        if _protection_modules.get("process_guard", True):
            sys_guard.start()
        if _protection_modules.get("file_guard", True):
            file_guard.start()
        # 启动后台防掉线守护（默认开启）
        watchdog.start()
        # 启动 F12 紧急处置
        emergency_kill.start()
        # 启动实时文件监控
        # ⚠️ 必须先注入共享 scanner：否则 realtime_guard 会自建一份
        #    LocalScanner + YaraScanner（重复编译 133 条规则、重复打开特征库），
        #    而且它调用的 scan_single 曾经根本不存在（见 local_scanner 里新增的
        #    公开别名）—— 那让实时防护 0 检测且静默。
        try:
            realtime_guard.set_scanner(scheduler.scanner)
            realtime_guard.set_quarantine(quarantine)
        except Exception:
            _log_startup("实时防护注入 scanner 失败:\n" + traceback.format_exc())
        realtime_guard.start()

        # 启动系统托盘
        if _feature_toggles.get("tray_icon", True):
            _init_tray_icon()

        # 启动游戏模式
        if _feature_toggles.get("game_mode", True):
            _init_game_mode()

        # 启动 USB 自动扫描
        if _feature_toggles.get("usb_scan", True):
            _init_usb_scanner()

        # 启动 ETW 事中检测（升级一）
        if _feature_toggles.get("etw_guard", True):
            _init_etw_guard()

    except Exception:
        pass



def _init_etw_guard():
    """初始化 ETW 事中检测（含轮询降频逻辑）"""
    global _etw_state
    try:
        from engine.native_guard_bridge import get_native_guard
        guard = get_native_guard()
        if not guard:
            return

        # 启动 ETW（失败会自动回退轮询兜底）
        result = guard.etw_start()
        if result and result.get("success"):
            _etw_state["running"] = True
            print("[ETW] 事中检测已启动（轮询自动降频）")
            # P1: ETW 可用 → 降低轮询频率（兜底第二层，接口不存在则忽略）
            try:
                if hasattr(sys_guard, 'set_scan_interval'):
                    sys_guard.set_scan_interval(10)
            except Exception:
                pass
        else:
            print(f"[ETW] 未启动（{result.get('error', '未知') if result else 'DLL 不可用'}），保持轮询兜底")
    except Exception as e:
        print(f"[ETW] 初始化异常: {e}")


# ---------- 新增模块初始化 ----------

def _init_tray_icon():
    """初始化系统托盘"""
    try:
        def on_show():
            """唤起 Tk 主窗口。

            不再兜底去开系统浏览器 —— 界面就在本进程内，开浏览器只会多出一个
            重复的 HTML 页面，反而不清楚哪个在生效。
            """
            if _show_main_window():
                print("[御天] 已唤起 Tk 界面")
            else:
                print("[御天] Tk 界面未就绪，无法唤起")

        def on_exit():
            """退出程序（Logo 淡出 + 资源释放 + 进程退出）"""
            import threading
            # 诊断：后端一整天在"自己消失"，日志只有 [御天] 再见、没有任何 HTTP
            # 请求痕迹。_do_exit_with_fadeout 跑在独立线程里，它自己的调用栈
            # 看不到是谁起的线程 —— 所以必须在**启动线程的地方**留痕。
            print("[御天][诊断] 退出触发点 = 托盘图标菜单 on_exit")
            threading.Thread(target=_do_exit_with_fadeout, daemon=True).start()

        tray_icon.set_callbacks(on_show=on_show, on_exit=on_exit)
        tray_icon.start()
    except Exception:
        pass


def _init_game_mode():
    """初始化游戏模式"""
    try:
        def on_game_start(window):
            # 进入游戏 → 降低扫描优先级
            scheduler.set_priority("low")
            realtime_guard.set_priority("low")

        def on_game_end():
            # 退出游戏 → 恢复
            scheduler.set_priority("normal")
            realtime_guard.set_priority("normal")

        game_mode.set_callbacks(on_game_start=on_game_start, on_game_end=on_game_end)
        game_mode.start()
    except Exception:
        pass


def _init_usb_scanner():
    """初始化 USB 自动扫描"""
    try:
        def scan_usb(drive):
            """扫描 USB 驱动器"""
            from engine.local_scanner import LocalScanner
            scanner = LocalScanner()
            result = scanner.scan_path(drive)
            # 通知前端
            threats = result.get("infected", []) or result.get("threats", [])
            if threats:
                from engine.report_logger import log_threat
                for t in threats:
                    log_threat(f"[USB] {drive}: {t}")
                # 通知前端（通过日志持久化，前端 logs.html 读取）
            return result

        usb_scanner.set_callbacks(scan_callback=scan_usb)
        usb_scanner.start()
    except Exception:
        pass


_thr.Thread(target=_start_guards, daemon=True).start()

# ---------- 通用可取消异步任务（清理/体检/优化/恢复/沙箱/漏洞等复用） ----------
#
# 背景：体检、一键优化、清理执行、沙箱分析等端点内部是同步阻塞调用，前端只能
# await 整个 HTTP 响应，期间没有任何取消通路。这里提供统一的可取消任务封装：
#   POST /api/v1/jobs                    创建任务（body: {kind, params}）
#   GET  /api/v1/jobs/{task_id}/status   查询进度 / 状态 / 结果
#   POST /api/v1/jobs/{task_id}/cancel   取消（协作式）
# 取消是真取消：各 engine 对应方法接受 cancel 令牌，在主循环检查点退出，
# 而不是只改前端状态、后端继续闷头跑。

class _CancelToken:
    """协作式取消令牌（同时兼容 is_cancelled() 与 threading.Event 的 is_set()）"""

    __slots__ = ("_event",)

    def __init__(self):
        self._event = _thr.Event()

    def cancel(self):
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def is_set(self) -> bool:
        return self._event.is_set()

    def set(self):
        self._event.set()

    def clear(self):
        self._event.clear()

    def wait(self, timeout=None) -> bool:
        return self._event.wait(timeout)


class _AsyncJob:
    """通用异步任务记录（字段与 ScanTask / CleanTask 对齐，前端可复用同一套渲染）"""

    def __init__(self, task_id: str, kind: str, params: dict = None):
        self.task_id = task_id
        self.kind = kind
        self.params = params or {}
        self.status = "queued"   # queued | running | completed | cancelled | failed
        self.progress = 0
        self.current = ""
        self.result = None
        self.error = None
        self.cancelled = False
        self.created_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.completed_at = None
        self._created_ts = time.time()
        self._completed_ts = 0.0
        self.token = _CancelToken()

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "kind": self.kind,
            "status": self.status,
            "progress": self.progress,
            "current": self.current,
            "result": self.result,
            "error": self.error,
            "cancelled": bool(self.cancelled or self.token.is_cancelled()),
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


class _AsyncJobRegistry:
    """通用异步任务登记表：独立线程执行 + 协作式取消 + TTL/容量清理"""

    TTL_SECONDS = 3600
    MAX_JOBS = 200

    def __init__(self):
        self._jobs: dict = {}
        self._lock = _thr.Lock()

    def _cleanup_locked(self):
        now = time.time()
        for tid, job in list(self._jobs.items()):
            if job._completed_ts and now - job._completed_ts > self.TTL_SECONDS:
                self._jobs.pop(tid, None)
        if len(self._jobs) >= self.MAX_JOBS:
            finished = sorted(
                (j for j in self._jobs.values() if j._completed_ts > 0),
                key=lambda j: j._completed_ts,
            )
            drop = max(1, len(finished) - self.MAX_JOBS // 2)
            for j in finished[:drop]:
                self._jobs.pop(j.task_id, None)

    def submit(self, kind: str, runner, params: dict = None) -> _AsyncJob:
        """runner(token, report) -> result；report(progress, current) 上报进度"""
        job = _AsyncJob("job_" + os.urandom(4).hex(), kind, params)
        with self._lock:
            self._cleanup_locked()
            self._jobs[job.task_id] = job

        def _report(progress=None, current=None):
            if progress is not None:
                try:
                    job.progress = max(0, min(100, int(progress)))
                except (TypeError, ValueError):
                    pass
            if current is not None:
                job.current = str(current)

        def _run():
            job.status = "running"
            try:
                result = runner(job.token, _report)
                if job.token.is_cancelled():
                    job.status = "cancelled"
                    job.cancelled = True
                    if result is not None:
                        job.result = result
                else:
                    job.result = result
                    job.status = "completed"
                    job.progress = 100
            except Exception as e:
                if job.token.is_cancelled():
                    job.status = "cancelled"
                    job.cancelled = True
                else:
                    job.status = "failed"
                    job.error = str(e)
            finally:
                job.completed_at = time.strftime("%Y-%m-%dT%H:%M:%S")
                job._completed_ts = time.time()

        _thr.Thread(target=_run, daemon=True, name="yutian-job-" + str(kind)).start()
        return job

    def get(self, task_id: str):
        return self._jobs.get(task_id)

    def cancel(self, task_id: str) -> bool:
        job = self._jobs.get(task_id)
        if not job or job.status not in ("queued", "running"):
            return False
        job.token.cancel()
        job.cancelled = True
        if job.status == "queued":
            job.status = "cancelled"
            job.completed_at = time.strftime("%Y-%m-%dT%H:%M:%S")
            job._completed_ts = time.time()
        return True


_jobs = _AsyncJobRegistry()


class JobCreateRequest(BaseModel):
    """通用异步任务创建请求"""

    kind: str
    params: Optional[dict] = None


def _job_clean_execute(token, report, params: dict):
    """清理执行（可取消）：删除白名单分类下的垃圾文件"""
    ids = params.get("category_ids") or []
    report(3, "正在清理选中分类")
    return junk_cleaner.execute_clean(
        ids, cancel=token,
        progress_callback=lambda p, c: report(3 + int((p or 0) * 0.95), c),
    )


def _job_optimize_overview(token, report, params: dict):
    """系统体检（可取消）"""
    report(20, "正在检查磁盘与内存")
    return system_optimizer.overview(cancel=token)


def _job_optimize_one_click(token, report, params: dict):
    """一键优化（可取消）"""
    report(10, "正在清理临时文件")
    return system_optimizer.one_click(cancel=token)


def _job_optimize_memory(token, report, params: dict):
    """内存释放（可取消）"""
    report(10, "正在收缩进程工作集")
    return system_optimizer.release_memory(cancel=token)


def _job_recovery_restore(token, report, params: dict):
    """版本恢复（可取消，分块复制）"""
    ok = data_recovery.restore_version(
        params.get("file_path", ""), params.get("version_id", ""),
        cancel=token,
        progress_callback=lambda p, c: report(p, c),
    )
    return {"ok": bool(ok), "cancelled": token.is_cancelled()}


def _job_sandbox_analyze(token, report, params: dict):
    """沙箱分析（可取消：立即终止受限进程）"""
    report(5, "正在启动受限沙箱")
    timeout = params.get("timeout") or 30
    try:
        timeout = int(timeout)
    except (TypeError, ValueError):
        timeout = 30
    return sandbox.analyze_file(params.get("file_path", ""), timeout, cancel=token)


def _job_vulnfix_scan(token, report, params: dict):
    """漏洞扫描（可取消）"""
    report(30, "正在枚举已安装补丁")
    return vuln_fix.scan(cancel=token)


def _job_rootkit_scan(token, report, params: dict):
    """反 Rootkit 扫描（可取消：阶段边界 + 枚举循环）"""
    report(10, "正在检测隐藏进程/驱动/钩子")
    return anti_rootkit.scan(cancel=token)


_JOB_HANDLERS = {
    "clean-execute": _job_clean_execute,
    "optimize-overview": _job_optimize_overview,
    "optimize-one-click": _job_optimize_one_click,
    "optimize-memory": _job_optimize_memory,
    "recovery-restore": _job_recovery_restore,
    "sandbox-analyze": _job_sandbox_analyze,
    "vulnfix-scan": _job_vulnfix_scan,
    "rootkit-scan": _job_rootkit_scan,
}


@app.post("/api/v1/jobs")
async def jobs_create(req: JobCreateRequest):
    """创建通用可取消异步任务"""
    handler = _JOB_HANDLERS.get(req.kind)
    if handler is None:
        return JSONResponse({"error": f"未知任务类型: {req.kind}"}, 400)
    params = req.params or {}
    job = _jobs.submit(
        req.kind,
        lambda token, report: handler(token, report, params),
        params,
    )
    return {"task_id": job.task_id, "kind": job.kind, "status": job.status}


@app.get("/api/v1/jobs/{task_id}/status")
async def jobs_status(task_id: str):
    """查询通用异步任务状态"""
    job = _jobs.get(task_id)
    if not job:
        return JSONResponse({"error": "任务不存在"}, 404)
    return job.to_dict()


@app.post("/api/v1/jobs/{task_id}/cancel")
async def jobs_cancel(task_id: str):
    """取消通用异步任务（协作式，任务体在检查点退出）"""
    if not _jobs.cancel(task_id):
        return JSONResponse({"error": "任务不存在或已结束"}, 400)
    return {"task_id": task_id, "status": "cancelled"}


# ---------- 扫描 API ----------

@app.post("/api/v1/scan/quick")
async def scan_quick():
    """快速扫描"""
    task = scheduler.create_task("quick")
    scheduler.run_task(task.task_id, progress_callback=broadcast_progress)
    return {"task_id": task.task_id, "scan_type": "quick", "status": task.status}


@app.post("/api/v1/scan/full")
async def scan_full():
    """全盘扫描"""
    task = scheduler.create_task("full")
    scheduler.run_task(task.task_id, progress_callback=broadcast_progress)
    return {"task_id": task.task_id, "scan_type": "full", "status": task.status}


@app.post("/api/v1/scan/custom")
async def scan_custom(req: CustomScanRequest):
    """自定义扫描"""
    task = scheduler.create_task("custom", req.paths)
    scheduler.run_task(task.task_id, progress_callback=broadcast_progress)
    return {"task_id": task.task_id, "scan_type": "custom", "status": task.status}


@app.get("/api/v1/scan/{task_id}/status")
async def scan_status(task_id: str):
    """查询扫描任务状态"""
    task = scheduler.get_task(task_id)
    if not task:
        return JSONResponse({"error": "任务不存在"}, 404)
    return task.to_dict()


@app.get("/api/v1/scan/{task_id}/report")
async def scan_report(task_id: str):
    """获取扫描报告"""
    task = scheduler.get_task(task_id)
    if not task:
        return JSONResponse({"error": "任务不存在"}, 404)
    return task.to_dict()


# ---------- 威胁处置决策 API ----------
# 2026-10-03：不再"YARA 命中即自动隔离"。命中后挂起为待决项、通报给用户，
# 由用户决定；DECISION_TIMEOUT 秒内没有决定则自动处理（默认隔离），
# 以保证无人值守时防护不失效。系统目录的文件在此之前已被二次复核
# （threat_decision.second_opinion，不使用 YARA）拦下，不会走到这里。

class ThreatDecideRequest(BaseModel):
    action: str          # "quarantine" | "ignore"


@app.get("/api/v1/threats/pending")
async def threats_pending():
    """当前等待用户决定的威胁（前端据此显示倒计时）"""
    from engine.threat_decision import QUEUE, DECISION_TIMEOUT
    return {
        "pending": QUEUE.list_pending(),
        "timeout": DECISION_TIMEOUT,
        "stats": QUEUE.stats,
    }


@app.post("/api/v1/threats/{pending_id}/decide")
async def threats_decide(pending_id: str, req: ThreatDecideRequest):
    """用户对待决威胁作出决定。超时后再调用返回 ok=False（已自动处理）。"""
    from engine.threat_decision import QUEUE
    ok = QUEUE.decide(pending_id, (req.action or "").strip().lower())
    return {"ok": ok, "id": pending_id, "action": req.action, "stats": QUEUE.stats}


@app.post("/api/v1/scan/{task_id}/cancel")
async def scan_cancel(task_id: str):
    """取消扫描任务"""
    ok = scheduler.cancel_task(task_id)
    if not ok:
        return JSONResponse({"error": "无法取消该任务"}, 400)
    return {"task_id": task_id, "status": "cancelled"}


@app.get("/api/v1/scan/perf-stats")
async def scan_perf_stats():
    """获取扫描引擎性能统计"""
    try:
        stats = scheduler.scanner.get_perf_stats()
        # 实时监控事件背压队列水位（有界队列深度/丢弃计数）
        try:
            stats["realtime_queue"] = realtime_guard.get_queue_stats()
        except Exception:
            stats["realtime_queue"] = None
        # 添加 YARA 索引信息
        yara_info = {
            "total_rules": len(scheduler.yara.rules) if scheduler.yara else 0,
            "pe_rules": len(scheduler.yara._rules_pe) if scheduler.yara else 0,
            "elf_rules": len(scheduler.yara._rules_elf) if scheduler.yara else 0,
            "generic_rules": len(scheduler.yara._rules_generic) if scheduler.yara else 0,
        }
        stats["yara"] = yara_info
        # ⚠️ 这里原来直接写裸名 MAX_WORKERS / MAX_FILE_SIZE —— 但那两个名字定义在
        #    config.py（第 175 / 184 行），app.py 只有选择性导入（from config import
        #    QUARANTINE_DIR 之类）、**没有 star import**，所以它们是未定义名：
        #    抛 NameError → 被本函数的 except 吞掉 → 整个接口恒定返回 500。
        #    表现为 /api/v1/scan/perf-stats 的 yara / realtime_queue / config 全部拿不到。
        import config as _cfg
        stats["config"] = {
            "max_workers": _cfg.MAX_WORKERS,
            "max_file_size_mb": _cfg.MAX_FILE_SIZE // (1024 * 1024),
            "buffer_limit_mb": 32,
            "cache_size": 512,
            "cache_ttl_seconds": 300,
        }
        return stats
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# ---------- 实时保护 API ----------

@app.get("/api/v1/protection/status")
async def protection_status():
    """防护模块状态"""
    return {
        "modules": _protection_modules,
        "realtime_enabled": any(_protection_modules.values())
    }


@app.post("/api/v1/protection/toggle")
async def protection_toggle(req: ToggleRequest):
    """切换防护模块"""
    if req.module in _protection_modules:
        _protection_modules[req.module] = req.enabled
        # 处理进程保护和文件防篡改的启停
        if req.module == "process_guard":
            if req.enabled:
                sys_guard.enable()
            else:
                sys_guard.disable()
        elif req.module == "file_guard":
            if req.enabled:
                file_guard.enable()
            else:
                file_guard.disable()
        elif req.module == "ransomware_shield":
            if req.enabled:
                ransomware_shield.enable()
            else:
                ransomware_shield.disable()
    return {"module": req.module, "enabled": req.enabled}


# ---------- 防勒索 API ----------

@app.get("/api/v1/ransomware/status")
async def ransomware_status():
    """防勒索模块状态"""
    return ransomware_shield.get_status()


@app.post("/api/v1/ransomware/auto-kill")
async def ransomware_auto_kill(req: ToggleRequest):
    """切换自动终止威胁进程"""
    ransomware_shield.auto_kill_enabled = req.enabled
    return {"enabled": req.enabled}


@app.get("/api/v1/ransomware/backups")
async def ransomware_backups():
    """获取快照备份列表"""
    return {"backups": ransomware_shield.get_snapshot_backups()}


@app.post("/api/v1/ransomware/restore")
async def ransomware_restore(req: dict):
    """从快照恢复文件"""
    path = req.get("path", "")
    if not path:
        return {"success": False, "error": "缺少 path 参数"}
    ok = ransomware_shield.restore_file(path)
    return {"success": ok}


@app.post("/api/v1/ransomware/protected-dir/add")
async def ransomware_add_dir(req: dict):
    """添加保护目录"""
    path = req.get("path", "")
    if not path:
        return {"success": False, "error": "缺少 path 参数"}
    ok = ransomware_shield.add_protected_dir(path)
    return {"success": ok}


@app.post("/api/v1/ransomware/protected-dir/remove")
async def ransomware_remove_dir(req: dict):
    """移除保护目录"""
    path = req.get("path", "")
    if not path:
        return {"success": False, "error": "缺少 path 参数"}
    ok = ransomware_shield.remove_protected_dir(path)
    return {"success": ok}


@app.post("/api/v1/ransomware/whitelist/add")
async def ransomware_add_whitelist(req: dict):
    """添加白名单进程"""
    name = req.get("name", "")
    if not name:
        return {"success": False, "error": "缺少 name 参数"}
    ransomware_shield.add_whitelist(name)
    return {"success": True}


@app.post("/api/v1/ransomware/whitelist/remove")
async def ransomware_remove_whitelist(req: dict):
    """移除白名单进程"""
    name = req.get("name", "")
    ok = ransomware_shield.remove_whitelist(name)
    return {"success": ok}


# ---------- 开机自启 API ----------

@app.get("/api/v1/auto-start/status")
async def auto_start_status():
    """开机自启状态"""
    try:
        from engine.auto_start import status
        return status()
    except Exception as e:
        return {"enabled": False, "error": str(e)}


@app.post("/api/v1/auto-start/toggle")
async def auto_start_toggle():
    """切换开机自启"""
    try:
        from engine.auto_start import toggle
        result = toggle()
        _feature_toggles["auto_start"] = result.get("enabled", False)
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------- 右键菜单 API ----------

@app.get("/api/v1/shell-menu/status")
async def shell_menu_status():
    """右键菜单状态"""
    try:
        from engine.shell_integration import status
        return status()
    except Exception as e:
        return {"registered": False, "error": str(e)}


@app.post("/api/v1/shell-menu/register")
async def shell_menu_register():
    """注册右键菜单"""
    try:
        from engine.shell_integration import register
        ok = register()
        _feature_toggles["shell_menu"] = ok
        return {"success": ok}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/v1/shell-menu/unregister")
async def shell_menu_unregister():
    """移除右键菜单"""
    try:
        from engine.shell_integration import unregister
        ok = unregister()
        _feature_toggles["shell_menu"] = False
        return {"success": ok}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------- 游戏模式 API ----------

@app.get("/api/v1/game-mode/status")
async def game_mode_status():
    """游戏模式状态"""
    try:
        status = game_mode.check_now()
        status["enabled"] = _feature_toggles.get("game_mode", True)
        return status
    except Exception as e:
        return {"in_game": False, "enabled": False, "error": str(e)}


@app.post("/api/v1/game-mode/toggle")
async def game_mode_toggle():
    """切换游戏模式"""
    _feature_toggles["game_mode"] = not _feature_toggles.get("game_mode", True)
    if _feature_toggles["game_mode"]:
        game_mode.start()
    else:
        game_mode.stop()
    return {"enabled": _feature_toggles["game_mode"]}


# ---------- USB 自动扫描 API ----------

@app.get("/api/v1/usb-scan/status")
async def usb_scan_status():
    """USB 自动扫描状态"""
    try:
        current_drives = usb_scanner._get_removable_drives() if hasattr(usb_scanner, '_get_removable_drives') else []
        return {
            "enabled": _feature_toggles.get("usb_scan", True),
            "device_count": len(current_drives),
            "drives": current_drives,
        }
    except Exception as e:
        return {"enabled": False, "error": str(e)}


@app.post("/api/v1/usb-scan/toggle")
async def usb_scan_toggle():
    """切换 USB 自动扫描"""
    _feature_toggles["usb_scan"] = not _feature_toggles.get("usb_scan", True)
    if _feature_toggles["usb_scan"]:
        _init_usb_scanner()
    else:
        usb_scanner.stop()
    return {"enabled": _feature_toggles["usb_scan"]}


# ---------- U盘免疫与外设管控 API ----------

@app.get("/api/v1/usb-guard/status")
async def usb_guard_status():
    """U盘免疫与外设管控状态"""
    return usb_guard.get_status()

@app.post("/api/v1/usb-guard/immunize")
async def usb_guard_immunize(data: dict = None):
    """对指定盘符（可空=全部可移动盘）执行免疫"""
    data = data or {}
    return usb_guard.immunize(data.get("drive"))

@app.post("/api/v1/usb-guard/autorun")
async def usb_guard_autorun(data: dict):
    """启用/禁用自动播放"""
    return usb_guard.set_autorun(bool(data.get("enabled", False)))

@app.post("/api/v1/usb-guard/usb-storage")
async def usb_guard_usb_storage(data: dict):
    """启用/禁用 USB 存储设备（外设管控，需管理员）"""
    return usb_guard.set_usb_storage(bool(data.get("enabled", False)))


# ---------- 邮件防护 API ----------

@app.post("/api/v1/mail-guard/scan-text")
async def mail_guard_scan_text(data: dict):
    """检测邮件正文/来源文本"""
    return mail_guard.scan_text(
        str(data.get("text", "")),
        display_name=str(data.get("display_name", "")),
        domain=str(data.get("domain", "")),
    )

@app.post("/api/v1/mail-guard/scan-urls")
async def mail_guard_scan_urls(data: dict):
    """批量检测 URL 列表"""
    return mail_guard.scan_urls(data.get("urls") or [])

@app.get("/api/v1/mail-guard/status")
async def mail_guard_status():
    """邮件防护状态"""
    return mail_guard.get_status()


# ---------- 系统托盘 API ----------

@app.get("/api/v1/tray-icon/status")
async def tray_icon_status():
    """系统托盘状态"""
    return {"enabled": _feature_toggles.get("tray_icon", True)}


@app.post("/api/v1/tray-icon/toggle")
async def tray_icon_toggle():
    """切换系统托盘"""
    _feature_toggles["tray_icon"] = not _feature_toggles.get("tray_icon", True)
    if _feature_toggles["tray_icon"]:
        _init_tray_icon()
    else:
        tray_icon.stop()
    return {"enabled": _feature_toggles["tray_icon"]}


# ---------- 全部功能状态汇总 API ----------

@app.get("/api/v1/features/status")
async def features_status():
    """获取所有辅助功能状态"""
    try:
        from engine.auto_start import status as auto_start_status
        from engine.shell_integration import status as shell_status
        as_status = auto_start_status()
        sm_status = shell_status()
    except Exception:
        as_status = {"enabled": False}
        sm_status = {"registered": False}

    gm = game_mode.check_now()

    # ETW 状态
    etw_state = {"enabled": _feature_toggles.get("etw_guard", True), "running": _etw_state.get("running", False)}

    # AMSI 状态
    try:
        import subprocess, sys
        amsi_ok = False
        try:
            from amsi_manager import status as amsi_status
            amsi_ok = amsi_status().get("registered", False)
        except Exception:
            pass
    except Exception:
        amsi_ok = False

    return {
        "auto_start": {"enabled": as_status.get("enabled", False)},
        "shell_menu": {"registered": sm_status.get("registered", False)},
        "game_mode": {"enabled": _feature_toggles.get("game_mode", True), "in_game": gm.get("in_game", False)},
        "usb_scan": {"enabled": _feature_toggles.get("usb_scan", True)},
        "tray_icon": {"enabled": _feature_toggles.get("tray_icon", True)},
        "etw_guard": etw_state,
        "amsi_provider": {"enabled": _feature_toggles.get("amsi_provider", True), "registered": amsi_ok},
    }


# ---------- ETW 事中检测 API ----------

@app.post("/api/v1/etw/start")
async def etw_start():
    """启动 ETW 事中检测"""
    global _etw_state
    try:
        from engine.native_guard_bridge import get_native_guard
        guard = get_native_guard()
        if not guard:
            return {"success": False, "error": "native_guard.dll 不可用"}
        result = guard.etw_start()
        if result and result.get("success"):
            _etw_state["running"] = True
        else:
            _etw_state["running"] = False
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/v1/etw/stop")
async def etw_stop():
    """停止 ETW 检测"""
    global _etw_state
    try:
        from engine.native_guard_bridge import get_native_guard
        guard = get_native_guard()
        if not guard:
            return {"success": False, "error": "native_guard.dll 不可用"}
        result = guard.etw_stop()
        _etw_state["running"] = False
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/v1/etw/status")
async def etw_status():
    """ETW 状态"""
    try:
        from engine.native_guard_bridge import get_native_guard
        guard = get_native_guard()
        if not guard:
            return {"running": False, "error": "dll unavailable"}
        result = guard.etw_status()
        result["running"] = result.get("running", False) or _etw_state.get("running", False)
        return result
    except Exception as e:
        return {"running": False, "error": str(e)}


@app.get("/api/v1/etw/events")
async def etw_events():
    """获取 ETW 捕获的可疑事件（获取后清空）"""
    try:
        from engine.native_guard_bridge import get_native_guard
        guard = get_native_guard()
        if not guard:
            return {"events": []}
        result = guard.etw_get_events()
        events = result.get("events", []) if result else []
        _etw_state["events"] = events
        # 有事件时记录到威胁日志
        if events:
            try:
                from engine.report_logger import log_threat
                for ev in events:
                    log_threat(f"[ETW] event_id={ev.get('event_id')} src={ev.get('source_pid')} -> dst={ev.get('target_pid')}")
            except Exception:
                pass
        return {"events": events, "total": len(events)}
    except Exception as e:
        return {"events": [], "error": str(e)}


@app.get("/api/v1/etw/correlations")
async def etw_correlations():
    """事件关联引擎：获取攻击链事件（获取后清空）"""
    try:
        from engine.native_guard_bridge import get_native_guard
        guard = get_native_guard()
        if not guard:
            return {"correlations": []}
        result = guard.etw_get_correlations()
        corrs = result.get("correlations", []) if result else []
        if corrs:
            try:
                from engine.report_logger import log_threat
                for c in corrs:
                    log_threat(f"[ETW-链] {c.get('chain')} severity={c.get('severity')} pid={c.get('pid')} {c.get('name', '')}")
            except Exception:
                pass
        return {"correlations": corrs, "total": len(corrs)}
    except Exception as e:
        return {"correlations": [], "error": str(e)}


@app.get("/api/v1/etw/process-tree")
async def etw_process_tree(top: int = 20):
    """进程树行为评分：输出风险分最高的进程及子树聚合分"""
    try:
        from engine.native_guard_bridge import get_native_guard
        guard = get_native_guard()
        if not guard:
            return {"processes": [], "total": 0}
        return guard.etw_process_tree(top)
    except Exception as e:
        return {"processes": [], "error": str(e)}


@app.get("/api/v1/etw/health")
async def etw_health():
    """Provider 健康监控：会话存活 + 事件流动（自保护）"""
    try:
        from engine.native_guard_bridge import get_native_guard
        guard = get_native_guard()
        if not guard:
            return {"running": False, "session_active": False, "error": "dll unavailable"}
        return guard.etw_health()
    except Exception as e:
        return {"running": False, "error": str(e)}


@app.get("/api/v1/etw/scan-tamper")
async def etw_scan_tamper():
    """篡改扫描：AMSI Inline Hook + ETW 自身防篡改 + 会话存活"""
    try:
        from engine.native_guard_bridge import get_native_guard
        guard = get_native_guard()
        if not guard:
            return {"amsi": None, "etw": None, "error": "dll unavailable"}
        amsi = guard.scan_amsi_tamper()
        etw = guard.scan_etw_tamper()
        return {"amsi": amsi, "etw": etw}
    except Exception as e:
        return {"amsi": None, "etw": None, "error": str(e)}


# ---------- AMSI Provider API ----------

@app.get("/api/v1/amsi/status")
async def amsi_status():
    """AMSI Provider 状态"""
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from amsi_manager import status as _amsi_status
        result = _amsi_status()
        result["enabled"] = _feature_toggles.get("amsi_provider", True)
        return result
    except Exception as e:
        return {"registered": False, "error": str(e)}


@app.post("/api/v1/amsi/register")
async def amsi_register():
    """注册 AMSI Provider"""
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from amsi_manager import register as _amsi_register
        return _amsi_register()
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/v1/amsi/unregister")
async def amsi_unregister():
    """注销 AMSI Provider"""
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from amsi_manager import unregister as _amsi_unregister
        return _amsi_unregister()
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------- 系统进程保护 API ----------

@app.get("/api/v1/system-guard/status")
async def sys_guard_status():
    """进程保护状态"""
    return sys_guard.get_status()


@app.get("/api/v1/system-guard/protected")
async def sys_guard_list_protected():
    """列出受保护进程"""
    return {"processes": sys_guard.list_protected()}


@app.post("/api/v1/system-guard/protected/add")
async def sys_guard_add_protected(data: dict):
    """添加受保护进程"""
    name = data.get("name", "")
    return sys_guard.add_protected(name)


@app.post("/api/v1/system-guard/protected/remove")
async def sys_guard_remove_protected(data: dict):
    """移除受保护进程"""
    name = data.get("name", "")
    return sys_guard.remove_protected(name)


@app.get("/api/v1/system-guard/events")
async def sys_guard_events(limit: int = 50):
    """获取进程保护事件"""
    return {"events": sys_guard.get_events(limit)}


@app.get("/api/v1/system-guard/processes")
async def sys_guard_processes():
    """获取当前进程列表"""
    procs = sys_guard.get_process_list()
    # 附加保护状态
    for p in procs:
        p["is_protected"] = p["name"] in sys_guard._protected_processes
    return {"total": len(procs), "processes": procs}


@app.post("/api/v1/system-guard/scan")
async def sys_guard_scan(data: dict):
    """扫描单个进程"""
    pid = data.get("pid", 0)
    if not pid:
        return JSONResponse({"error": "请提供 PID"}, 400)
    return sys_guard.scan_process(int(pid))


@app.post("/api/v1/system-guard/baseline")
async def sys_guard_baseline():
    """重建进程基线"""
    sys_guard._build_baseline()
    return {"success": True, "message": "进程基线已重建"}


# ---------- 文件防篡改 API ----------

@app.get("/api/v1/file-guard/status")
async def file_guard_status():
    """文件防篡改状态"""
    return file_guard.get_status()


@app.get("/api/v1/file-guard/protected")
async def file_guard_list_protected():
    """列出受保护文件"""
    return file_guard.list_protected()


@app.post("/api/v1/file-guard/file/add")
async def file_guard_add_file(data: dict):
    """添加受保护文件"""
    path = data.get("path", "")
    return file_guard.add_file(path)


@app.post("/api/v1/file-guard/file/remove")
async def file_guard_remove_file(data: dict):
    """移除受保护文件"""
    path = data.get("path", "")
    return file_guard.remove_file(path)


@app.post("/api/v1/file-guard/dir/add")
async def file_guard_add_dir(data: dict):
    """添加受保护目录"""
    path = data.get("path", "")
    return file_guard.add_dir(path)


@app.post("/api/v1/file-guard/dir/remove")
async def file_guard_remove_dir(data: dict):
    """移除受保护目录"""
    path = data.get("path", "")
    return file_guard.remove_dir(path)


@app.get("/api/v1/file-guard/events")
async def file_guard_events(limit: int = 50):
    """获取文件保护事件"""
    return {"events": file_guard.get_events(limit)}


@app.post("/api/v1/file-guard/verify")
async def file_guard_verify(data: dict):
    """验证单个文件完整性"""
    path = data.get("path", "")
    if not path:
        return JSONResponse({"error": "请提供文件路径"}, 400)
    return file_guard.verify_file(path)


@app.post("/api/v1/file-guard/baseline")
async def file_guard_baseline():
    """重建文件基线"""
    return file_guard.build_baseline()


@app.post("/api/v1/file-guard/rebaseline")
async def file_guard_rebaseline(data: dict):
    """重建单个文件基线"""
    path = data.get("path", "")
    return file_guard.rebaseline_file(path)


# ---------- 后台防掉线 API ----------

@app.get("/api/v1/watchdog/status")
async def watchdog_status():
    """获取防掉线守护状态"""
    return watchdog.get_status()


@app.post("/api/v1/watchdog/toggle")
async def watchdog_toggle(data: dict):
    """开启/关闭防掉线守护"""
    enabled = data.get("enabled", True)
    if enabled:
        watchdog.enable()
    else:
        watchdog.disable()
    return watchdog.get_status()


# ---------- F12 紧急处置 API ----------

@app.get("/api/v1/emergency-kill/status")
async def emergency_kill_status():
    """获取紧急处置状态"""
    return emergency_kill.get_status()


@app.post("/api/v1/emergency-kill/toggle")
async def emergency_kill_toggle(data: dict):
    """开启/关闭 F12 紧急处置"""
    enabled = data.get("enabled", True)
    if enabled:
        emergency_kill.enable()
    else:
        emergency_kill.disable()
    return emergency_kill.get_status()


@app.get("/api/v1/emergency-kill/log")
async def emergency_kill_log():
    """获取紧急处置日志"""
    return {"log": emergency_kill.get_log()}


# ---------- 退出御天 ----------

@app.post("/api/v1/shutdown")
async def shutdown():
    """关闭御天（含守护进程）- Logo 淡出动画 + 资源释放 + 进程退出"""
    # 诊断：见 on_exit 处的说明。这个接口被设置页的「立即退出」按钮调用。
    print("[御天][诊断] 退出触发点 = POST /api/v1/shutdown")
    _thr.Thread(target=_do_exit_with_fadeout, daemon=True).start()
    return {"success": True, "message": "御天正在退出，Logo 淡出动画播放中..."}


# ---------- 守护天数 API ----------

@app.get("/api/v1/guard-days")
async def get_guard_days():
    """获取累计守护天数"""
    try:
        from persistence import load_guard_days
        data = load_guard_days()
        return {
            "first_start_date": data.get("first_start_date", ""),
            "last_start_date": data.get("last_start_date", ""),
            "accumulated_days": data.get("accumulated_days", 0),
        }
    except Exception as e:
        return {"accumulated_days": 0, "error": str(e)}


# ---------- 持久化配置保存 API ----------

@app.get("/api/v1/config-save")
async def get_config_save():
    """获取持久化保存的用户配置"""
    try:
        from persistence import load_config_save
        return load_config_save()
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/config-save")
async def save_config_endpoint(data: dict):
    """保存用户自定义扫描配置到磁盘"""
    try:
        from persistence import save_config_save, load_config_save
        existing = load_config_save()
        # 递归合并
        _deep_merge_dict(existing, data)
        save_config_save(existing)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/v1/config-save/scan")
async def get_scan_config():
    """获取扫描配置"""
    try:
        from persistence import load_config_save
        cfg = load_config_save()
        return cfg.get("scan", {})
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/config-save/scan")
async def save_scan_config(data: dict):
    """保存扫描配置"""
    try:
        from persistence import save_config_save, load_config_save
        cfg = load_config_save()
        cfg["scan"] = {**cfg.get("scan", {}), **data}
        save_config_save(cfg)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _deep_merge_dict(base: dict, override: dict):
    """递归合并两个字典"""
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge_dict(base[k], v)
        else:
            base[k] = v


# ---------- 扫描缓存 API ----------

@app.get("/api/v1/cache/stats")
async def cache_stats():
    """扫描缓存统计"""
    try:
        from persistence import cache_stats
        return cache_stats()
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/cache/clear")
async def cache_clear():
    """清空扫描缓存"""
    try:
        from persistence import cache_clear, cache_cleanup
        cache_clear()
        cache_cleanup()
        return {"success": True, "message": "缓存已清空"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------- 实时文件监控 API ----------

@app.get("/api/v1/realtime-guard/status")
async def realtime_guard_status():
    """获取实时监控状态"""
    return realtime_guard.get_status()


@app.post("/api/v1/realtime-guard/toggle")
async def realtime_guard_toggle(data: dict):
    """开启/关闭实时监控"""
    enabled = data.get("enabled", True)
    if enabled:
        realtime_guard.enable()
    else:
        realtime_guard.disable()
    return realtime_guard.get_status()


@app.post("/api/v1/realtime-guard/dir/add")
async def realtime_guard_dir_add(data: dict):
    """添加自定义监控目录"""
    path = data.get("path", "")
    if not path:
        return {"success": False, "error": "路径不能为空"}
    ok = realtime_guard.add_watch_dir(path)
    return {"success": ok, "dirs": realtime_guard.get_watch_dirs()}


@app.post("/api/v1/realtime-guard/dir/remove")
async def realtime_guard_dir_remove(data: dict):
    """移除监控目录"""
    path = data.get("path", "")
    if not path:
        return {"success": False, "error": "路径不能为空"}
    ok = realtime_guard.remove_watch_dir(path)
    return {"success": ok, "dirs": realtime_guard.get_watch_dirs()}


# ---------- 隔离区 API ----------

@app.get("/api/v1/quarantine")
async def quarantine_list():
    """隔离区列表"""
    items = quarantine.list_quarantined()
    return {"total": len(items), "items": items}


@app.post("/api/v1/quarantine/report-false-positive")
async def quarantine_report_false_positive(data: dict):
    """用户上报「这是误报」。

    为什么要在服务端补上下文，而不是只收一句"我这是误报"：
    判断一条命中到底是真误报还是用户不懂，靠的是**命中时的一切旁证** ——
    文件在不在系统目录、是不是 Program Files、什么扩展名、多大、
    哪个威胁名/规则、什么等级。这些只有隔离那一刻才知道，事后问用户是问不出来的。

    报告落到 data/false_positive_reports/，由 tools/collect_fp.py 汇总，
    用于给 YARA 规则做「有效鉴别力」复核（哪些规则专挑系统文件下手）。
    """
    import json as _json
    import platform as _platform

    qid = str(data.get("id") or "")
    note = str(data.get("note") or "")[:2000]
    if not qid:
        return JSONResponse({"error": "缺少隔离ID"}, 400)

    # 从隔离列表里找到这条记录（QuarantineManager 没有单条 get）。
    # 注意两个 id 不是一回事：
    #   list_quarantined() 的 "id" = 数据库数字行号
    #   quarantine_file()  的 "id" = quarantine_name（文件名）
    # 界面传的是前者，直接调 manager 拿到的是后者 —— 两种都认，否则会 404。
    try:
        record = next((it for it in quarantine.list_quarantined()
                       if qid in (str(it.get("id") or ""),
                                  str(it.get("quarantine_name") or ""))), None)
    except Exception as exc:
        return JSONResponse({"error": f"读取隔离记录失败: {exc}"}, 500)
    if record is None:
        return JSONResponse({"error": "找不到该隔离记录（可能已被还原或删除）"}, 404)

    original_path = str(record.get("original_path") or "")
    lower = original_path.lower().replace("/", "\\")

    # 目录归类 —— 这几个是误报分诊最有效的信号
    if "\\windows\\system32" in lower:
        dir_cat = "Windows\\System32"
    elif "\\windows\\syswow64" in lower:
        dir_cat = "Windows\\SysWOW64"
    elif "\\program files" in lower:
        dir_cat = "Program Files"
    elif "\\windows\\" in lower:
        dir_cat = "Windows (其它)"
    elif "\\appdata\\" in lower or "\\users\\" in lower:
        dir_cat = "用户目录"
    elif lower.startswith("\\\\"):
        dir_cat = "网络路径"
    else:
        dir_cat = "其它"

    is_sys = False
    try:
        from engine.threat_decision import is_system_path
        is_sys = bool(is_system_path(original_path)) if original_path else False
    except Exception:
        pass

    base = os.path.basename(original_path) if original_path else ""
    report = {
        "schema": 1,
        "report_id": f"{int(time.time())}_{qid[:24]}",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "quarantine": {
            "id": qid,
            "threat_name": record.get("threat_name"),
            "threat_level": record.get("threat_level"),
            "file_hash": record.get("file_hash"),
            "hash_type": record.get("file_hash_type") or "sha256",
            "file_size": record.get("file_size"),
            "original_path": original_path,
            "quarantined_at": record.get("quarantined_at"),
        },
        "path_context": {
            "dir_category": dir_cat,
            "is_system_path": is_sys,
            "filename": base,
            "extension": os.path.splitext(base)[1].lower() if base else "",
            "in_user_profile": ("\\users\\" in lower or "\\appdata\\" in lower),
        },
        "user_note": note,
        "environment": {
            "os": _platform.platform(),
            "python": _platform.python_version(),
            "app_version": APP_VERSION if "APP_VERSION" in globals() else "",
        },
    }

    # 落盘（与隔离区同级的 data 目录下）
    try:
        from config import QUARANTINE_DIR as _QDIR
        out_dir = os.path.join(os.path.dirname(_QDIR), "false_positive_reports")
    except Exception:
        out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "engine", "data", "false_positive_reports")
    try:
        os.makedirs(out_dir, exist_ok=True)
        fpath = os.path.join(out_dir, f"{report['report_id']}.json")
        tmp = fpath + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            _json.dump(report, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, fpath)
    except OSError as exc:
        return JSONResponse({"error": f"写入误报记录失败: {exc}"}, 500)

    print(f"[御天][误报] 收到上报 {qid[:16]} ｜ {record.get('threat_name')} "
          f"｜ {dir_cat} ｜ {base}")
    return {"ok": True, "report_id": report["report_id"],
            "report_path": fpath, "dir_category": dir_cat,
            "is_system_path": is_sys}


@app.post("/api/v1/quarantine/restore")
async def quarantine_restore(data: dict):
    """还原隔离文件"""
    qid = data.get("id", "")
    if not qid:
        return JSONResponse({"error": "缺少隔离ID"}, 400)
    result = quarantine.restore_file(str(qid))
    return result


@app.delete("/api/v1/quarantine/{quarantine_id}")
async def quarantine_delete(quarantine_id: str):
    """永久删除隔离文件"""
    result = quarantine.delete_quarantined(quarantine_id)
    return result


@app.post("/api/v1/quarantine/restore-all")
async def quarantine_restore_all():
    """还原所有隔离文件"""
    items = quarantine.list_quarantined()
    restored = 0
    errors = []
    for item in items:
        result = quarantine.restore_file(str(item["id"]))
        if result.get("success"):
            restored += 1
        else:
            errors.append(result.get("error", "未知错误"))
    return {"success": True, "restored": restored, "total": len(items), "errors": errors}


@app.delete("/api/v1/quarantine")
async def quarantine_delete_all():
    """永久删除所有隔离文件"""
    items = quarantine.list_quarantined()
    deleted = 0
    errors = []
    for item in items:
        result = quarantine.delete_quarantined(str(item["id"]))
        if result.get("success"):
            deleted += 1
        else:
            errors.append(result.get("error", "未知错误"))
    return {"success": True, "deleted": deleted, "total": len(items), "errors": errors}


# ---------- 特征库 API ----------

@app.get("/api/v1/signatures/info")
async def signatures_info():
    """特征库信息"""
    stats = sig_mgr.get_stats()
    return stats


@app.post("/api/v1/signatures/update")
async def signatures_update():
    """手动更新特征库"""
    return {"version": sig_mgr.get_stats().get("version", "1.0.0"), "updated": True}


@app.post("/api/v1/signatures/download")
async def signatures_download(data: dict = None):
    """从网络下载病毒特征库（支持: all, eset, urlhaus, phishtank, blocklist）"""
    source = (data or {}).get("source", "all")
    limit = (data or {}).get("limit", 2000)

    def _do_download():
        sig_downloader.download_and_import(source=source, limit=limit)

    import threading
    t = threading.Thread(target=_do_download, daemon=True)
    t.start()
    return {"status": "started", "source": source, "limit": limit}


@app.get("/api/v1/signatures/sources")
async def signatures_sources():
    """返回可用的病毒库下载源列表"""
    from engine.signature_downloader import SOURCES
    return {
        "sources": [
            {"key": k, "name": v["name"], "type": v["type"], "desc": v["desc"]}
            for k, v in SOURCES.items()
        ]
    }


@app.get("/api/v1/signatures/download/status")
async def signatures_download_status():
    """病毒库下载进度"""
    return sig_downloader.status


@app.post("/api/v1/signatures/import_local")
async def signatures_import_local(data: dict = None):
    """
    手动导入本地 bingduku 病毒库（MD5 文本文件）。
    参数: force=true 时忽略已导入标记，强制重新导入。
    """
    from config import BINGDUKU_MD5_TXT
    import os as _os
    import sqlite3
    force = (data or {}).get("force", False) in (True, 1, "true", "True", "1", "yes")
    if not BINGDUKU_MD5_TXT or not _os.path.isfile(BINGDUKU_MD5_TXT):
        return JSONResponse(status_code=404, content={
            "status": "error",
            "error": "本地病毒库文件不存在",
            "path": BINGDUKU_MD5_TXT
        })
    # 清除已导入标记（force）
    if force:
        try:
            conn = sqlite3.connect(sig_mgr.db_path)
            conn.execute(
                "DELETE FROM signature_meta WHERE key='bingduku_20260419_imported'"
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _do():
        try:
            import time
            t0 = time.time()
            result = sig_mgr.import_md5_text(BINGDUKU_MD5_TXT)
            try:
                conn = sqlite3.connect(sig_mgr.db_path)
                conn.execute(
                    "INSERT OR REPLACE INTO signature_meta (key, value) VALUES (?, ?)",
                    ("bingduku_20260419_imported", "1")
                )
                conn.commit()
                conn.close()
            except Exception:
                pass
            result["duration_ms"] = int((time.time() - t0) * 1000)
            result["stats"] = sig_mgr.get_stats()
            return result
        except Exception as e:
            return {"error": str(e)}

    t = _thr.Thread(target=_do, daemon=True)
    t.start()
    return {"status": "started", "force": force, "source_file": BINGDUKU_MD5_TXT}


# ---------- ML 扫描 API ----------

class ScanFileRequest(BaseModel):
    file_path: str


@app.post("/api/v1/ml/scan")
async def ml_scan(req: ScanFileRequest):
    """使用ML引擎扫描单个文件"""
    try:
        with open(req.file_path, "rb") as f:
            data = f.read()
        result = ml_scan_pe(data)
        return {"file": req.file_path, **result}
    except FileNotFoundError:
        return JSONResponse({"error": "文件不存在"}, 404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/ml/scan-file")
async def ml_scan_file(file: UploadFile = File(..., max_size=100 * 1024 * 1024)):
    """上传文件进行ML引擎扫描（最大100MB）"""
    try:
        data = await file.read()
        result = ml_scan_pe(data)
        return {"file": file.filename, **result}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# ---------- C2 威胁情报 API ----------

@app.get("/api/v1/threat-intel/c2/stats")
async def c2_stats():
    """C2 威胁情报统计"""
    return _get_c2_intel().get_stats()


@app.get("/api/v1/threat-intel/c2/lookup")
async def c2_lookup(ip: str = "", domain: str = ""):
    """查询 C2 威胁情报"""
    result = {}
    if ip:
        result["ip_result"] = _get_c2_intel().lookup_ip(ip)
    if domain:
        result["domain_result"] = _get_c2_intel().lookup_domain(domain)
    return result


@app.get("/api/v1/threat-intel/c2/cobaltstrike")
async def c2_cobaltstrike(ip: str = ""):
    """查询 Cobalt Strike C2 配置"""
    if ip:
        return {"ip": ip, "config": _get_c2_intel().lookup_cobalt_strike(ip)}
    return {"error": "请提供IP参数"}


# ---------- 恶意软件威胁情报 API ----------

@app.get("/api/v1/threat-intel/malware/stats")
async def malware_stats():
    """恶意软件威胁情报统计"""
    return _get_threat_intel().get_stats()


@app.get("/api/v1/threat-intel/malware/lookup")
async def malware_lookup(ioc: str = ""):
    """查询 IOC 归属的恶意软件家族"""
    if not ioc:
        return JSONResponse({"error": "请提供IOC参数"}, 400)
    families = _get_threat_intel().lookup_ioc(ioc)
    return {"ioc": ioc, "families": families, "count": len(families)}


@app.get("/api/v1/threat-intel/malware/search")
async def malware_search(name: str = ""):
    """搜索恶意软件家族"""
    if not name:
        return JSONResponse({"error": "请提供搜索关键词"}, 400)
    results = _get_threat_intel().search_family(name)
    return {"keyword": name, "count": len(results), "results": results}


@app.get("/api/v1/threat-intel/malware/family")
async def malware_family_iocs(name: str = "", limit: int = 100):
    """获取某个恶意软件家族的 IOC 列表"""
    if not name:
        return JSONResponse({"error": "请提供家族名称"}, 400)
    iocs = _get_threat_intel().get_family_iocs(name)
    return {"family": name, "ioc_count": len(iocs), "iocs": iocs[:limit]}


# ---------- 卫士-垃圾清理 API ----------

class CleanExecuteRequest(BaseModel):
    """清理执行请求：选中分类 id 列表"""
    category_ids: list[str] = []


@app.post("/api/v1/clean/scan")
async def clean_scan():
    """启动垃圾清理扫描（异步，进度经 WebSocket 推送）"""
    task = junk_cleaner.start_scan(progress_callback=broadcast_progress)
    return {"task_id": task.task_id, "status": task.status}


@app.get("/api/v1/clean/{task_id}/status")
async def clean_status(task_id: str):
    """查询清理扫描任务状态"""
    task = junk_cleaner.get_task(task_id)
    if not task:
        return JSONResponse({"error": "任务不存在"}, 404)
    return task.to_dict()


@app.post("/api/v1/clean/{task_id}/cancel")
async def clean_cancel(task_id: str):
    """取消垃圾清理扫描任务（协作式：扫描主循环在检查点退出）"""
    if not junk_cleaner.cancel_task(task_id):
        return JSONResponse({"error": "无法取消该任务"}, 400)
    return {"task_id": task_id, "status": "cancelled"}


@app.post("/api/v1/clean/execute")
async def clean_execute(req: CleanExecuteRequest):
    """执行清理：仅允许白名单分类，返回释放统计"""
    try:
        return junk_cleaner.execute_clean(req.category_ids)
    except Exception as e:
        return JSONResponse({"error": f"清理失败: {e}"}, 500)


@app.get("/api/v1/clean/history")
async def clean_history(limit: int = 20):
    """获取清理历史记录（最新在前）"""
    return {"records": junk_cleaner.get_history(limit)}


# ---------- 卫士-电脑优化 API ----------

class StartupToggleRequest(BaseModel):
    """启动项切换请求"""
    item_id: str
    action: str  # disable | enable


class ServiceToggleRequest(BaseModel):
    """服务启动类型切换请求"""
    name: str
    action: str  # auto | manual | disabled


@app.get("/api/v1/optimize/overview")
async def optimize_overview():
    """系统体检报告（评分 + 检查项）"""
    try:
        return system_optimizer.overview()
    except Exception as e:
        return JSONResponse({"error": f"体检失败: {e}"}, 500)


@app.get("/api/v1/optimize/startup")
async def optimize_startup():
    """启动项列表（含已禁用项，可还原）"""
    try:
        return {"items": system_optimizer.list_startup()}
    except Exception as e:
        return JSONResponse({"error": f"读取启动项失败: {e}"}, 500)


@app.post("/api/v1/optimize/startup/toggle")
async def optimize_startup_toggle(req: StartupToggleRequest):
    """禁用/启用启动项（可逆操作）"""
    return system_optimizer.toggle_startup(req.item_id, req.action)


@app.get("/api/v1/optimize/services")
async def optimize_services():
    """服务列表：系统服务只读，第三方服务可管理"""
    try:
        return system_optimizer.list_services()
    except Exception as e:
        return JSONResponse({"error": f"读取服务列表失败: {e}"}, 500)


@app.post("/api/v1/optimize/services/toggle")
async def optimize_service_toggle(req: ServiceToggleRequest):
    """修改第三方服务启动类型（auto/manual/disabled）"""
    return system_optimizer.toggle_service(req.name, req.action)


@app.post("/api/v1/optimize/memory")
async def optimize_memory():
    """释放内存（收缩空闲进程工作集）"""
    try:
        return system_optimizer.release_memory()
    except Exception as e:
        return JSONResponse({"error": f"内存释放失败: {e}"}, 500)


@app.post("/api/v1/optimize/one-click")
async def optimize_one_click():
    """一键优化：临时垃圾清理 + 内存释放 + 启动项建议"""
    try:
        return system_optimizer.one_click()
    except Exception as e:
        return JSONResponse({"error": f"一键优化失败: {e}"}, 500)


# ---------- 统计概览 API ----------

@app.get("/api/v1/stats/overview")
async def stats_overview():
    """仪表盘统计数据"""
    s = logger.get_stats()
    s["quarantine_count"] = len(quarantine.list_quarantined())
    s["signatures_count"] = sig_mgr.get_stats().get("total_signatures", 0)
    s["c2_ip_count"] = _get_c2_intel().get_stats().get("ip_count", 0)
    s["c2_domain_count"] = _get_c2_intel().get_stats().get("domain_count", 0)
    s["malware_families"] = _get_threat_intel().get_stats().get("family_count", 0)
    s["malware_ioc_count"] = _get_threat_intel().get_stats().get("ioc_count", 0)
    # 累计守护天数
    try:
        from persistence import load_guard_days
        gd = load_guard_days()
        s["guard_days"] = gd.get("accumulated_days", 0)
        s["first_start_date"] = gd.get("first_start_date", "")
    except Exception:
        s["guard_days"] = 0
    return s


@app.get("/api/v1/stats/activity")
async def stats_activity():
    """最近活动日志"""
    threats = logger.get_threat_logs(10)
    scans = logger.get_scan_logs(10)
    return {"threats": threats, "scans": scans}


@app.post("/api/v1/logs/clear")
async def logs_clear():
    """清空所有日志"""
    logger.clear_logs()
    return {"success": True, "message": "日志已清空"}


# ---------- WebSocket ----------

@app.websocket("/ws/progress")
async def websocket_progress(ws: WebSocket):
    """WebSocket 实时进度推送"""
    global _event_loop
    if len(ws_connections) >= MAX_WS_CONNECTIONS:
        await ws.close(code=1013, reason="连接数已满")
        return
    await ws.accept()
    _event_loop = asyncio.get_running_loop()
    conn_id = str(id(ws))
    ws_connections[conn_id] = ws
    try:
        while True:
            await asyncio.wait_for(ws.receive_text(), timeout=60)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        ws_connections.pop(conn_id, None)


def broadcast_progress(task_id: str, progress: int, current_file: str):
    """广播扫描进度到所有 WebSocket 客户端"""
    msg = json.dumps({
        "task_id": task_id,
        "progress": progress,
        "current_file": current_file
    })
    loop = _event_loop
    if not loop or loop.is_closed():
        return
    for ws in list(ws_connections.values()):
        try:
            asyncio.run_coroutine_threadsafe(ws.send_text(msg), loop)
        except Exception:
            pass


# ---------- 云端 API ----------

class CloudConfigRequest(BaseModel):
    api_key: Optional[str] = ""
    engine_order: Optional[list] = None


@app.get("/api/v1/cloud/status")
async def cloud_status():
    """云端引擎状态"""
    cs = scheduler.cloud
    return cs.get_status()


@app.post("/api/v1/cloud/config")
async def cloud_config(req: CloudConfigRequest):
    """配置云端 API Key / 云查杀引擎优先级"""
    if req.api_key:
        scheduler.cloud.set_api_key(req.api_key)
    if req.engine_order:
        scheduler.cloud.set_engine_order(req.engine_order)
        # 持久化归一化后的优先级（过滤掉已下线/未知引擎）
        try:
            cfg = load_config_save()
            cfg.setdefault("cloud", {})["engine_order"] = scheduler.cloud.engine_order
            save_config_save(cfg)
        except Exception:
            pass
    return scheduler.cloud.get_status()


@app.get("/api/v1/cloud/avic/status")
async def avic_status():
    """AVIC 情报中心状态"""
    try:
        from engine.avic_client import AVICClient
        from config import AVIC_API_KEY, AVIC_BASE_URL
        if not AVIC_API_KEY:
            return {
                "ok": False,
                "degraded": True,
                "configured": False,
                "hint": "尚未配置 AVIC API Key，AVIC 情报服务暂不可用，可到「引擎启动」页配置。",
                "base_url": AVIC_BASE_URL,
            }
        avic = AVICClient(base_url=AVIC_BASE_URL, api_key=AVIC_API_KEY, timeout=8)
        status = avic.status()
        return {
            "ok": True,
            "server": status,
            "api_key": f"{AVIC_API_KEY[:8]}...",
            "base_url": AVIC_BASE_URL,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------- OTX AlienVault 云查杀 + IOC 情报 API ----------

class OTXConfigRequest(BaseModel):
    otx_api_key: str


class OTXHashRequest(BaseModel):
    md5: Optional[str] = ""
    sha1: Optional[str] = ""
    sha256: Optional[str] = ""


@app.post("/api/v1/cloud/otx/config")
async def otx_config(req: OTXConfigRequest):
    """设置 / 更新 AlienVault OTX API Key"""
    try:
        scheduler.cloud.set_otx_key(req.otx_api_key)
        return {"success": True, "status": scheduler.cloud.get_status().get("otx")}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, 500)


@app.get("/api/v1/cloud/otx/status")
async def otx_status():
    """AlienVault OTX 引擎状态（含 Key 验证）"""
    try:
        cs = scheduler.cloud
        status = cs.get_status().get("otx", {})
        # 若配置了 Key，尝试带用户名信息的验证结果
        if status.get("configured"):
            verification = cs.otx_verify_key()
            status["verification"] = verification
        return {
            "ok": True,
            **status,
            "last_error": cs.last_error if not status.get("available") else None,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/v1/cloud/otx/hash")
async def otx_scan_hash(req: OTXHashRequest):
    """OTX 文件哈希云查杀（MD5/SHA1/SHA256，任一即可）"""
    if not req.md5 and not req.sha1 and not req.sha256:
        return JSONResponse({"error": "请至少提供 md5/sha1/sha256 中任一哈希值"}, 400)
    try:
        cs = scheduler.cloud
        result = cs.lookup_hash(md5=req.md5, sha1=req.sha1, sha256=req.sha256)
        resource = req.sha256 or req.sha1 or req.md5
        if result is None:
            return {
                "found": False,
                "hash": resource,
                "classification": "unknown",
                "threat_level": "clean",
                "engine": "cloud_otx",
                "message": "OTX 未命中或不可用",
            }
        return {
            "found": True,
            "hash": resource,
            **result,
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, 500)


@app.post("/api/v1/cloud/otx/hash/batch")
async def otx_scan_batch(data: dict):
    """OTX 批量哈希云查杀"""
    hashes = data.get("hashes", [])
    if not isinstance(hashes, list) or len(hashes) == 0:
        return JSONResponse({"error": "请提供 hashes 数组"}, 400)
    try:
        results = scheduler.cloud.lookup_hashes_batch(hashes)
        summary = {
            "total": len(hashes),
            "hits": sum(1 for v in results.values() if v is not None),
            "misses": sum(1 for v in results.values() if v is None),
        }
        return {"summary": summary, "results": results}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, 500)


@app.get("/api/v1/cloud/otx/ip")
async def otx_lookup_ip(ip: str = ""):
    """OTX 查询 IPv4 情报（脉冲数、声誉、地理信息、关联样本）"""
    if not ip:
        return JSONResponse({"error": "请提供 ip 参数"}, 400)
    try:
        result = scheduler.cloud.otx_lookup_ip(ip)
        return result
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, 500)


@app.get("/api/v1/cloud/otx/domain")
async def otx_lookup_domain(domain: str = ""):
    """OTX 查询域名情报（脉冲数、关联样本、Pulse 列表）"""
    if not domain:
        return JSONResponse({"error": "请提供 domain 参数"}, 400)
    try:
        result = scheduler.cloud.otx_lookup_domain(domain)
        return result
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, 500)


@app.get("/api/v1/cloud/otx/url")
async def otx_lookup_url(url: str = ""):
    """OTX 查询 URL 情报"""
    if not url:
        return JSONResponse({"error": "请提供 url 参数"}, 400)
    try:
        result = scheduler.cloud.otx_lookup_url(url)
        return result
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, 500)


@app.get("/api/v1/cloud/otx/cve")
async def otx_lookup_cve(cve_id: str = ""):
    """OTX 查询 CVE 漏洞情报"""
    if not cve_id:
        return JSONResponse({"error": "请提供 cve_id 参数 (如 CVE-2024-1234)"}, 400)
    try:
        result = scheduler.cloud.otx_lookup_cve(cve_id)
        return result
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, 500)


@app.get("/api/v1/cloud/otx/pulses/subscribed")
async def otx_subscribed_pulses(page: int = 1, limit: int = 20, modified_since: str = ""):
    """OTX 已订阅的 Pulse 列表（威胁事件/活动集合）"""
    try:
        from engine.otx_client import OTXClient
        import os
        key = scheduler.cloud._otx_key if hasattr(scheduler.cloud, "_otx_key") else os.environ.get("OTX_API_KEY", "")
        if not key:
            return JSONResponse({"error": "未配置 OTX API Key"}, 400)
        otx = OTXClient(api_key=key)
        kwargs = {"page": page, "limit": limit}
        if modified_since:
            kwargs["modified_since"] = modified_since
        result = otx.list_subscribed_pulses(**kwargs) or {}
        return {
            "page": page,
            "limit": limit,
            "count": result.get("count", 0),
            "pulses": result.get("results", [])[:limit],
            "source": "otx",
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, 500)


@app.get("/api/v1/cloud/otx/pulses/search")
async def otx_search_pulses(query: str = "", page: int = 1, limit: int = 20):
    """OTX 搜索 Pulse（按关键词）"""
    if not query:
        return JSONResponse({"error": "请提供 query 搜索关键词"}, 400)
    try:
        from engine.otx_client import OTXClient
        import os
        key = scheduler.cloud._otx_key if hasattr(scheduler.cloud, "_otx_key") else os.environ.get("OTX_API_KEY", "")
        if not key:
            return JSONResponse({"error": "未配置 OTX API Key"}, 400)
        otx = OTXClient(api_key=key)
        result = otx.search_pulses(query, page=page, limit=limit) or {}
        return {
            "query": query,
            "page": page,
            "count": result.get("count", 0),
            "pulses": result.get("results", [])[:limit],
            "source": "otx",
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, 500)


@app.get("/api/v1/cloud/otx/pulses/{pulse_id}")
async def otx_get_pulse(pulse_id: str):
    """按 Pulse ID 获取单个 Pulse 详情（含相关 IOC）"""
    if not pulse_id:
        return JSONResponse({"error": "缺少 pulse_id"}, 400)
    try:
        from engine.otx_client import OTXClient
        import os
        key = scheduler.cloud._otx_key if hasattr(scheduler.cloud, "_otx_key") else os.environ.get("OTX_API_KEY", "")
        if not key:
            return JSONResponse({"error": "未配置 OTX API Key"}, 400)
        otx = OTXClient(api_key=key)
        result = otx.get_pulse(pulse_id) or {}
        return {"pulse_id": pulse_id, **result, "source": "otx"}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, 500)


@app.post("/api/v1/cloud/sample/submit")
async def cloud_sample_submit(file: UploadFile = File(...)):
    """
    云样本研判：上传一个疑似样本文件 → 本地计算哈希 → 多引擎哈希比对（天听），
    返回研判报告。
    """
    import hashlib
    cs = scheduler.cloud
    try:
        content = await file.read()
        sha256 = hashlib.sha256(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()

        lookup = cs.lookup_hash(md5=md5, sha256=sha256) or {}
        known = lookup.get("verdict") in ("malicious", "clean")
        return {
            "sha256": sha256,
            "md5": md5,
            "size_bytes": len(content),
            "filename": file.filename or "",
            "known": known,
            "lookup": lookup,
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, 500)


@app.get("/api/v1/cloud/engines")
async def cloud_engines():
    """获取当前云查杀引擎配置与优先级"""
    try:
        status = scheduler.cloud.get_status()
        return {
            "engine_order": status.get("engine_order", []),
            "engines": {
                "avic": status.get("avic", {}),
                "threatbook": status.get("threatbook", {}),
                "otx": status.get("otx", {}),
            },
            "last_error": status.get("last_error"),
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, 500)


# ---------- 洞渊引擎 API ----------

@app.get("/api/v1/deep/engines")
async def deep_engines_status():
    """洞渊引擎状态检查"""
    try:
        from engine.deep_analyzer import engines_status
        return engines_status()
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/deep/scan")
async def deep_scan_file(data: dict):
    """深度扫描文件（capa + ClamAV + YARA）"""
    file_path = data.get("file_path", "")
    engines = data.get("engines", None)
    if not file_path or not os.path.isfile(file_path):
        return JSONResponse({"error": "文件不存在"}, 404)
    try:
        from engine.deep_analyzer import deep_scan_async, status
        result = deep_scan_async(file_path, engines)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.get("/api/v1/deep/status")
async def deep_scan_status():
    """深度扫描状态"""
    try:
        from engine.deep_analyzer import status
        return status()
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/v1/deep/yargen")
async def deep_yargen(data: dict):
    """使用 yarGen 生成 YARA 规则"""
    sample_dir = data.get("sample_dir", "")
    output_dir = data.get("output_dir", None)
    if not sample_dir:
        return JSONResponse({"error": "请提供样本目录"}, 400)
    try:
        from engine.deep_analyzer import yargen_generate

        def _do():
            yargen_generate(sample_dir, output_dir)

        import threading
        t = threading.Thread(target=_do, daemon=True)
        t.start()
        return {"status": "started", "sample_dir": sample_dir}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/deep/pesieve")
async def deep_pesieve(data: dict):
    """PE-sieve 内存扫描"""
    pid = data.get("pid", None)
    exe_path = data.get("exe_path", None)
    try:
        from engine.deep_analyzer import pe_sieve_scan
        result = pe_sieve_scan(pid=pid, exe_path=exe_path)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.get("/api/v1/deep/libpeconv")
async def deep_libpeconv():
    """libpeconv 信息"""
    try:
        from engine.deep_analyzer import libpeconv_info
        return libpeconv_info()
    except Exception as e:
        return JSONResponse({"error": str(e)})


# ---------- rtguard 联动（实时防护 CPU 节流） ----------
# rtguard 是独立进程（<仓库>/rtguard），只监听 127.0.0.1 的控制 API：
#     GET  /api/status    -> 档位 + 实测占用 + 扫描统计
#     POST /api/throttle  -> {"level": "low"|"medium"|"high"}
# 这里做三件事：状态代理、档位转发、按需拉起（pythonw.exe，无控制台、脱离本进程会话）。
# 只用标准库转发，超时短，rtguard 不在跑时降级而不报 500。
import subprocess as _sp
import urllib.request as _urlreq

_RTGUARD_HOST = "127.0.0.1"
_RTGUARD_PORT = 8022
_RTGUARD_TIMEOUT = 2.5              # 转发超时必须短，否则会把主产品后端拖住
_RTGUARD_BOOT_TIMEOUT = 30.0        # 首次拉起要加载规则集（实测约 2 s），留足余量
_RTGUARD_LEVELS = {"low": ("低 5%", 5.0), "medium": ("中 10%", 10.0), "high": ("高 15%", 15.0)}
_RTGUARD_DEFAULT_LEVEL = "low"
_RTGUARD_LOCK = _thr.Lock()


def _rtguard_fallback_levels():
    return {k: {"label": v[0], "pct": v[1]} for k, v in _RTGUARD_LEVELS.items()}


def _rtguard_root():
    """rtguard 目录：开发模式 ../rtguard，打包模式 exe 同级 rtguard。"""
    if getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(sys.executable), "rtguard")
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rtguard")


def _rtguard_pythonw():
    """无控制台的解释器：用 python.exe 起控制台进程，控制台一被拆就静默死。"""
    for cand in (os.path.join(os.path.dirname(sys.executable), "pythonw.exe"),
                 r"F:\Python314\pythonw.exe"):
        if os.path.isfile(cand):
            return cand
    return sys.executable


def _rtguard_http(method, path, payload=None, timeout=_RTGUARD_TIMEOUT):
    url = f"http://{_RTGUARD_HOST}:{_RTGUARD_PORT}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = _urlreq.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with _urlreq.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _rtguard_unavailable(error="rtguard 未运行"):
    return {
        "available": False,
        "error": error,
        "level": None,
        "label": None,
        "target_pct": None,
        "actual_pct": None,
        "cores": None,
        "budget_cores": None,
        "levels": _rtguard_fallback_levels(),
        "stats": {},
        "alerts": [],
    }


def _rtguard_normalize(raw):
    """把 rtguard 的快照收敛成前端契约（只搬关键字，不重算档位/占用）。"""
    raw = raw if isinstance(raw, dict) else {}
    th = raw.get("throttle")
    if not isinstance(th, dict):
        th = raw
    return {
        "available": True,
        "level": th.get("level"),
        "label": th.get("label"),
        "target_pct": th.get("target_pct"),
        "actual_pct": th.get("actual_pct"),
        "cores": th.get("cores"),
        "budget_cores": th.get("budget_cores"),
        "levels": th.get("levels") or _rtguard_fallback_levels(),
        "stats": raw.get("stats") or {},
        "uptime_h": raw.get("uptime_h"),
        "backend": raw.get("backend"),
        "alerts": raw.get("alerts") or [],
    }


def _rtguard_probe():
    """在跑返回归一化状态，否则 None（任何异常都按“没在跑”处理）"""
    try:
        return _rtguard_normalize(_rtguard_http("GET", "/api/status"))
    except Exception:
        return None


def _rtguard_spawn(level):
    """用 pythonw.exe 拉起 rtguard，日志追加到 rtguard\\_run.log"""
    root = _rtguard_root()
    entry = os.path.join(root, "run_rtguard.py")
    if not os.path.isfile(entry):
        return False, f"rtguard 入口不存在: {entry}"
    level = level if level in _RTGUARD_LEVELS else _RTGUARD_DEFAULT_LEVEL
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"   # 否则子进程 stdout 走块缓冲，日志要等退出才落盘
    # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    flags = 0x00000008 | 0x00000200 | 0x08000000
    try:
        logf = open(os.path.join(root, "_run.log"), "ab", buffering=0)
    except Exception:
        logf = _sp.DEVNULL
    try:
        _sp.Popen([_rtguard_pythonw(), entry, "--level", level, "--ui-port", str(_RTGUARD_PORT)],
                  cwd=root, env=env, stdin=_sp.DEVNULL, stdout=logf, stderr=_sp.STDOUT,
                  creationflags=flags, close_fds=True)
    except Exception as exc:
        return False, f"启动 rtguard 失败: {exc}"
    finally:
        try:
            if logf is not _sp.DEVNULL:
                logf.close()
        except Exception:
            pass
    return True, ""


def _rtguard_ensure_started(level=_RTGUARD_DEFAULT_LEVEL):
    """确保 rtguard 在跑：已响应就不再拉起；整体加锁，连续调用不会起出第二个实例。"""
    with _RTGUARD_LOCK:
        st = _rtguard_probe()
        if st is not None:
            return {"started": False, "already_running": True, "status": st}
        ok, err = _rtguard_spawn(level)
        if not ok:
            return {"started": False, "already_running": False, "error": err}
        deadline = time.time() + _RTGUARD_BOOT_TIMEOUT
        while time.time() < deadline:
            time.sleep(0.4)
            st = _rtguard_probe()
            if st is not None:
                return {"started": True, "already_running": False, "status": st}
    return {"started": True, "already_running": False,
            "error": f"rtguard 启动超时（{_RTGUARD_BOOT_TIMEOUT:.0f}s 内未监听 {_RTGUARD_PORT}）",
            "status": _rtguard_unavailable("rtguard 启动超时")}


@app.get("/api/v1/rtguard/status")
async def rtguard_status():
    """实时防护状态（rtguard 未运行时降级为 available:false，不报 500）"""
    st = await asyncio.to_thread(_rtguard_probe)
    if st is None:
        return _rtguard_unavailable()
    return st


@app.post("/api/v1/rtguard/start")
async def rtguard_start(data: dict = Body(default={})):
    """拉起 rtguard（pythonw，脱离本进程会话）。已在跑就直接返回，不重复拉起。"""
    try:
        level = str((data or {}).get("level") or _RTGUARD_DEFAULT_LEVEL).strip().lower()
    except Exception:
        level = _RTGUARD_DEFAULT_LEVEL
    if level not in _RTGUARD_LEVELS:
        level = _RTGUARD_DEFAULT_LEVEL
    res = await asyncio.to_thread(_rtguard_ensure_started, level)
    st = res.get("status") or _rtguard_unavailable()
    if not res.get("started") and not res.get("already_running"):
        return {"success": False, "available": False,
                "error": res.get("error") or "rtguard 启动失败", "status": st}
    return {"success": bool(st.get("available")),
            "available": bool(st.get("available")),
            "started": bool(res.get("started")),
            "already_running": bool(res.get("already_running")),
            "error": res.get("error") or "",
            "status": st}


@app.post("/api/v1/rtguard/throttle")
async def rtguard_throttle(data: dict = Body(default={})):
    """切换实时防护 CPU 档位；rtguard 没跑就先拉起来再切（按钮点了就得有反应）"""
    try:
        level = str((data or {}).get("level", "")).strip().lower()
    except Exception:
        level = ""
    if level not in _RTGUARD_LEVELS:
        return JSONResponse({"success": False, "available": False,
                             "error": f"非法档位: {level}（只支持 low/medium/high）"}, 400)
    st = await asyncio.to_thread(_rtguard_probe)
    if st is None:
        res = await asyncio.to_thread(_rtguard_ensure_started, level)
        st = res.get("status") or _rtguard_unavailable()
        if not st.get("available"):
            return {"success": False, "available": False,
                    "error": res.get("error") or "rtguard 未运行", "status": st}
        return {"success": st.get("level") == level, "available": True,
                "started": True, "level": st.get("level"), "status": st}
    try:
        raw = await asyncio.to_thread(_rtguard_http, "POST", "/api/throttle",
                                      {"level": level}, 5.0)
    except Exception as exc:
        return {"success": False, "available": False, "error": f"rtguard 未响应: {exc}",
                "status": _rtguard_unavailable(f"rtguard 未响应: {exc}")}
    st = _rtguard_normalize(raw)
    return {"success": bool(raw.get("ok", True)), "available": True,
            "level": st.get("level"), "status": st}


# ---------- 根路由 ----------

@app.get("/")
async def root():
    """返回前端主页"""
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return {
        "service": "御天 Engine",
        "version": ENGINE_VERSION,
        "status": "running"
    }


@app.get("/api/v1/version")
async def get_version():
    """获取引擎版本信息"""
    try:
        perf = scheduler.scanner.get_perf_stats()
        yara_total = len(scheduler.yara.rules) if scheduler.yara else 0
        yara_pe = len(scheduler.yara._rules_pe) if scheduler.yara else 0
        yara_generic = len(scheduler.yara._rules_generic) if scheduler.yara else 0
        return {
            "version": ENGINE_VERSION,
            "name": ENGINE_VERSION_NAME,
            "api": ENGINE_VERSION,
            "engine": {
                "total_scans": perf.get("total_scans", 0),
                "cache_hits": perf.get("cache_hits", 0),
                "cache_hit_rate": perf.get("cache_hit_rate", 0),
                "avg_scan_time_ms": perf.get("avg_scan_time_ms", 0),
            },
            "yara": {
                "total_rules": yara_total,
                "pe_rules": yara_pe,
                "generic_rules": yara_generic,
            },
            "features": ["single-pass-io", "scan-cache", "yara-index", "adaptive-workers", "perf-stats"],
        }
    except Exception as e:
        return {
            "version": ENGINE_VERSION,
            "name": ENGINE_VERSION_NAME,
            "api": ENGINE_VERSION,
        }


# ── 用户协议确认 API ──

@app.post("/api/v1/agreement/accept")
async def agreement_accept():
    """用户同意协议"""
    try:
        _save_agreement()
        return {"success": True, "message": "协议已确认"}
    except Exception as e:
        return JSONResponse({"success": False, "error": f"保存失败: {str(e)}"}, 500)


@app.post("/api/v1/agreement/reject")
async def agreement_reject():
    """用户拒绝协议（记录日志，前端负责关闭窗口）"""
    print("[御天] 用户拒绝了用户协议")
    return {"success": True}


@app.get("/api/v1/agreement/status")
async def agreement_status():
    """查询协议确认状态"""
    return {"accepted": _is_agreement_accepted()}


@app.get("/{page}.html")
async def serve_page(page: str):
    """提供前端 HTML 页面"""
    if ".." in page or "/" in page or "\\" in page:
        return JSONResponse({"error": "无效的页面名称"}, 400)
    file_path = os.path.join(FRONTEND_DIR, f"{page}.html")
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    return JSONResponse({"error": "页面不存在"}, 404)


# ---------- 工具 API ----------

@app.get("/api/v1/utils/pick-folder")
async def pick_folder():
    """打开原生文件夹选择对话框，返回选中路径"""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        folder = filedialog.askdirectory(title="选择要扫描的文件夹")
        root.destroy()
        if folder:
            return {"path": folder}
        return {"path": None}
    except Exception as e:
        return {"path": None, "error": str(e)}


# ---------- 启动项扫描 API ----------

@app.get("/api/v1/startup/scan")
async def startup_scan():
    """扫描所有启动项"""
    try:
        from engine.startup_scanner import scan_all
        return scan_all()
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/startup/disable")
async def startup_disable(data: dict):
    """禁用指定启动项（删除注册表项/禁用计划任务）"""
    source = data.get("source", "")
    location = data.get("location", "")
    name = data.get("name", "")
    try:
        if source == "registry":
            import winreg
            parts = location.split("\\", 2)
            if len(parts) >= 3:
                hive_map = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
                hive = hive_map.get(parts[0])
                subkey = "\\".join(parts[1:-1])
                value_name = parts[-1]
                if hive:
                    key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE)
                    winreg.DeleteValue(key, value_name)
                    winreg.CloseKey(key)
                    return {"success": True, "message": f"已删除注册表项: {name}"}
        elif source == "scheduled_task":
            import subprocess
            task_name = location.replace("Task Scheduler\\", "")
            subprocess.run(["schtasks", "/change", "/tn", task_name, "/disable"],
                           capture_output=True, timeout=10)
            return {"success": True, "message": f"已禁用计划任务: {name}"}
        return {"success": False, "error": "不支持的操作"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------- 网络监控 API ----------

@app.get("/api/v1/network/scan")
async def network_scan():
    """扫描当前网络连接"""
    try:
        from engine.network_monitor import get_network_monitor
        nm = get_network_monitor()
        return nm.scan_summary()
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/network/monitor/toggle")
async def network_monitor_toggle(data: dict):
    """启停网络监控"""
    enabled = data.get("enabled", True)
    try:
        from engine.network_monitor import get_network_monitor
        from engine.policy_manager import update_policy
        nm = get_network_monitor()
        if enabled:
            nm.start_monitor(interval=5)
        else:
            nm.stop_monitor()
        update_policy(enable_network_monitor=enabled)
        return {"enabled": enabled}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# ---------- 安全策略 API ----------

@app.get("/api/v1/policy")
async def policy_get():
    """获取安全策略"""
    try:
        from engine.policy_manager import load_policy
        return load_policy()
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/policy")
async def policy_update(data: dict):
    """更新安全策略"""
    try:
        from engine.policy_manager import update_policy
        return update_policy(**data)
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# ---------- 病毒记忆 API ----------

virus_memory = get_virus_memory()

@app.get("/api/v1/history/viruses")
async def get_virus_history(limit: int = 100, keyword: str = "",
                             virus_type: str = "", engine: str = ""):
    """获取病毒扫描历史记录"""
    return virus_memory.get_recent_viruses(limit, keyword, virus_type, engine)

@app.get("/api/v1/history/virus-stats")
async def get_virus_stats():
    """获取病毒类型统计"""
    return {
        "type_count": virus_memory.get_virus_count(),
        "engine_stats": virus_memory.get_engine_stats(),
        "total_records": virus_memory.get_total_count(),
        "unique_types": virus_memory.get_unique_virus_types()
    }

@app.get("/api/v1/history/virus-types")
async def get_virus_types():
    """获取所有病毒类型列表"""
    return {"types": virus_memory.get_unique_virus_types()}

@app.get("/api/v1/history/virus-family")
async def get_virus_family(limit: int = 20):
    """病毒家族分布 topN（供历史页家族图渲染）"""
    try:
        if limit < 1 or limit > 100:
            limit = 20
        return {"families": virus_memory.get_family_stats(limit)}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)

@app.post("/api/v1/history/clear")
async def clear_virus_history():
    """清空病毒记忆记录"""
    success = virus_memory.clear_memory()
    return {"success": success}

# ---------- 白名单 API ----------

@app.get("/api/v1/whitelist")
async def whitelist_get():
    """获取白名单"""
    try:
        from engine.policy_manager import load_whitelist
        return load_whitelist()
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/whitelist/add")
async def whitelist_add(data: dict):
    """添加白名单"""
    category = data.get("category", "paths")
    value = data.get("value", "")
    note = data.get("note", "")
    try:
        from engine.policy_manager import whitelist_add_path, whitelist_add_hash
        if category == "paths":
            return whitelist_add_path(value, note)
        elif category == "hashes":
            return whitelist_add_hash(value, note)
        return {"error": "不支持的类别"}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/whitelist/remove")
async def whitelist_remove(data: dict):
    """移除白名单"""
    category = data.get("category", "")
    value = data.get("value", "")
    try:
        from engine.policy_manager import whitelist_remove
        return whitelist_remove(category, value)
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/whitelist/check")
async def whitelist_check(data: dict):
    """检查是否在白名单"""
    path = data.get("path", "")
    file_hash = data.get("hash", "")
    try:
        from engine.policy_manager import is_whitelisted
        return {"whitelisted": is_whitelisted(path=path, file_hash=file_hash)}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# ---------- 文件哈希 API ----------

@app.post("/api/v1/hash/file")
async def hash_file(data: dict):
    """计算文件哈希"""
    path = data.get("path", "")
    if not path or not os.path.isfile(path):
        return JSONResponse({"error": "文件不存在"}, 404)
    try:
        from engine.policy_manager import file_all_hashes
        return file_all_hashes(path)
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/hash/directory")
async def hash_directory(data: dict):
    """批量计算目录哈希"""
    path = data.get("path", "")
    max_files = data.get("max_files", 200)
    if not path or not os.path.isdir(path):
        return JSONResponse({"error": "目录不存在"}, 404)
    try:
        from engine.policy_manager import batch_hash_directory
        results = batch_hash_directory(path, max_files=max_files)
        return {"total": len(results), "results": results}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# ---------- 防篡改 API ----------

@app.post("/api/v1/integrity/build")
async def integrity_build():
    """建立完整性基线"""
    try:
        from engine.integrity import build_integrity_baseline
        baseline = build_integrity_baseline()
        return {"status": "ok", "total_files": len(baseline)}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.get("/api/v1/integrity/check")
async def integrity_check():
    """检查完整性"""
    try:
        from engine.integrity import check_integrity
        return check_integrity()
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# ---------- 破军引擎 API (C++ Native Engine) ----------

@app.get("/api/v1/native/version")
async def native_version():
    """破军引擎版本信息"""
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        return eng.version() or {"error": "native engine not available"}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.get("/api/v1/native/selftest")
async def native_selftest():
    """原生引擎自检"""
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        return eng.self_test() or {"error": "native engine not available"}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# -- SHA256 哈希 --

@app.post("/api/v1/native/sha256/file")
async def native_sha256_file(data: dict):
    """计算文件 SHA256（CryptoAPI 原生实现，速度远超 Python）"""
    path = data.get("path", "")
    if not path:
        return JSONResponse({"error": "请提供文件路径"}, 400)
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.sha256_file(path)
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/native/sha256/dir")
async def native_sha256_dir(data: dict):
    """批量计算目录文件哈希"""
    path = data.get("path", "")
    max_files = data.get("max_files", 500)
    if not path:
        return JSONResponse({"error": "请提供目录路径"}, 400)
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.sha256_directory(path, max_files)
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return {"files": result}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/native/sha256/blacklist")
async def native_sha256_blacklist(data: dict):
    """SHA256 黑名单校验（MalwareBazaar 匹配）"""
    path = data.get("path", "")
    blacklist = data.get("blacklist", "")
    if not path or not blacklist:
        return JSONResponse({"error": "请提供文件路径和黑名单"}, 400)
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.sha256_check_blacklist(path, blacklist)
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# -- PE 解析 --

@app.post("/api/v1/native/pe/parse")
async def native_pe_parse(data: dict):
    """完整 PE 静态解析（DOS头/NT头/节表/导入表/熵值/字符串提取）"""
    path = data.get("path", "")
    if not path:
        return JSONResponse({"error": "请提供文件路径"}, 400)
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.pe_parse_full(path)
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/native/pe/quick")
async def native_pe_quick(data: dict):
    """快速 PE 校验"""
    path = data.get("path", "")
    if not path:
        return JSONResponse({"error": "请提供文件路径"}, 400)
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.pe_quick_check(path)
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# -- 启发式检测 --

@app.post("/api/v1/native/heuristic/score")
async def native_heuristic_score(data: dict):
    """基于PE解析结果进行启发式风险打分"""
    pe_json = data.get("pe_result", {})
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.heuristic_score(pe_json)
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/native/heuristic/scan")
async def native_heuristic_scan(data: dict):
    """一站式 PE 分析 + 启发式打分"""
    path = data.get("path", "")
    if not path:
        return JSONResponse({"error": "请提供文件路径"}, 400)
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        # 第一步: PE 解析
        pe_result = eng.pe_parse_full(path)
        if not pe_result or pe_result.get("error"):
            return JSONResponse({"error": "PE解析失败", "pe_error": pe_result.get("error", "")}, 500)
        # 第二步: 启发式打分
        score = eng.heuristic_score(pe_result)
        if score is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return {
            "path": path,
            "pe_info": pe_result,
            "heuristic": score
        }
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# -- 系统巡检 --

@app.get("/api/v1/native/processes")
async def native_processes():
    """枚举全部运行进程"""
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.enum_processes()
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.get("/api/v1/native/startup")
async def native_startup():
    """扫描开机启动项"""
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.scan_startup()
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.get("/api/v1/native/network")
async def native_network():
    """枚举进程网络连接"""
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.enum_network()
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.get("/api/v1/native/sysinfo")
async def native_sysinfo():
    """系统摘要信息"""
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.sys_summary()
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# -- 隔离区（原生 C++）--

@app.post("/api/v1/native/quarantine/move")
async def native_quarantine_move(data: dict):
    """移动文件到隔离区（加密）"""
    path = data.get("path", "")
    qdir = data.get("quarantine_dir", "")
    if not path:
        return JSONResponse({"error": "请提供文件路径"}, 400)
    if not qdir:
        from config import QUARANTINE_DIR
        qdir = QUARANTINE_DIR
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.quarantine_move(path, qdir)
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/native/quarantine/restore")
async def native_quarantine_restore(data: dict):
    """从隔离区恢复文件"""
    quar_path = data.get("quarantine_path", "")
    restore_dir = data.get("restore_dir", "")
    if not quar_path:
        return JSONResponse({"error": "请提供隔离文件路径"}, 400)
    if not restore_dir:
        restore_dir = os.path.expanduser("~\\Desktop")
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.quarantine_restore(quar_path, restore_dir)
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/native/quarantine/delete")
async def native_quarantine_delete(data: dict):
    """永久删除隔离文件（安全覆写）"""
    quar_path = data.get("quarantine_path", "")
    if not quar_path:
        return JSONResponse({"error": "请提供隔离文件路径"}, 400)
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.quarantine_delete(quar_path)
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.get("/api/v1/native/quarantine/list")
async def native_quarantine_list():
    """列出隔离区文件"""
    from config import QUARANTINE_DIR
    qdir = QUARANTINE_DIR
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.quarantine_list(qdir)
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# ==================== 安全工具 API ====================

# ── 断网急救 ──

@app.get("/api/v1/network/check")
async def network_check():
    """检查网络状态"""
    return network_repair.check_network()

@app.post("/api/v1/network/repair-hosts")
async def network_repair_hosts():
    """修复 HOSTS 文件"""
    return network_repair.repair_hosts()

@app.post("/api/v1/network/repair-dns")
async def network_repair_dns():
    """刷新 DNS 缓存"""
    return network_repair.repair_dns()

@app.post("/api/v1/network/repair-lsp")
async def network_repair_lsp():
    """重置 Winsock/LSP"""
    return network_repair.repair_lsp()

@app.post("/api/v1/network/repair-all")
async def network_repair_all():
    """一键断网急救"""
    return network_repair.repair_all()

@app.get("/api/v1/network/history")
async def network_history():
    """获取修复历史"""
    return {"history": network_repair.get_history()}

# ── 弹窗拦截 ──

@app.get("/api/v1/adblock/status")
async def adblock_status():
    """弹窗拦截状态"""
    return adblock.get_status()

@app.post("/api/v1/adblock/toggle")
async def adblock_toggle(data: ToggleRequest):
    """切换弹窗拦截"""
    if data.enabled:
        adblock.enable()
    else:
        adblock.disable()
    return {"enabled": data.enabled}

@app.get("/api/v1/adblock/stats")
async def adblock_stats():
    """弹窗拦截统计"""
    return adblock.get_stats()

@app.post("/api/v1/adblock/strict-mode")
async def adblock_strict(data: dict):
    """设置严格模式"""
    adblock.set_strict_mode(data.get("enabled", False))
    return {"strict_mode": data.get("enabled", False)}

# ── 下载防护 ──

@app.get("/api/v1/download-guard/status")
async def download_guard_status():
    """下载防护状态"""
    return download_guard.get_status()

@app.post("/api/v1/download-guard/toggle")
async def download_guard_toggle(data: ToggleRequest):
    """切换下载防护"""
    if data.enabled:
        download_guard.enable()
    else:
        download_guard.disable()
    return {"enabled": data.enabled}

@app.get("/api/v1/download-guard/stats")
async def download_guard_stats():
    """下载防护统计"""
    return download_guard.get_stats()

@app.get("/api/v1/download-guard/dirs")
async def download_guard_dirs():
    """获取监控目录"""
    return {"dirs": download_guard.get_watch_dirs()}

@app.post("/api/v1/download-guard/dir-add")
async def download_guard_dir_add(data: dict):
    """添加监控目录"""
    path = data.get("path", "")
    ok = download_guard.add_watch_dir(path)
    return {"success": ok, "dirs": download_guard.get_watch_dirs()}

@app.post("/api/v1/download-guard/dir-remove")
async def download_guard_dir_remove(data: dict):
    """移除监控目录"""
    path = data.get("path", "")
    download_guard.remove_watch_dir(path)
    return {"success": True, "dirs": download_guard.get_watch_dirs()}

# ── 网址/网页防护 ──

@app.get("/api/v1/urlguard/status")
async def urlguard_status():
    """网址防护状态"""
    return url_guard.get_status()

@app.post("/api/v1/urlguard/toggle")
async def urlguard_toggle(data: ToggleRequest):
    """切换网址防护"""
    enabled = url_guard.set_enabled(data.enabled)
    return {"enabled": enabled}

@app.post("/api/v1/urlguard/check")
async def urlguard_check(data: dict):
    """检测一条 URL/域名"""
    result = url_guard.check_url(data.get("url", ""))
    return result

@app.post("/api/v1/urlguard/block")
async def urlguard_block(data: dict):
    """将域名加入阻断名单"""
    ok = url_guard.block_domain(data.get("url", ""))
    return {"success": ok, "blocked": url_guard.get_blocked_domains()}

@app.post("/api/v1/urlguard/unblock")
async def urlguard_unblock(data: dict):
    """从阻断名单移除"""
    url_guard.unblock_domain(data.get("url", ""))
    return {"success": True, "blocked": url_guard.get_blocked_domains()}

@app.get("/api/v1/urlguard/blocked")
async def urlguard_blocked():
    """阻断名单"""
    return {"blocked": url_guard.get_blocked_domains()}

@app.post("/api/v1/urlguard/hosts-sync")
async def urlguard_hosts_sync(data: dict):
    """应用/清除 hosts 阻断"""
    return url_guard.sync_hosts(bool(data.get("enabled", False)))

@app.post("/api/v1/urlguard/whitelist-add")
async def urlguard_whitelist_add(data: dict):
    """加入访问白名单"""
    ok = url_guard.add_whitelist(data.get("url", ""))
    return {"success": ok, "whitelist": url_guard.get_whitelist()}

@app.post("/api/v1/urlguard/whitelist-remove")
async def urlguard_whitelist_remove(data: dict):
    """移出访问白名单"""
    url_guard.remove_whitelist(data.get("url", ""))
    return {"success": True, "whitelist": url_guard.get_whitelist()}

@app.get("/api/v1/urlguard/whitelist")
async def urlguard_whitelist():
    """访问白名单"""
    return {"whitelist": url_guard.get_whitelist()}

# ── 系统漏洞修复 ──

@app.post("/api/v1/vulnfix/scan")
async def vulnfix_scan():
    """扫描系统漏洞"""
    return vuln_fix.scan()

@app.get("/api/v1/vulnfix/status")
async def vulnfix_status():
    """漏洞修复状态"""
    return vuln_fix.get_status()

@app.post("/api/v1/vulnfix/open-update")
async def vulnfix_open_update():
    """唤起系统更新引导修复"""
    return vuln_fix.open_windows_update()

@app.post("/api/v1/vulnfix/ignore")
async def vulnfix_ignore(data: dict):
    """忽略指定补丁（不再提示）"""
    ok = vuln_fix.ignore(str(data.get("kb", "")))
    return {"success": ok, "status": vuln_fix.get_status()}

@app.post("/api/v1/vulnfix/unignore")
async def vulnfix_unignore(data: dict):
    """取消忽略指定补丁（恢复提示）"""
    ok = vuln_fix.unignore(str(data.get("kb", "")))
    return {"success": ok, "status": vuln_fix.get_status()}

# ── 进程启动拦截 ──

@app.get("/api/v1/process-guard/status")
async def process_guard_status():
    """进程拦截状态"""
    return process_guard_tool.get_status()

@app.post("/api/v1/process-guard/toggle")
async def process_guard_toggle(data: ToggleRequest):
    """切换进程拦截"""
    if data.enabled:
        process_guard_tool.enable()
    else:
        process_guard_tool.disable()
    return {"enabled": data.enabled}

@app.get("/api/v1/process-guard/stats")
async def process_guard_stats():
    """进程拦截统计"""
    return process_guard_tool.get_stats()

@app.get("/api/v1/process-guard/lists")
async def process_guard_lists():
    """获取黑白名单"""
    return process_guard_tool.get_lists()

@app.post("/api/v1/process-guard/blacklist-add")
async def process_guard_blacklist_add(data: dict):
    """添加进程黑名单"""
    name = data.get("name", "")
    process_guard_tool.add_to_blacklist(name)
    return {"success": True}

@app.post("/api/v1/process-guard/blacklist-remove")
async def process_guard_blacklist_remove(data: dict):
    """移除进程黑名单"""
    name = data.get("name", "")
    process_guard_tool.remove_from_blacklist(name)
    return {"success": True}

@app.post("/api/v1/process-guard/whitelist-add")
async def process_guard_whitelist_add(data: dict):
    """添加进程白名单"""
    name = data.get("name", "")
    process_guard_tool.add_to_whitelist(name)
    return {"success": True}


# 原先只有 whitelist-add 没有 remove —— 加进白名单就撤不回来（黑名单那边
# 一直是有 add/remove 一对的）。补上，否则"名单管理"里白名单每项都会是个死条目。
@app.post("/api/v1/process-guard/whitelist-remove")
async def process_guard_whitelist_remove(data: dict):
    """移除进程白名单"""
    name = data.get("name", "")
    process_guard_tool.remove_from_whitelist(name)
    return {"success": True}

# ── 注册表监控 ──

@app.get("/api/v1/registry-guard/status")
async def registry_guard_status():
    """注册表监控状态"""
    return registry_guard.get_status()

@app.post("/api/v1/registry-guard/toggle")
async def registry_guard_toggle(data: ToggleRequest):
    """切换注册表监控"""
    if data.enabled:
        registry_guard.enable()
    else:
        registry_guard.disable()
    return {"enabled": data.enabled}

@app.get("/api/v1/registry-guard/stats")
async def registry_guard_stats():
    """注册表监控统计"""
    return registry_guard.get_stats()

@app.get("/api/v1/registry-guard/changes")
async def registry_guard_changes():
    """获取注册表变更记录"""
    return {"changes": registry_guard.get_changes()}

@app.post("/api/v1/registry-guard/auto-restore")
async def registry_guard_auto_restore(data: dict):
    """设置自动恢复"""
    registry_guard.set_auto_restore(data.get("enabled", True))
    return {"auto_restore": data.get("enabled", True)}

# ── 高危行为阻断 ──

@app.get("/api/v1/behavior-block/status")
async def behavior_block_status():
    """高危行为阻断状态"""
    return behavior_block.get_status()

@app.post("/api/v1/behavior-block/toggle")
async def behavior_block_toggle(data: ToggleRequest):
    """切换高危行为阻断"""
    if data.enabled:
        behavior_block.enable()
    else:
        behavior_block.disable()
    return {"enabled": data.enabled}

@app.get("/api/v1/behavior-block/stats")
async def behavior_block_stats():
    """高危行为阻断统计"""
    return behavior_block.get_stats()


# ---------- 启动入口 ----------

# ── 双进程互保（进程自保护） ──

def _run_watchdog_mode():
    """守护模式入口：监控主进程，意外退出时重启主进程"""
    import ctypes
    import ctypes.wintypes as wt
    import time
    import os
    import subprocess

    idx = sys.argv.index('--parent-pid')
    parent_pid = int(sys.argv[idx + 1])
    is_frozen = getattr(sys, 'frozen', False)
    import tempfile
    clean_exit_file = os.path.join(tempfile.gettempdir(), ".andun_clean_exit")

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    handle = kernel32.OpenProcess(0x00100000, False, parent_pid)
    if not handle:
        return 1

    kernel32.WaitForSingleObject(handle, -1)
    kernel32.CloseHandle(handle)

    if os.path.isfile(clean_exit_file):
        try:
            os.unlink(clean_exit_file)
        except Exception:
            pass
        return 0
    else:
        time.sleep(2)
        if is_frozen:
            subprocess.Popen([sys.argv[0]])
        else:
            subprocess.Popen([sys.executable, sys.argv[0]])
        return 0


def _start_self_protection():
    """主进程：启动守护 + 退出清理 + 守护重启"""
    import subprocess
    import atexit
    import time
    import tempfile
    import ctypes
    import os

    clean_exit_file = os.path.join(tempfile.gettempdir(), ".andun_clean_exit")
    wd_cmd = []
    if getattr(sys, 'frozen', False):
        wd_cmd = [sys.argv[0]]
    else:
        wd_cmd = [sys.executable, os.path.abspath(__file__)]
    wd_cmd.extend(['--watchdog', '--parent-pid', str(os.getpid())])

    try:
        wd_proc = subprocess.Popen(wd_cmd, close_fds=True)
    except Exception:
        return

    @atexit.register
    def _clean_exit():
        try:
            with open(clean_exit_file, 'w') as f:
                f.write('1')
        except Exception:
            pass
        if wd_proc and wd_proc.poll() is None:
            try:
                wd_proc.terminate()
                wd_proc.wait(timeout=5)
            except Exception:
                pass

    def _wd_watcher():
        nonlocal wd_proc
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        while True:
            try:
                handle = kernel32.OpenProcess(0x00100000, False, wd_proc.pid)
                if not handle:
                    break
                kernel32.WaitForSingleObject(handle, -1)
                kernel32.CloseHandle(handle)
            except Exception:
                break
            time.sleep(2)
            try:
                new_wd = subprocess.Popen(wd_cmd, close_fds=True)
                wd_proc = new_wd
            except Exception:
                break

    t = threading.Thread(target=_wd_watcher, daemon=True)
    t.start()


# ══════════════════════════════════════════════════════════════
#  Logo 退出流程（淡出动画 + 资源释放 + 进程退出）
# ══════════════════════════════════════════════════════════════

def _shutdown_and_exit(code: int = 0):
    """统一的收尾流程：保存状态 → 释放引擎资源 → 写正常退出标记 → 退出进程。"""
    # 1. 保存配置
    try:
        save_config_save({
            "protection": _protection_modules,
            "features": _feature_toggles,
        })
    except Exception:
        pass

    # 2. 保存守护天数
    #    原写法是：
    #        save_guard_days(load_guard_days() if 'load_guard_days' in dir() else _guard_data)
    #    ⚠️ 更正（先前我判断错了）：`_guard_data` 在模块层**是存在的**
    #    （第 115 行 `_guard_data = update_guard_days()`），所以这句不会抛异常、
    #    守护天数**确实保存了**。真正的问题是这个三元表达式**永远走 else 分支**：
    #    `dir()` 在函数内返回的是**局部**名字，而 `load_guard_days` 不在这个函数的
    #    局部里，条件恒为假 → 存的始终是模块级启动快照 `_guard_data`，
    #    左边那个 `load_guard_days()` 是死代码。
    #    影响很有限（该值本就只在启动时更新一次），但语义与代码意图不符。
    #    这里显式导入，改成退出时重新读取。
    try:
        from persistence import load_guard_days
        save_guard_days(load_guard_days())
    except Exception:
        pass
    print("[御天] 状态已保存")

    # 3. 释放引擎资源
    try:
        from engine_loader import release_engine_resources
        release_engine_resources()
    except Exception:
        pass

    # 4. 正常退出标记 + 退出进程
    print("[御天] 再见")
    try:
        import tempfile
        clean_exit = os.path.join(tempfile.gettempdir(), ".andun_clean_exit")
        with open(clean_exit, 'w') as f:
            f.write('1')
    except Exception:
        pass
    os._exit(code)


def _do_exit_with_fadeout():
    """统一的退出入口（托盘菜单 on_exit 与 POST /api/v1/shutdown 都在调它）。

    函数名里的 "fadeout" 已经名不副实 —— Logo 淡出是 webview 时代的产物，
    随 webview 链路一起删掉了。保留旧名字只是为了不改两个调用点。
    """
    # 诊断：后端一整天在"自己消失"，日志里只有 [御天] 再见、没有任何 HTTP
    # 请求痕迹，说明是进程内部某处调了这里。把调用栈打出来，一次就能点名。
    try:
        import traceback as _tb
        print("[御天][诊断] _do_exit_with_fadeout 被调用，调用栈如下：")
        _tb.print_stack()
        print("[御天][诊断] 调用栈结束")
    except Exception:
        pass
    _shutdown_and_exit(0)


# ==================== 健康检查与监控 ====================

# 启动时间（用于计算运行时长）
_START_TIME = time.time()

@app.get('/api/health')
async def health_check():
    """健康检查：签名库版本、引擎版本、运行时长、内存占用"""
    import psutil
    import platform

    driver_status = False   # 内核驱动防护层已移除

    # 内存占用
    process = psutil.Process(os.getpid())
    mem = process.memory_info()

    # 磁盘空间（签名库所在盘）
    disk_usage = None
    try:
        db_dir = os.path.dirname(sig_mgr.db_path)
        du = psutil.disk_usage(db_dir)
        disk_usage = {
            "total_gb": round(du.total / (1024**3), 2),
            "used_gb": round(du.used / (1024**3), 2),
            "free_gb": round(du.free / (1024**3), 2),
            "percent": du.percent,
        }
    except Exception:
        pass

    # 签名库统计
    sig_stats = sig_mgr.get_stats()
    sig_version = sig_mgr.get_bingduku_version()

    return {
        "status": "ok",
        "uptime_seconds": int(time.time() - _START_TIME),
        "engine_version": ENGINE_VERSION,
        "engine_version_name": ENGINE_VERSION_NAME,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "driver": driver_status,
        "signatures": {
            "version": sig_version,
            "total": sig_stats.get("total_signatures", 0),
            "db_path": sig_mgr.db_path,
        },
        "memory": {
            "rss_mb": round(mem.rss / (1024**2), 2),
            "vms_mb": round(mem.vms / (1024**2), 2),
        },
        "disk": disk_usage,
        "disk_status": "warning" if (disk_usage and disk_usage["percent"] > 90) else "ok",
    }

# ==================== 配置热加载 ====================

@app.post('/api/config/reload')
async def config_reload():
    """运行时重载配置（无需重启进程）"""
    try:
        from persistence import load_config_save
        _persistent_config = load_config_save()

        # 动态更新 config 模块变量
        import config as cfg

        _scan_cfg = _persistent_config.get("scan", {})
        if _scan_cfg.get("max_workers", 0) > 0:
            cfg.MAX_WORKERS = _scan_cfg["max_workers"]
        if _scan_cfg.get("single_file_timeout", 0) > 0:
            cfg.SINGLE_FILE_TIMEOUT = _scan_cfg["single_file_timeout"]
        if _scan_cfg.get("yara_enabled", True) is False:
            cfg.YARA_ENABLED = False
        if _scan_cfg.get("cloud_enabled", True) is False:
            cfg.CLOUD_ENABLED = False

        _net_cfg = _persistent_config.get("network", {})
        if _net_cfg.get("monitor_interval", 0) > 0:
            cfg.NETWORK_MONITOR_INTERVAL = _net_cfg["monitor_interval"]

        _cloud_cfg = _persistent_config.get("cloud", {})
        if _cloud_cfg.get("engine_order"):
            cfg.CLOUD_ENGINE_ORDER = list(_cloud_cfg["engine_order"])
        if _cloud_cfg.get("avic_api_key"):
            cfg.AVIC_API_KEY = _cloud_cfg["avic_api_key"]

        _policy_cfg = _persistent_config.get("policy", {})
        if _policy_cfg.get("log_retention_days", 0) > 0:
            cfg.LOG_RETENTION_DAYS = _policy_cfg["log_retention_days"]

        logging.getLogger("yutian").info("[配置热加载] 配置已刷新")
        return {
            "ok": True,
            "reloaded": {
                "max_workers": cfg.MAX_WORKERS,
                "yara_enabled": getattr(cfg, "YARA_ENABLED", True),
                "cloud_enabled": getattr(cfg, "CLOUD_ENABLED", True),
                "cloud_engine_order": getattr(cfg, "CLOUD_ENGINE_ORDER", []),
                "network_monitor_interval": getattr(cfg, "NETWORK_MONITOR_INTERVAL", 0),
                "log_retention_days": getattr(cfg, "LOG_RETENTION_DAYS", 0),
            },
        }
    except Exception as e:
        logging.getLogger("yutian").error(f"[配置热加载] 失败: {e}")
        return {"ok": False, "error": str(e)}

# ==================== 反 Rootkit 引擎 ====================

@app.post('/api/v1/rootkit/scan')
async def rootkit_scan():
    result = anti_rootkit.scan()
    return result

@app.get('/api/v1/rootkit/status')
async def rootkit_status():
    return anti_rootkit.get_status()

# ==================== 安全产品自保护 ====================

@app.get('/api/v1/self-protect/status')
async def self_protect_status():
    sp = self_protect._get_real()
    return {
        "configured": sp._configured if hasattr(sp, '_configured') else False,
        "install_dir": sp._install_dir if hasattr(sp, '_install_dir') else "",
        "agent_pid": sp._agent_pid if hasattr(sp, '_agent_pid') else 0,
    }

@app.post('/api/v1/self-protect/configure')
async def self_protect_configure(data: dict = Body(...)):
    sp = self_protect._get_real()
    result = sp.configure(
        install_dir=data.get("install_dir", ""),
        agent_pid=data.get("agent_pid", 0),
    )
    return result

@app.get('/api/v1/self-protect/protection-status')
async def self_protect_protection_status():
    sp = self_protect._get_real()
    return {
        "process": True if (hasattr(sp, '_configured') and sp._configured) else False,
        "file": True if (hasattr(sp, '_configured') and sp._configured) else False,
        "registry": True if (hasattr(sp, '_configured') and sp._configured) else False,
        "service": True if (hasattr(sp, '_configured') and sp._configured) else False,
    }

# ==================== 检测→响应闭环（处置中心） ====================

@app.get('/api/v1/response/status')
async def response_status():
    rc = response_center._get_real()
    return {
        "auto_response_enabled": rc._auto_response_enabled if hasattr(rc, '_auto_response_enabled') else False,
        "history_count": len(rc._history) if hasattr(rc, '_history') else 0,
        "temp_rules_count": len(rc._temp_rules) if hasattr(rc, '_temp_rules') else 0,
    }

@app.post('/api/v1/response/auto-response-toggle')
async def response_auto_toggle(data: dict = Body(...)):
    rc = response_center._get_real()
    enabled = data.get("enabled", False)
    rc._auto_response_enabled = enabled
    return {"ok": True, "auto_response_enabled": enabled}

@app.post('/api/v1/response/kill-process')
async def response_kill_process(data: dict = Body(...)):
    rc = response_center._get_real()
    result = rc.kill_process(
        target_pid=data.get("pid", 0),
        force=data.get("force", False),
        source=data.get("source", "api_manual"),
    )
    return result

@app.post('/api/v1/response/quarantine-file')
async def response_quarantine_file(data: dict = Body(...)):
    rc = response_center._get_real()
    result = rc.quarantine_file(
        file_path=data.get("file_path", ""),
        source=data.get("source", "api_manual"),
    )
    return result

@app.post('/api/v1/response/block-rule')
async def response_block_rule(data: dict = Body(...)):
    rc = response_center._get_real()
    rule = {
        "ruleId": data.get("rule_id", 0),
        "ruleType": data.get("rule_type", 1),
        "action": data.get("action", 1),
        "pattern": data.get("pattern", ""),
        "enabled": 1,
    }
    result = rc.block_rule(
        rule=rule,
        auto_remove_sec=data.get("auto_remove_sec", 300),
    )
    return result

@app.get('/api/v1/response/history')
async def response_history(limit: int = 50):
    rc = response_center._get_real()
    return {"history": rc._history[-limit:] if hasattr(rc, '_history') else []}

@app.post('/api/v1/response/rollback')
async def response_rollback(data: dict = Body(...)):
    rc = response_center._get_real()
    count = rc.rollback_expired_rules()
    return {"ok": True, "rolled_back": count}

@app.post('/api/v1/response/handle-correlations')
async def response_handle_correlations(data: dict = Body(...)):
    """处理 ETW 攻击链事件，自动触发处置"""
    rc = response_center._get_real()
    correlations = data.get("correlations", [])
    results = rc.handle_correlations(correlations)
    return {"ok": True, "results": results}

# ==================== 签名库增量更新 ====================

@app.get('/api/v1/signatures/version-check')
async def signatures_version_check():
    """检查病毒库版本，支持增量更新判断"""
    current = sig_mgr.get_bingduku_version()
    return {
        "current_version": current,
        "has_version": current is not None,
    }

@app.post('/api/v1/signatures/import-incremental')
async def signatures_import_incremental(data: dict = Body(...)):
    """
    增量导入病毒库（版本号对比 + 仅导入新签名）。
    :param file_path: 本地病毒库文件路径
    :param version: 病毒库版本号（如 bingduku_20260419）
    """
    file_path = data.get("file_path", "")
    version = data.get("version", "")
    if not file_path or not version:
        return {"error": "file_path and version are required"}
    result = sig_mgr.import_md5_incremental(file_path, version)
    return result

@app.get('/api/v1/signatures/download/check')
async def signatures_download_check(url: str = ""):
    """检查远程病毒库是否有更新"""
    if not url:
        url = "http://shadu.zh.kg/downloads/bingduku_version.json"
    result = sig_downloader.check_bingduku_update(url)
    return result

# ==================== 自定义规则 ====================

@app.get('/api/v1/rules/list')
async def rules_list(rule_type: str = None):
    return {'rules': custom_rules.get_rules(rule_type)}

@app.post('/api/v1/rules/add')
async def rules_add(data: dict = Body(...)):
    rule = custom_rules.add_rule(data.get('rule_type', 'file'), data.get('action', 'block'), data.get('pattern', ''), data.get('description', ''))
    return {'ok': True, 'rule': rule}

@app.post('/api/v1/rules/remove')
async def rules_remove(data: dict = Body(...)):
    ok = custom_rules.remove_rule(data.get('rule_id', 0))
    return {'ok': ok}

@app.post('/api/v1/rules/toggle')
async def rules_toggle(data: dict = Body(...)):
    custom_rules.toggle_rule(data.get('rule_id', 0), data.get('enabled', True))
    return {'ok': True}

@app.get('/api/v1/rules/templates')
async def rules_templates():
    return {'templates': custom_rules.get_templates()}

@app.post('/api/v1/rules/import')
async def rules_import(data: dict = Body(...)):
    custom_rules.import_rules(data.get('rules', []))
    return {'ok': True}

@app.get('/api/v1/rules/export')
async def rules_export():
    return {'rules': custom_rules.export_rules()}

@app.get('/api/v1/rules/stats')
async def rules_stats():
    try:
        rules = custom_rules.get_rules()
        return {'total_rules': len(rules), 'rules': rules}
    except Exception:
        return {'total_rules': 0, 'rules': []}

# ==================== 勒索诱捕 ====================

@app.get('/api/v1/honeypot/status')
async def honeypot_status():
    return honeypot_manager.get_status()

@app.post('/api/v1/honeypot/deploy')
async def honeypot_deploy(data: dict = Body(...)):
    result = honeypot_manager.deploy(data.get('directories', []))
    return result

@app.post('/api/v1/honeypot/recall')
async def honeypot_recall():
    result = honeypot_manager.recall()
    return result

@app.get('/api/v1/honeypot/list')
async def honeypot_list():
    return {'decoys': honeypot_manager.get_decoys()}

@app.get('/api/v1/honeypot/stats')
async def honeypot_stats():
    try:
        st = honeypot_manager.get_status()
        decoys = honeypot_manager.get_decoys()
        return {
            'enabled': bool(st.get('monitoring', st.get('active', False))),
            'catch_count': len(decoys),
            'decoy_files': [d.get('path') if isinstance(d, dict) else d for d in decoys],
            'recent_catches': [],
        }
    except Exception:
        return {'enabled': False, 'catch_count': 0, 'decoy_files': [], 'recent_catches': []}

@app.post('/api/v1/honeypot/toggle')
async def honeypot_toggle(data: dict = Body(...)):
    try:
        if data.get('enabled'):
            honeypot_manager.deploy([])
        else:
            honeypot_manager.recall()
    except Exception:
        pass
    st = honeypot_manager.get_status()
    return {'ok': True, 'enabled': bool(st.get('monitoring', st.get('active', False)))}

# ==================== 浏览器保护 ====================

@app.get('/api/v1/browser-guard/status')
async def browser_guard_status():
    return browser_guard.get_status()

@app.post('/api/v1/browser-guard/toggle')
async def browser_guard_toggle(data: dict = Body(...)):
    if data.get('enabled'):
        browser_guard.enable()
    else:
        browser_guard.disable()
    return {'ok': True}

@app.get('/api/v1/browser-guard/check')
async def browser_guard_check():
    return {'issues': browser_guard.check_browser_integrity()}

@app.get('/api/v1/browser-guard/stats')
async def browser_guard_stats():
    try:
        st = browser_guard.get_status()
        issues = browser_guard.check_browser_integrity()
        return {
            'enabled': bool(st.get('enabled', st.get('active', False))),
            'blocked_count': len(issues),
            'recent_blocks': issues,
        }
    except Exception:
        return {'enabled': False, 'blocked_count': 0, 'recent_blocks': []}

# ==================== 摄像头保护 ====================

@app.get('/api/v1/camera/status')
async def camera_status():
    return camera_guard.get_camera_status()

@app.post('/api/v1/camera/toggle')
async def camera_toggle(data: dict = Body(...)):
    if data.get('enabled'):
        camera_guard.enable()
    else:
        camera_guard.disable()
    return {'ok': True}

@app.get('/api/v1/camera/list')
async def camera_list():
    return {'cameras': camera_guard.get_camera_status()}

@app.get('/api/v1/camera/history')
async def camera_history():
    return {'history': camera_guard.get_access_history()}

@app.post('/api/v1/camera/whitelist/add')
async def camera_whitelist_add(data: dict = Body(...)):
    camera_guard.add_to_whitelist(data.get('process_name', ''))
    return {'ok': True}

@app.post('/api/v1/camera/whitelist/remove')
async def camera_whitelist_remove(data: dict = Body(...)):
    camera_guard.remove_from_whitelist(data.get('process_name', ''))
    return {'ok': True}

@app.get('/api/v1/camera/stats')
async def camera_stats():
    try:
        whitelist = camera_guard.get_whitelist()
        history = camera_guard.get_access_history(100)
        st = camera_guard.get_camera_status()
        return {
            'enabled': bool(st.get('enabled', st.get('active', False))),
            'blocked_count': len(history),
            'whitelist': whitelist,
            'recent_blocks': history,
        }
    except Exception:
        return {'enabled': False, 'blocked_count': 0, 'whitelist': [], 'recent_blocks': []}

# ==================== 隐私保护 ====================

@app.get('/api/v1/privacy/status')
async def privacy_status():
    return privacy_shield.get_status()

@app.post('/api/v1/privacy/toggle')
async def privacy_toggle(data: dict = Body(...)):
    if data.get('enabled'):
        privacy_shield.enable()
    else:
        privacy_shield.disable()
    return {'ok': True}

@app.get('/api/v1/privacy/scan')
async def privacy_scan():
    return privacy_shield.scan_privacy_traces()

@app.post('/api/v1/privacy/clean')
async def privacy_clean(data: dict = Body(...)):
    result = privacy_shield.clean_traces(data.get('categories', []))
    return result

@app.post('/api/v1/privacy/protect-files')
async def privacy_protect_files(data: dict = Body(...)):
    privacy_shield.protect_sensitive_files(data.get('paths', []))
    return {'ok': True}

@app.get('/api/v1/privacy/access-log')
async def privacy_access_log():
    return {'logs': privacy_shield.get_sensitive_file_access_log()}

@app.get('/api/v1/privacy/sensitive-files')
async def privacy_sensitive_files():
    try:
        files = privacy_shield.get_sensitive_files()
        return {'files': [{'path': p} for p in files]}
    except Exception:
        return {'files': []}

@app.post('/api/v1/privacy/sensitive-files')
async def privacy_sensitive_files_add(data: dict = Body(...)):
    try:
        path = data.get('path', '')
        if path:
            privacy_shield.protect_sensitive_files([path])
    except Exception:
        pass
    return {'ok': True}

@app.post('/api/v1/privacy/sensitive-files/delete')
async def privacy_sensitive_files_remove(data: dict = Body(...)):
    try:
        ok = privacy_shield.unprotect_sensitive_file(data.get('id', data.get('path', '')))
    except Exception:
        ok = False
    return {'ok': bool(ok)}

@app.get('/api/v1/privacy/stats')
async def privacy_stats():
    try:
        st = privacy_shield.get_status()
        return {'enabled': bool(st.get('enabled', st.get('active', False))), 'trace_count': 0, 'trace_types': []}
    except Exception:
        return {'enabled': False, 'trace_count': 0, 'trace_types': []}

# ==================== 数据恢复 ====================

@app.get('/api/v1/recovery/status')
async def recovery_status():
    return data_recovery.get_status()

@app.post('/api/v1/recovery/start')
async def recovery_start(data: dict = Body(...)):
    data_recovery.start(data.get('directories', []))
    return {'ok': True}

@app.post('/api/v1/recovery/stop')
async def recovery_stop():
    data_recovery.stop()
    return {'ok': True}

@app.get('/api/v1/recovery/versions')
async def recovery_versions(file_path: str = ''):
    return {'versions': data_recovery.get_versions(file_path)}

@app.post('/api/v1/recovery/restore')
async def recovery_restore(data: dict = Body(...)):
    ok = data_recovery.restore_version(data.get('file_path', ''), data.get('version_id', ''))
    return {'ok': ok}

@app.post('/api/v1/recovery/delete-version')
async def recovery_delete_version(data: dict = Body(...)):
    ok = data_recovery.delete_version(data.get('file_path', ''), data.get('version_id', ''))
    return {'ok': ok}

@app.get('/api/v1/recovery/stats')
async def recovery_stats():
    return data_recovery.get_recovery_stats()

@app.get('/api/v1/recovery/files')
async def recovery_files():
    try:
        return {'files': data_recovery.get_files()}
    except Exception:
        return {'files': []}

@app.get('/api/v1/recovery/settings')
async def recovery_settings_get():
    try:
        return data_recovery.get_settings()
    except Exception:
        return {}

@app.post('/api/v1/recovery/settings')
async def recovery_settings_save(data: dict = Body(...)):
    try:
        retain = int(data.get('retain_days') or 0)
        limit = int(data.get('storage_limit') or 0)
        return data_recovery.save_settings(retain, limit)
    except Exception:
        return {'ok': False}

@app.post('/api/v1/recovery/watch-dirs')
async def recovery_watch_dirs_add(data: dict = Body(...)):
    try:
        ok = data_recovery.add_watch_dir(data.get('dir', ''))
    except Exception:
        ok = False
    return {'ok': bool(ok), 'watch_dirs': data_recovery.get_settings().get('watch_dirs', [])}

@app.post('/api/v1/recovery/watch-dirs/delete')
async def recovery_watch_dirs_remove(data: dict = Body(...)):
    dirs = data_recovery.get_settings().get('watch_dirs', [])
    target = data.get('dir', '')
    if not target:
        idx = data.get('index')
        if isinstance(idx, int) and 0 <= idx < len(dirs):
            target = dirs[idx]
    try:
        ok = data_recovery.remove_watch_dir(target) if target else False
    except Exception:
        ok = False
    return {'ok': bool(ok)}

# ==================== 沙箱分析 ====================

@app.post('/api/v1/sandbox/analyze')
async def sandbox_analyze(data: dict = Body(...)):
    result = sandbox.analyze_file(data.get('file_path', ''), data.get('timeout', 30))
    return result


@app.post('/api/v1/sandbox/upload')
async def sandbox_upload(file: UploadFile = File(...)):
    """上传样本并启动「可取消」的沙箱分析任务。

    浏览器拿不到本地绝对路径，原 /api/v1/sandbox/analyze 只能收 JSON file_path，
    因此前端上传路径一直是坏的（回退分支传 filename 会得到"文件不存在"的空报告）。
    这里把上传样本落到临时目录，再交给通用任务登记表异步分析：
      - 返回 task_id，前端轮询 GET /api/v1/jobs/{task_id}/status
      - 取消走 POST /api/v1/jobs/{task_id}/cancel（真的 TerminateJobObject 杀进程）
    """
    import tempfile as _tempfile

    safe_name = os.path.basename(file.filename or "sample.bin") or "sample.bin"
    up_dir = os.path.join(_tempfile.gettempdir(), "yutian_sandbox_uploads")
    try:
        os.makedirs(up_dir, exist_ok=True)
    except OSError as e:
        return JSONResponse({"error": f"创建上传目录失败: {e}"}, 500)

    dest = os.path.join(up_dir, os.urandom(4).hex() + "_" + safe_name)
    try:
        with open(dest, "wb") as f:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
    except Exception as e:
        return JSONResponse({"error": f"样本保存失败: {e}"}, 500)
    finally:
        try:
            await file.close()
        except Exception:
            pass

    params = {"file_path": dest, "timeout": 30}
    job = _jobs.submit(
        "sandbox-analyze",
        lambda token, report: _job_sandbox_analyze(token, report, params),
        params,
    )
    return {"task_id": job.task_id, "file_path": dest, "filename": safe_name}

@app.get('/api/v1/sandbox/status')
async def sandbox_status():
    return sandbox.get_status()

@app.get('/api/v1/sandbox/history')
async def sandbox_history():
    return {'history': sandbox.get_history()}

@app.get('/api/v1/sandbox/stats')
async def sandbox_stats():
    try:
        history = sandbox.get_history(50)
        st = sandbox.get_status()
        return {'enabled': bool(st.get('enabled', st.get('active', False))), 'analysis_count': len(history), 'recent_reports': history}
    except Exception:
        return {'enabled': False, 'analysis_count': 0, 'recent_reports': []}


# ══════════════════════════════════════════════════════════════════════════
# 启动辅助：界面定位 / 后台服务 / 就绪等待 / 退出保存
# ══════════════════════════════════════════════════════════════════════════

UI_BASE_URL = "http://127.0.0.1:8899"
BACKEND_PORT = 8899


def _find_ui_tk_dir() -> str:
    """定位 ``ui_tk`` 目录（需含 run_ui.py）。

    开发模式在仓库根；打包模式在 ``sys._MEIPASS`` 下 —— 前提是 spec 把 ui_tk
    作为 datas 收进去了，否则打包版会报找不到界面目录并退出。
    """
    base = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(os.path.dirname(base), "ui_tk"),   # 仓库根/ui_tk
        os.path.join(base, "ui_tk"),                    # backend/ui_tk
    ]
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", "") or ""
        if meipass:
            candidates.insert(0, os.path.join(meipass, "ui_tk"))
    for cand in candidates:
        if os.path.isfile(os.path.join(cand, "run_ui.py")):
            return os.path.normpath(cand)
    return ""


def _start_uvicorn_thread(port: int = BACKEND_PORT):
    """在守护线程里跑 uvicorn（Tk 界面通过 HTTP 访问它）。"""
    import threading as _th

    import uvicorn

    def _run_server():
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")

    thread = _th.Thread(target=_run_server, daemon=True, name="uvicorn-server")
    thread.start()
    return thread


def _start_aux_services():
    """网络监控 / 实时文件守护 / 破军引擎状态。"""
    try:
        from engine.network_monitor import get_network_monitor
        nm = get_network_monitor()
        nm.start_monitor(interval=10)
    except Exception:
        pass

    try:
        from engine.file_guard_client import get_guard
        guard = get_guard()
        guard.start()
    except Exception:
        pass

    try:
        from engine.native_bridge import get_native_engine
        native_eng = get_native_engine()
        if native_eng.available():
            ver = native_eng.version()
            print(f"[破军引擎] 破军引擎已加载: {ver.get('version', 'unknown')}")
        else:
            print("[破军引擎] 破军引擎DLL未找到，使用Python回退方案")
    except Exception as e:
        print(f"[破军引擎] 初始化失败: {e}")


def _wait_http_ready(url: str = UI_BASE_URL, timeout: float = 40.0) -> bool:
    """等 FastAPI 真正开始监听。等不到返回 False（不抛）。"""
    import urllib.error
    import urllib.request

    deadline = time.time() + max(1.0, float(timeout))
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/api/health", timeout=1.0) as resp:
                if 200 <= getattr(resp, "status", 200) < 500:
                    return True
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
            time.sleep(0.3)
    return False


def _register_exit_save_hook():
    """atexit：保存配置 / 守护天数 / 清理缓存。

    与 ``_shutdown_and_exit`` 里同样的更正：原写法
        save_guard_days(load_guard_days() if 'load_guard_days' in dir() else _guard_data)
    不会抛异常（``_guard_data`` 是模块级变量，确实存在），守护天数也确实保存了；
    但三元条件在函数内恒为假，`load_guard_days()` 那句是死代码，实际存的是启动快照。
    这里改为退出时重新读取。
    """
    import atexit

    @atexit.register
    def _on_exit_save_all():
        try:
            save_config_save({
                "protection": _protection_modules,
                "features": _feature_toggles,
            })
        except Exception:
            pass
        try:
            from persistence import load_guard_days
            save_guard_days(load_guard_days())
        except Exception:
            pass
        try:
            cache_cleanup()
        except Exception:
            pass
        try:
            print("[御天] 状态已保存")
        except Exception:
            pass


if __name__ == "__main__":
    import sys
    # 冻结窗口程序下 stdout/stderr 为 None, uvicorn 日志访问 .isatty() 会崩溃
    if sys.stdout is None:
        import os, io as _io
        sys.stdout = _io.open(os.devnull, "w")
    if sys.stderr is None:
        import os, io as _io
        sys.stderr = _io.open(os.devnull, "w")
    _mark("__main__ 入口")
    # --watchdog 模式：极简启动，不走任何重型导入
    if '--watchdog' in sys.argv:
        _mark("进入 watchdog 模式")
        ret = _run_watchdog_mode()
        sys.exit(ret if ret else 0)

    import os
    import threading

    # 开发模式：添加 libs 目录到搜索路径
    if not getattr(sys, 'frozen', False):
        libs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libs")
        if os.path.isdir(libs_dir):
            sys.path.insert(0, libs_dir)

    # ── 界面：Tk（ui_tk/）。内嵌 WebView2 链路已移除，见文件顶部说明 ──
    _mark("定位 ui_tk 界面目录")
    _UI_TK_DIR = _find_ui_tk_dir()
    if not _UI_TK_DIR:
        _log_startup("找不到 ui_tk 目录（需含 run_ui.py），无法启动界面")
        print("[御天] 严重错误：找不到 ui_tk 界面目录（需含 run_ui.py）")
        sys.exit(2)
    _mark(f"ui_tk = {_UI_TK_DIR}")
    if _UI_TK_DIR not in sys.path:
        sys.path.insert(0, _UI_TK_DIR)

    _mark("导入 ui_tk 界面")
    from andun_ui.app import App as TkApp
    from engine_loader import load_engine_resources

    # 引擎资源在后台线程预加载，与界面创建并行
    # （原先它与 splash 动画并行；splash 随 webview 一起删了，改为与 Tk 界面创建并行）
    threading.Thread(
        target=load_engine_resources,
        kwargs={"status_callback": None, "done_callback": None},
        daemon=True,
        name="engine-loader",
    ).start()

    # 注册退出钩子：程序退出时保存配置 / 守护天数 / 清理缓存
    _register_exit_save_hook()

    # ── 后台服务：uvicorn（同进程）+ 网络监控 / 文件守护 / 破军引擎 ──
    _mark("启动 uvicorn（同进程内）")
    _start_uvicorn_thread(8899)
    _start_aux_services()

    # 启动双进程互保（自保护）
    _mark("启动自保护 watchdog")
    _start_self_protection()
    _mark("自保护已启动")

    _mark("等待 uvicorn 就绪")
    if not _wait_http_ready(UI_BASE_URL, timeout=40.0):
        _log_startup("等待 uvicorn 就绪超时；界面会显示「后端未连接」")
        print("[御天] 警告：等待后端就绪超时，界面可能显示未连接")

    # ── 主线程：Tk 消息循环（Tk 要求必须在主线程）──
    _mark("创建 Tk 界面")
    _ui = TkApp(base_url=UI_BASE_URL, initial_page="overview")
    # 后端就在本进程里跑着，所以：
    #   · auto_start_backend=False —— 否则健康检查一旦抢在 uvicorn 监听之前完成，
    #     Tk 侧会再拉起一个 uvicorn 抢同一个端口，必然绑定失败
    #   · stop_on_exit=False —— 后端就是这个进程本身，不存在"停止后端"
    _ui.backend.prefs["auto_start_backend"] = False
    _ui.backend.prefs["stop_on_exit"] = False
    _UI_STATE["app"] = _ui

    _mark("进入 Tk mainloop")
    _ui.run()
    _mark("Tk mainloop 已退出（窗口已关闭）")

    # ── 正常退出：保存状态 + 释放引擎资源 + 干净退出 ──
    _shutdown_and_exit(0)
