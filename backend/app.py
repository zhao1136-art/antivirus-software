"""
安盾 后端 API 网关 - FastAPI + WebSocket 进度推送
"""
import os
import sys
import asyncio
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional

# 确保项目根在搜索路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.scheduler import Scheduler
from engine.quarantine import QuarantineManager
from engine.signature_manager import SignatureManager
from engine.report_logger import ReportLogger
from engine.signature_downloader import SignatureDownloader
from engine.vuln_database import VulnerabilityDatabase
from engine.vuln_downloader import VulnerabilityDownloader
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

# ---------- 全局实例 ----------
app = FastAPI(title="安盾 Engine API", version="1.0.0")
scheduler = Scheduler()
quarantine = QuarantineManager()
sig_mgr = SignatureManager()
logger = ReportLogger()
sig_downloader = SignatureDownloader(sig_mgr)
vuln_db = VulnerabilityDatabase()
vuln_downloader = VulnerabilityDownloader(vuln_db)

# 威胁情报引擎改为懒加载（见上方 _get_c2_intel / _get_threat_intel）

# WebSocket 连接池
ws_connections: dict[str, WebSocket] = {}
MAX_WS_CONNECTIONS = 50
_event_loop = None  # 保存事件循环引用，供跨线程广播使用

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
            """打开前端页面"""
            import webbrowser
            webbrowser.open("http://127.0.0.1:8899")

        def on_exit():
            """退出程序"""
            import os
            import signal
            os._exit(0)

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


@app.post("/api/v1/scan/{task_id}/cancel")
async def scan_cancel(task_id: str):
    """取消扫描任务"""
    ok = scheduler.cancel_task(task_id)
    if not ok:
        return JSONResponse({"error": "无法取消该任务"}, 400)
    return {"task_id": task_id, "status": "cancelled"}


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
    return {"module": req.module, "enabled": req.enabled}


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


# ---------- 退出安盾 ----------

@app.post("/api/v1/shutdown")
async def shutdown():
    """关闭安盾（含守护进程）"""
    import time
    _thr.Thread(target=lambda: (time.sleep(0.5), os._exit(0)), daemon=True).start()
    return {"success": True, "message": "安盾即将退出"}


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


# ---------- 漏洞筛查 API ----------

@app.get("/api/v1/vulnerabilities/search")
async def vuln_search(keyword: str = "", severity: str = "", source: str = "",
                       page: int = 1, pagesize: int = 50):
    """搜索漏洞"""
    offset = (page - 1) * pagesize
    results = vuln_db.search(keyword=keyword, severity=severity, source=source,
                             limit=pagesize, offset=offset)
    total = vuln_db.search_count(keyword=keyword, severity=severity, source=source)
    return {"total": total, "page": page, "pagesize": pagesize, "results": results}


@app.get("/api/v1/vulnerabilities/stats")
async def vuln_stats():
    """漏洞统计"""
    return vuln_db.get_stats()


@app.get("/api/v1/vulnerabilities/recent")
async def vuln_recent(limit: int = 20):
    """最近漏洞"""
    return {"results": vuln_db.get_recent(limit)}


@app.post("/api/v1/vulnerabilities/download")
async def vuln_download(data: dict = None):
    """下载漏洞数据库"""
    source = (data or {}).get("source", "community")

    def _do():
        if source == "cnnvd":
            vuln_downloader.download_from_cnnvd()
        elif source == "community":
            vuln_downloader.download_community_feed(limit=5000)
        else:
            vuln_downloader.download_from_nvd(limit=2000)

    import threading
    t = threading.Thread(target=_do, daemon=True)
    t.start()
    return {"status": "started", "source": source}


@app.get("/api/v1/vulnerabilities/download/status")
async def vuln_download_status():
    """漏洞下载进度"""
    return vuln_downloader.status


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
    api_key: str


@app.get("/api/v1/cloud/status")
async def cloud_status():
    """云端引擎状态"""
    cs = scheduler.cloud
    return {
        "available": cs.available,
        "configured": bool(cs._available),
        "last_error": cs._last_error,
        "provider": "ThreatBook (微步在线)"
    }


@app.post("/api/v1/cloud/config")
async def cloud_config(req: CloudConfigRequest):
    """配置云端 API Key"""
    scheduler.cloud.set_api_key(req.api_key)
    return {
        "available": scheduler.cloud.available,
        "configured": bool(req.api_key),
        "provider": "ThreatBook (微步在线)"
    }


# ---------- 深度分析 API ----------

@app.get("/api/v1/deep/engines")
async def deep_engines_status():
    """深度分析引擎状态检查"""
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


# ---------- Vigil 强力模式 API ----------

_vigil_status = {"running": False, "port": 7331}

def _check_vigil_alive() -> bool:
    """Check if Vigil is actually responding"""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex(("127.0.0.1", _vigil_status["port"]))
        s.close()
        return result == 0
    except Exception:
        return False

@app.get("/api/v1/vigil/status")
async def vigil_status():
    """Vigil 强力模式状态"""
    if _vigil_status["running"] and not _check_vigil_alive():
        _vigil_status["running"] = False
    return _vigil_status


@app.post("/api/v1/vigil/start")
async def vigil_start():
    """启动 Vigil 强力模式"""
    if _vigil_status["running"] and _check_vigil_alive():
        return {"status": "already_running", "url": f"http://127.0.0.1:{_vigil_status['port']}"}
    try:
        from vigil.launcher import start_dashboard
        start_dashboard(host="127.0.0.1", port=_vigil_status["port"])
        # Wait for service to actually be ready
        import time
        for i in range(10):
            time.sleep(0.5)
            if _check_vigil_alive():
                _vigil_status["running"] = True
                return {"status": "started", "url": f"http://127.0.0.1:{_vigil_status['port']}"}
        return {"status": "error", "error": "Vigil 启动超时，请检查依赖（需要 Flask）"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ---------- 根路由 ----------

@app.get("/")
async def root():
    """返回前端主页"""
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return {
        "service": "安盾 Engine",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/{page}.html")
async def serve_page(page: str):
    """提供前端 HTML 页面"""
    # 安全检查：防止路径遍历
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


# ---------- 实时防护 API ----------

@app.get("/api/v1/realtime-guard/status")
async def realtime_guard_status():
    """实时防护状态"""
    try:
        from engine.file_guard_client import get_guard
        g = get_guard()
        return {"running": g.is_running}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.post("/api/v1/realtime-guard/toggle")
async def realtime_guard_toggle(data: dict):
    """启停实时防护"""
    enabled = data.get("enabled", True)
    try:
        from engine.file_guard_client import get_guard, scan_on_event
        g = get_guard()
        if enabled:
            watch = data.get("watch_dirs", None)
            g._callback = scan_on_event
            g.start(watch_dirs=watch)
        else:
            g.stop()
        return {"running": g.is_running}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


# ---------- 原生引擎 API (C++ Native Engine) ----------

@app.get("/api/v1/native/version")
async def native_version():
    """原生引擎版本信息"""
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
        qdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engine", "data", "quarantine")
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
    qdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engine", "data", "quarantine")
    try:
        from engine.native_bridge import get_native_engine
        eng = get_native_engine()
        result = eng.quarantine_list(qdir)
        if result is None:
            return JSONResponse({"error": "native engine not available"}, 503)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


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


if __name__ == "__main__":
    import sys
    # --watchdog 模式：极简启动，不走任何重型导入
    if '--watchdog' in sys.argv:
        ret = _run_watchdog_mode()
        sys.exit(ret if ret else 0)

    import os
    import threading

    # 开发模式：添加 libs 目录到搜索路径
    if not getattr(sys, 'frozen', False):
        libs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libs")
        if os.path.isdir(libs_dir):
            sys.path.insert(0, libs_dir)

    import uvicorn
    import webview

    # 后台启动 FastAPI
    def run_server():
        uvicorn.run(app, host="127.0.0.1", port=8899, log_level="warning")

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Vigil 强力模式默认不启动，用户可在设置页手动启用（/api/v1/vigil/start）

    # 后台启动网络监控
    try:
        from engine.network_monitor import get_network_monitor
        nm = get_network_monitor()
        nm.start_monitor(interval=10)
    except Exception:
        pass

    # 后台启动实时文件守护进程
    try:
        from engine.file_guard_client import get_guard
        guard = get_guard()
        guard.start()
    except Exception:
        pass

    # 初始化原生引擎状态
    try:
        from engine.native_bridge import get_native_engine
        native_eng = get_native_engine()
        if native_eng.available():
            ver = native_eng.version()
            print(f"[NativeEngine] 原生引擎已加载: {ver.get('version', 'unknown')}")
        else:
            print("[NativeEngine] 原生引擎DLL未找到，使用Python回退方案")
    except Exception as e:
        print(f"[NativeEngine] 初始化失败: {e}")

    # 启动双进程互保（自保护）
    _start_self_protection()

    # 内置浏览器窗口
    window = webview.create_window(
        title="安盾 安全中心",
        url="http://127.0.0.1:8899",
        width=1100,
        height=700,
        min_size=(900, 600),
        resizable=True,
    )

    # 拦截窗口关闭 → 最小化到托盘（托盘图标由 _init_tray_icon 启动）
    def _on_closing():
        window.hide()
        return False  # 返回 False 取消实际关闭

    window.events.closing += _on_closing

    # 主线程：webview 消息循环（pywebview 要求必须在主线程）
    webview.start()
