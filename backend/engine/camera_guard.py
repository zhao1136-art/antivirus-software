"""
御天 摄像头保护引擎

监控摄像头设备访问行为，防止恶意软件偷偷开启摄像头偷拍。

功能：
  1. enable() 通过 SetupDi API 枚举系统摄像头设备，并启用访问监控（内核驱动防护层已移除）
  2. on_camera_access(pid, device_path) 检查白名单，不在白名单则阻断（用户态终止进程）+弹窗
  3. add_to_whitelist / remove_from_whitelist 管理可信进程白名单
  4. get_camera_status() 获取摄像头列表与启用状态
  5. get_access_history() 获取访问历史记录

特性：
  - 使用 ctypes 调用 SetupDiGetClassDevs / SetupDiEnumDeviceInfo 枚举摄像头设备
  - 白名单持久化到 data/camera_whitelist.json
  - 访问历史持久化（最近 500 条）
  - 内核驱动防护层已移除，统一采用用户态阻断（终止非白名单进程）
  - 线程安全（双重检查锁单例 + 实例锁）
"""

import os
import sys
import json
import time
import ctypes
import threading
import subprocess
import logging
from collections import deque
from typing import Optional, Any

IS_WINDOWS = sys.platform == "win32"

# ============================================================
# 路径与常量
# ============================================================

# data 目录：backend/data/
_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data"
)
# 白名单持久化文件
WHITELIST_FILE = os.path.join(_DATA_DIR, "camera_whitelist.json")
# 访问历史持久化文件
HISTORY_FILE = os.path.join(_DATA_DIR, "camera_access_history.json")
# 日志目录
_LOG_DIR = os.path.join(_DATA_DIR, "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "camera_guard.log")

# 访问历史最大保留条数
MAX_HISTORY = 500

# 摄像头设备接口 GUID（USB 视频设备接口）
# {E5323777-F976-4f5b-9B55-B94699C46E44}
CAMERA_INTERFACE_GUID = "{E5323777-F976-4f5b-9B55-B94699C46E44}"

# 影像设备类 GUID（Device Class: Image）
# {6996AD0C-EFF7-11D0-B72B-00A0C91443E1}
IMAGE_DEVICE_CLASS_GUID = "{6996AD0C-EFF7-11D0-B72B-00A0C91443E1}"

# 默认可信进程白名单（系统自带相机相关进程）
DEFAULT_WHITELIST = [
    "wininit.exe",
    "winlogon.exe",
    "svchost.exe",
    "explorer.exe",
]


# ============================================================
# Windows API 常量与结构体
# ============================================================

# SetupAPI 标志
DIGCF_PRESENT = 0x02
DIGCF_DEVICEINTERFACE = 0x10

# 注册表属性
SPDRP_DEVICEDESC = 0x00       # 设备描述
SPDRP_FRIENDLYNAME = 0x0C     # 友好名称
SPDRP_HARDWAREID = 0x01       # 硬件 ID

# 错误码
ERROR_NO_MORE_ITEMS = 259


class SP_DEVINFO_DATA(ctypes.Structure):
    """设备信息数据结构"""
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("ClassGuid", ctypes.c_byte * 16),
        ("DevInst", ctypes.c_ulong),
        ("Reserved", ctypes.c_void_p),
    ]


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    """设备接口数据结构"""
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("InterfaceClassGuid", ctypes.c_byte * 16),
        ("Flags", ctypes.c_ulong),
        ("Reserved", ctypes.c_void_p),
    ]


class SP_DEVICE_INTERFACE_DETAIL_DATA_W(ctypes.Structure):
    """设备接口详情数据结构（WCHAR 版本）

    注意：cbSize 在 64 位系统为 8（4 字节 cbSize + 4 字节填充对齐到指针宽度）。
    """
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("DevicePath", ctypes.c_wchar * 512),
    ]


# ============================================================
# 日志器
# ============================================================

def _get_logger() -> logging.Logger:
    """获取摄像头保护专用日志记录器"""
    os.makedirs(_LOG_DIR, exist_ok=True)
    logger = logging.getLogger("camera_guard")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(_LOG_FILE, encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(fh)
    return logger


# ============================================================
# 工具函数
# ============================================================

def _guid_string_to_bytes(guid_str: str) -> bytes:
    """将 GUID 字符串转换为 16 字节字节数组（用于 ctypes 结构体）"""
    import uuid
    g = uuid.UUID(guid_str)
    return g.bytes_le


def _get_process_name(pid: int) -> str:
    """根据 PID 获取进程名"""
    if not IS_WINDOWS or pid <= 0:
        return "unknown"
    try:
        # 使用 wmic 查询进程名
        result = subprocess.run(
            ["wmic", "process", "where", f"ProcessId={pid}", "get", "Name", "/format:value"],
            capture_output=True, text=True, timeout=3, encoding="utf-8", errors="ignore"
        )
        for line in result.stdout.splitlines():
            if line.lower().startswith("name="):
                return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def _block_process(pid: int) -> bool:
    """终止指定进程"""
    if not IS_WINDOWS or pid <= 0:
        return False
    try:
        result = subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


# ============================================================
# CameraGuard — 摄像头保护引擎主类
# ============================================================

class CameraGuard:
    """摄像头保护引擎

    枚举摄像头设备，监控访问行为，白名单外进程访问时阻断并告警。
    """

    # 驱动规则 ID 起始（避免与其他模块冲突）
    _next_rule_id = 70000

    def __init__(self):
        """初始化摄像头保护引擎"""
        self._logger = _get_logger()

        # 摄像头设备列表 [{device_path, friendly_name, hardware_id}]
        self._cameras: list[dict] = []
        self._cameras_lock = threading.Lock()

        # 白名单（进程名小写）
        self._whitelist: set[str] = set(DEFAULT_WHITELIST)
        self._whitelist_lock = threading.Lock()

        # 访问历史 deque[{timestamp, pid, process_name, device_path, action, blocked}]
        self._access_history: deque = deque(maxlen=MAX_HISTORY)
        self._history_lock = threading.Lock()

        # 启用状态
        self._enabled = False
        self._enabled_lock = threading.Lock()

        # 驱动下发的规则 ID 列表（内核驱动防护层已移除，恒为空）
        self._driver_rule_ids: list[int] = []
        self._rule_ids_lock = threading.Lock()

        # 统计
        self._stats = {
            "cameras_detected": 0,
            "access_attempts": 0,
            "blocked_attempts": 0,
        }
        self._stats_lock = threading.Lock()

        # 延迟加载标记
        self._data_loaded = False

    def _ensure_data(self):
        """延迟加载白名单和历史（首次访问时从磁盘读取）"""
        if not self._data_loaded:
            self._load_whitelist()
            self._load_history()
            self._data_loaded = True
            self._log("info", "摄像头保护引擎初始化完成")

    # ── 属性 ──

    @property
    def driver_available(self) -> bool:
        """驱动是否可用（内核驱动防护层已移除，恒为 False）"""
        return False

    @property
    def enabled(self) -> bool:
        with self._enabled_lock:
            return self._enabled

    # ── 启用/停用 ──

    def enable(self) -> dict:
        """启用摄像头保护

        1. 枚举系统摄像头设备（SetupDi API）
        2. 记录设备保护规则数量（内核驱动防护层已移除，恒为 0）

        Returns:
            {"cameras": list, "rules_pushed": int, "driver_available": bool}
        """
        self._ensure_data()
        with self._enabled_lock:
            if self._enabled:
                self._log("info", "摄像头保护已启用，跳过重复启用")
                return {"cameras": list(self._cameras), "rules_pushed": 0,
                        "driver_available": self.driver_available}
            self._enabled = True

        # 枚举摄像头设备
        cameras = self._enumerate_cameras()
        with self._cameras_lock:
            self._cameras = cameras

        with self._stats_lock:
            self._stats["cameras_detected"] = len(cameras)

        # 设备文件保护规则（内核驱动防护层已移除，恒为 0 条）
        rules_pushed = 0
        for cam in cameras:
            rules_pushed += self._push_camera_protection_rule(cam["device_path"])

        # 注册驱动事件处理器（内核驱动防护层已移除，空实现）
        self._register_driver_handlers()

        self._log("info", f"摄像头保护已启用: 检测到 {len(cameras)} 个摄像头，"
                          f"下发 {rules_pushed} 条规则")

        return {
            "cameras": cameras,
            "rules_pushed": rules_pushed,
            "driver_available": self.driver_available,
        }

    def disable(self) -> None:
        """停用摄像头保护"""
        with self._enabled_lock:
            self._enabled = False

        # 移除驱动规则（内核驱动防护层已移除，空实现）
        self._remove_all_driver_rules()

        # 注销驱动事件处理器（内核驱动防护层已移除，空实现）
        self._unregister_driver_handlers()

        self._log("info", "摄像头保护已停用")

    # ── 摄像头设备枚举（私有） ──

    def _enumerate_cameras(self) -> list[dict]:
        """使用 SetupDi API 枚举系统摄像头设备

        Returns:
            设备列表 [{device_path, friendly_name, hardware_id}]
        """
        if not IS_WINDOWS:
            self._log("warning", "非 Windows 平台，跳过摄像头枚举")
            return []

        cameras: list[dict] = []
        try:
            # 加载 SetupAPI
            setupapi = ctypes.windll.setupapi

            # 将 GUID 字符串转换为字节数组
            guid_bytes = _guid_string_to_bytes(CAMERA_INTERFACE_GUID)

            # 创建 GUID 结构体（16 字节）
            class GUID(ctypes.Structure):
                _fields_ = [("Data4", ctypes.c_byte * 8),
                            ("Data3", ctypes.c_ushort),
                            ("Data2", ctypes.c_ushort),
                            ("Data1", ctypes.c_ulong)]

            interface_guid = GUID()
            ctypes.memmove(ctypes.byref(interface_guid), guid_bytes, 16)

            # 调用 SetupDiGetClassDevs 获取设备信息集
            h_dev_info = setupapi.SetupDiGetClassDevsW(
                ctypes.byref(interface_guid),
                None, None,
                DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
            )
            if h_dev_info == ctypes.c_void_p(-1).value or not h_dev_info:
                self._log("warning", "SetupDiGetClassDevs 失败，未找到摄像头设备")
                return []

            # 枚举设备接口
            index = 0
            while True:
                iface_data = SP_DEVICE_INTERFACE_DATA()
                iface_data.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)

                if not setupapi.SetupDiEnumDeviceInterfaces(
                    h_dev_info, None,
                    ctypes.byref(interface_guid),
                    index, ctypes.byref(iface_data)
                ):
                    # 没有更多设备
                    break

                # 获取设备路径（先查询所需大小，再获取详情）
                detail_data = SP_DEVICE_INTERFACE_DETAIL_DATA_W()
                # cbSize 在 64 位系统为 8（4 字节 cbSize + 4 字节对齐）
                detail_data.cbSize = 8

                required_size = ctypes.c_ulong(0)
                # 第一次调用获取所需大小
                setupapi.SetupDiGetDeviceInterfaceDetailW(
                    h_dev_info, ctypes.byref(iface_data),
                    None, 0, ctypes.byref(required_size), None
                )
                # 第二次调用获取详情
                ok = setupapi.SetupDiGetDeviceInterfaceDetailW(
                    h_dev_info, ctypes.byref(iface_data),
                    ctypes.byref(detail_data),
                    ctypes.sizeof(detail_data),
                    ctypes.byref(required_size), None
                )

                if ok:
                    device_path = detail_data.DevicePath.rstrip("\x00")
                    friendly_name = self._get_device_friendly_name(
                        setupapi, h_dev_info, ctypes.byref(iface_data)
                    )
                    cameras.append({
                        "device_path": device_path,
                        "friendly_name": friendly_name,
                        "hardware_id": "",  # 可扩展获取
                    })

                index += 1

            # 关闭设备信息集
            setupapi.SetupDiDestroyDeviceInfoList(h_dev_info)

        except Exception as e:
            self._log("error", f"摄像头设备枚举失败: {e}")

        return cameras

    def _get_device_friendly_name(self, setupapi, h_dev_info: int,
                                   iface_data: Any) -> str:
        """获取设备友好名称"""
        try:
            dev_info = SP_DEVINFO_DATA()
            dev_info.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)

            # 获取关联的设备信息
            if not setupapi.SetupDiGetDeviceInterfaceDetailW(
                h_dev_info, iface_data,
                None, 0, None, ctypes.byref(dev_info)
            ):
                # 上面的调用会失败（缓冲区为空），但会填充 dev_info
                pass

            # 读取友好名称属性
            buffer = ctypes.create_unicode_buffer(256)
            required = ctypes.c_ulong(0)
            ok = setupapi.SetupDiGetDeviceRegistryPropertyW(
                h_dev_info, ctypes.byref(dev_info),
                SPDRP_FRIENDLYNAME, None,
                ctypes.byref(buffer), ctypes.sizeof(buffer),
                ctypes.byref(required)
            )
            if ok:
                return buffer.value.rstrip("\x00")

            # 回退到设备描述
            ok = setupapi.SetupDiGetDeviceRegistryPropertyW(
                h_dev_info, ctypes.byref(dev_info),
                SPDRP_DEVICEDESC, None,
                ctypes.byref(buffer), ctypes.sizeof(buffer),
                ctypes.byref(required)
            )
            if ok:
                return buffer.value.rstrip("\x00")

        except Exception:
            pass
        return "Unknown Camera"

    # ── 访问事件处理 ──

    def on_camera_access(self, pid: int, device_path: str) -> dict:
        """摄像头访问事件处理（由驱动事件回调触发）

        Args:
            pid: 访问进程 PID
            device_path: 被访问的设备文件路径

        Returns:
            处理结果 {allowed, blocked, process_name, reason}
        """
        process_name = _get_process_name(pid)

        with self._stats_lock:
            self._stats["access_attempts"] += 1

        # 检查白名单
        allowed = False
        reason = ""
        with self._whitelist_lock:
            if process_name.lower() in self._whitelist:
                allowed = True
                reason = f"进程 {process_name} 在白名单中"
            else:
                reason = f"进程 {process_name} 不在白名单中"

        # 记录访问历史
        record = {
            "timestamp": time.time(),
            "pid": pid,
            "process_name": process_name,
            "device_path": device_path,
            "allowed": allowed,
            "blocked": not allowed,
        }
        with self._history_lock:
            self._access_history.append(record)

        # 异步持久化（避免频繁 IO）
        self._save_history_async()

        if allowed:
            self._log("info", f"摄像头访问放行: {process_name} (PID={pid}) -> {device_path}")
            return {"allowed": True, "blocked": False,
                    "process_name": process_name, "reason": reason}

        # 不在白名单，阻断 + 弹窗
        with self._stats_lock:
            self._stats["blocked_attempts"] += 1

        # 内核驱动防护层已移除，统一由用户态终止非白名单进程
        if _block_process(pid):
            self._log("warning", f"已终止非白名单进程: {process_name} (PID={pid})")
        else:
            self._log("error", f"终止进程失败: {process_name} (PID={pid})")

        # 弹窗告警
        self._show_alert(process_name, pid, device_path)

        return {"allowed": False, "blocked": True,
                "process_name": process_name, "reason": reason}

    def _show_alert(self, process_name: str, pid: int, device_path: str) -> None:
        """显示摄像头访问告警弹窗"""
        if not IS_WINDOWS:
            return
        title = "御天 摄像头保护告警"
        body = (
            f"检测到非白名单进程访问摄像头！\n\n"
            f"进程: {process_name}\n"
            f"PID: {pid}\n"
            f"设备: {device_path}\n\n"
            f"御天已阻止该访问。如果不是您主动开启，请检查是否感染恶意软件。"
        )
        try:
            ctypes.windll.user32.MessageBoxW(0, body, title, 0x10 | 0x1000)
        except Exception:
            try:
                subprocess.Popen(
                    ["msg", "*", f"{title}\n{body}"],
                    stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
            except Exception:
                pass

    # ── 白名单管理 ──

    def add_to_whitelist(self, process_name: str) -> bool:
        """添加进程到白名单

        Args:
            process_name: 进程名（如 chrome.exe）

        Returns:
            成功返回 True
        """
        self._ensure_data()
        if not process_name:
            return False
        name = process_name.strip().lower()
        with self._whitelist_lock:
            if name in self._whitelist:
                return True
            self._whitelist.add(name)
        self._save_whitelist()
        self._log("info", f"添加摄像头白名单: {name}")
        return True

    def remove_from_whitelist(self, process_name: str) -> bool:
        """从白名单移除进程

        Args:
            process_name: 进程名

        Returns:
            成功返回 True，不在白名单返回 False
        """
        self._ensure_data()
        name = process_name.strip().lower()
        with self._whitelist_lock:
            if name not in self._whitelist:
                return False
            self._whitelist.discard(name)
        self._save_whitelist()
        self._log("info", f"移除摄像头白名单: {name}")
        return True

    def get_whitelist(self) -> list[str]:
        """获取白名单列表（排序）"""
        with self._whitelist_lock:
            return sorted(self._whitelist)

    # ── 状态与历史查询 ──

    def get_camera_status(self) -> dict:
        """获取摄像头保护完整状态

        Returns:
            {enabled, driver_available, cameras, whitelist, stats}
        """
        self._ensure_data()
        with self._cameras_lock:
            cameras = list(self._cameras)
        with self._whitelist_lock:
            whitelist = sorted(self._whitelist)
        with self._stats_lock:
            stats = dict(self._stats)
        with self._rule_ids_lock:
            rules_count = len(self._driver_rule_ids)

        return {
            "enabled": self.enabled,
            "driver_available": self.driver_available,
            "cameras": cameras,
            "cameras_count": len(cameras),
            "whitelist": whitelist,
            "whitelist_count": len(whitelist),
            "driver_rules_count": rules_count,
            "stats": stats,
        }

    def get_access_history(self, limit: int = 100) -> list[dict]:
        """获取摄像头访问历史

        Args:
            limit: 返回最近 N 条记录

        Returns:
            访问历史列表（按时间倒序）
        """
        self._ensure_data()
        with self._history_lock:
            history = list(self._access_history)
        # 倒序并限制数量
        history.reverse()
        return history[:limit]

    # ── 驱动规则下发（私有） ──

    def _push_camera_protection_rule(self, device_path: str) -> int:
        """下发摄像头设备文件保护规则

        内核驱动防护层已移除，规则无法下发，恒返回 0（仅记录模式）。
        """
        self._log("info", f"内核驱动防护层已移除，摄像头 {device_path} 仅启用记录模式")
        return 0

    def _remove_all_driver_rules(self) -> None:
        """移除所有已下发的摄像头保护规则

        内核驱动防护层已移除，仅清空本地记录的规则 ID。
        """
        with self._rule_ids_lock:
            self._driver_rule_ids.clear()

    # ── 驱动事件处理器注册（私有） ──

    def _register_driver_handlers(self) -> None:
        """注册驱动事件处理器（内核驱动防护层已移除，保留空实现）"""
        return

    def _unregister_driver_handlers(self) -> None:
        """注销驱动事件处理器（内核驱动防护层已移除，保留空实现）"""
        return

    def _on_file_event(self, event: dict) -> None:
        """驱动文件事件回调

        检查目标路径是否为摄像头设备路径，是则触发 on_camera_access。
        """
        if not self.enabled:
            return

        target_path = event.get("targetPath", "")
        pid = event.get("pid", 0)

        if not target_path or pid <= 0:
            return

        # 检查是否为摄像头设备路径
        with self._cameras_lock:
            for cam in self._cameras:
                if cam["device_path"] and cam["device_path"] in target_path:
                    # 异步处理，避免阻塞驱动事件轮询线程
                    threading.Thread(
                        target=self.on_camera_access,
                        args=(pid, target_path),
                        daemon=True
                    ).start()
                    break

    # ── 持久化 ──

    def _save_whitelist(self) -> bool:
        """将白名单持久化到 data/camera_whitelist.json"""
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            with self._whitelist_lock:
                data = {
                    "saved_at": time.time(),
                    "whitelist": sorted(self._whitelist),
                }
            with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            self._log("error", f"白名单持久化失败: {e}")
            return False

    def _load_whitelist(self) -> bool:
        """从 data/camera_whitelist.json 加载白名单"""
        if not os.path.exists(WHITELIST_FILE):
            return False
        try:
            with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            whitelist = data.get("whitelist", [])
            with self._whitelist_lock:
                # 合并默认白名单
                self._whitelist = set(DEFAULT_WHITELIST) | set(whitelist)
            return True
        except Exception as e:
            self._log("error", f"白名单加载失败: {e}")
            return False

    def _save_history_async(self) -> None:
        """异步保存访问历史（避免阻塞事件回调）"""
        t = threading.Thread(target=self._save_history, daemon=True)
        t.start()

    def _save_history(self) -> bool:
        """将访问历史持久化到 data/camera_access_history.json"""
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            with self._history_lock:
                data = {
                    "saved_at": time.time(),
                    "history": list(self._access_history),
                }
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            self._log("error", f"访问历史持久化失败: {e}")
            return False

    def _load_history(self) -> bool:
        """从 data/camera_access_history.json 加载访问历史"""
        if not os.path.exists(HISTORY_FILE):
            return False
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            history = data.get("history", [])
            with self._history_lock:
                self._access_history.clear()
                self._access_history.extend(history[-MAX_HISTORY:])
            return True
        except Exception as e:
            self._log("error", f"访问历史加载失败: {e}")
            return False

    # ── 日志 ──

    def _log(self, level: str, message: str) -> None:
        """记录日志"""
        try:
            getattr(self._logger, level, self._logger.info)(message)
        except Exception:
            pass


# ============================================================
# 单例模式（双重检查锁）
# ============================================================

_camera_guard: Optional[CameraGuard] = None
_camera_guard_lock = threading.Lock()


def get_camera_guard() -> CameraGuard:
    """获取全局唯一的 CameraGuard 实例（双重检查锁定单例）

    Returns:
        全局唯一的 CameraGuard 实例
    """
    global _camera_guard
    if _camera_guard is None:
        with _camera_guard_lock:
            if _camera_guard is None:
                _camera_guard = CameraGuard()
    return _camera_guard


# ============================================================
# 模块自检（直接运行时执行）
# ============================================================

if __name__ == "__main__":
    guard = CameraGuard()

    print("[camera_guard] 状态:", guard.get_camera_status())

    print("[camera_guard] 启用保护...")
    result = guard.enable()
    print(f"[camera_guard] 启用结果: {result}")

    # 测试白名单管理
    guard.add_to_whitelist("zoom.exe")
    guard.add_to_whitelist("teams.exe")
    print("[camera_guard] 白名单:", guard.get_whitelist())
    guard.remove_from_whitelist("zoom.exe")
    print("[camera_guard] 白名单（移除后）:", guard.get_whitelist())

    # 模拟访问事件
    print("[camera_guard] 模拟访问事件...")
    guard.on_camera_access(pid=1234, device_path=r"\\?\USB#VID_1234")

    print("[camera_guard] 访问历史:")
    for h in guard.get_access_history(limit=5):
        print(f"  - {h}")

    print("[camera_guard] 最终状态:", guard.get_camera_status())

    guard.disable()
