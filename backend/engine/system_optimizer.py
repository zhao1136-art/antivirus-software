"""
御天卫士 - 电脑优化引擎
- 系统体检：磁盘 / 内存 / 临时文件 / 启动项 / 待重启，输出评分
- 启动项管理：注册表 Run 项 + 启动文件夹，禁用可逆（带备份记录）
- 服务优化：仅允许调整第三方（非 C:\\Windows）服务启动类型
- 内存释放：对高占用空闲进程执行工作集收缩
全部基于 ctypes / winreg / subprocess，不引入第三方依赖。
"""
import os
import sys
import json
import time
import ctypes
import ctypes.wintypes as wt
import winreg
import threading
from datetime import datetime

# ── 数据目录（沿用 engine/data 约定） ──
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_BACKUP_FILE = os.path.join(_DATA_DIR, "startup_backup.json")

# 注册表启动项位置
STARTUP_REG_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]

# 禁用/启用时注册表值名的前后缀
DISABLED_PREFIX = ".yutian_off_"
BACKUP_DIR_NAME = ".yutian_backup"

# 服务启动类型（注册表 Start 值）
SERVICE_START_AUTO = 2
SERVICE_START_MANUAL = 3
SERVICE_START_DISABLED = 4

# 内存释放阈值：仅处理工作集大于该值的进程（MB）
MEM_MIN_WORKING_SET_MB = 30

_win_dir = os.environ.get("SystemRoot", "C:\\Windows")


def _format_size(num: float) -> str:
    try:
        num = float(num or 0)
    except (TypeError, ValueError):
        num = 0.0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024
    return "0 B"


def _cancelled(cancel) -> bool:
    """判断取消令牌是否已置位（兼容 is_cancelled() / is_set() 两种约定）"""
    if cancel is None:
        return False
    if hasattr(cancel, "is_cancelled"):
        return bool(cancel.is_cancelled())
    if hasattr(cancel, "is_set"):
        return bool(cancel.is_set())
    return False


class SystemOptimizer:
    """电脑优化引擎"""

    def __init__(self):
        self._lock = threading.Lock()
        self._backup = None
        os.makedirs(_DATA_DIR, exist_ok=True)

    # ════════════════════ 系统体检 ════════════════════

    def overview(self, cancel=None) -> dict:
        """系统体检：磁盘/内存/临时文件/启动项/待重启，输出 0-100 分

        cancel: 可选取消令牌；置位后立即返回 {"cancelled": True}。
        """
        if _cancelled(cancel):
            return {"cancelled": True}
        disk = self._disk_info()
        if _cancelled(cancel):
            return {"cancelled": True}
        mem = self._memory_info()
        if _cancelled(cancel):
            return {"cancelled": True}
        temp = self._temp_size(cancel)
        if _cancelled(cancel) or temp is None:
            return {"cancelled": True}
        startup_items = self.list_startup()
        if _cancelled(cancel):
            return {"cancelled": True}
        startup_count = len([s for s in startup_items if s["status"] == "enabled"])
        pending_reboot = self._pending_reboot()
        if _cancelled(cancel):
            return {"cancelled": True}

        checks = []
        # 磁盘
        free_pct = disk["free_percent"]
        if free_pct >= 20:
            checks.append({"id": "disk", "name": "磁盘空间", "status": "ok",
                           "detail": f"C 盘剩余 {disk['free_text']}（{free_pct:.0f}%）"})
        elif free_pct >= 10:
            checks.append({"id": "disk", "name": "磁盘空间", "status": "warn",
                           "detail": f"C 盘剩余仅 {disk['free_text']}（{free_pct:.0f}%），建议清理垃圾文件"})
        else:
            checks.append({"id": "disk", "name": "磁盘空间", "status": "danger",
                           "detail": f"C 盘剩余 {disk['free_text']}（{free_pct:.0f}%），空间严重不足"})
        # 内存
        mem_pct = mem["used_percent"]
        if mem_pct < 70:
            checks.append({"id": "memory", "name": "内存占用", "status": "ok",
                           "detail": f"当前内存占用 {mem_pct:.0f}%（已用 {mem['used_text']} / {mem['total_text']}）"})
        elif mem_pct < 85:
            checks.append({"id": "memory", "name": "内存占用", "status": "warn",
                           "detail": f"当前内存占用 {mem_pct:.0f}%，可尝试释放内存"})
        else:
            checks.append({"id": "memory", "name": "内存占用", "status": "danger",
                           "detail": f"当前内存占用 {mem_pct:.0f}%，内存吃紧，建议关闭多余程序"})
        # 临时文件
        if temp["total_bytes"] < 500 * 1024 * 1024:
            checks.append({"id": "temp", "name": "临时文件", "status": "ok",
                           "detail": f"临时文件共 {temp['size_text']}"})
        elif temp["total_bytes"] < 2 * 1024 * 1024 * 1024:
            checks.append({"id": "temp", "name": "临时文件", "status": "warn",
                           "detail": f"临时文件已达 {temp['size_text']}，建议清理"})
        else:
            checks.append({"id": "temp", "name": "临时文件", "status": "danger",
                           "detail": f"临时文件高达 {temp['size_text']}，急需清理"})
        # 启动项
        if startup_count <= 8:
            checks.append({"id": "startup", "name": "启动项", "status": "ok",
                           "detail": f"当前启用 {startup_count} 个开机启动项"})
        elif startup_count <= 15:
            checks.append({"id": "startup", "name": "启动项", "status": "warn",
                           "detail": f"当前启用 {startup_count} 个开机启动项，偏多影响开机速度"})
        else:
            checks.append({"id": "startup", "name": "启动项", "status": "danger",
                           "detail": f"当前启用 {startup_count} 个开机启动项，建议精简"})
        # 待重启
        if pending_reboot:
            checks.append({"id": "reboot", "name": "待重启更新", "status": "warn",
                           "detail": "存在待处理的重启操作（如系统更新），建议重启完成"})
        else:
            checks.append({"id": "reboot", "name": "待重启更新", "status": "ok",
                           "detail": "无待处理的重启操作"})

        # 评分：满分 100，warn -10，danger -25
        score = 100
        for c in checks:
            if c["status"] == "warn":
                score -= 10
            elif c["status"] == "danger":
                score -= 25
        score = max(0, min(100, score))

        return {
            "score": score,
            "checks": checks,
            "disk": disk,
            "memory": mem,
            "temp": temp,
            "startup_count": startup_count,
            "pending_reboot": pending_reboot,
        }

    @staticmethod
    def _disk_info() -> dict:
        """C 盘空间信息（GetDiskFreeSpaceExW）"""
        try:
            kernel32 = ctypes.windll.kernel32
            free = ctypes.c_ulonglong(0)
            total = ctypes.c_ulonglong(0)
            kernel32.GetDiskFreeSpaceExW("C:\\", None, ctypes.byref(total), ctypes.byref(free))
            free_b, total_b = free.value, total.value
            pct = free_b / total_b * 100 if total_b else 0
            return {
                "free_bytes": free_b, "total_bytes": total_b,
                "free_text": _format_size(free_b), "total_text": _format_size(total_b),
                "free_percent": pct,
            }
        except Exception:
            return {"free_bytes": 0, "total_bytes": 0, "free_text": "未知",
                    "total_text": "未知", "free_percent": 100}

    @staticmethod
    def _memory_info() -> dict:
        """物理内存信息（GlobalMemoryStatusEx）"""
        try:
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", wt.DWORD),
                    ("dwMemoryLoad", wt.DWORD),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            ms = MEMORYSTATUSEX()
            ms.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms)):
                raise OSError("GlobalMemoryStatusEx 失败")
            used = ms.ullTotalPhys - ms.ullAvailPhys
            return {
                "used_bytes": used, "total_bytes": ms.ullTotalPhys,
                "used_text": _format_size(used), "total_text": _format_size(ms.ullTotalPhys),
                "used_percent": used / ms.ullTotalPhys * 100 if ms.ullTotalPhys else 0,
            }
        except Exception:
            return {"used_bytes": 0, "total_bytes": 0, "used_text": "未知",
                    "total_text": "未知", "used_percent": 0}

    @staticmethod
    def _temp_size(cancel=None):
        """统计系统临时文件总量

        支持取消：令牌置位时返回 None（调用方据此判定为已取消）。
        """
        roots = []
        for name in ("TEMP", "TMP"):
            p = os.environ.get(name, "").strip().strip('"')
            if p and os.path.isdir(p) and p not in roots:
                roots.append(p)
        sys_temp = os.path.join(_win_dir, "Temp")
        if os.path.isdir(sys_temp) and sys_temp not in roots:
            roots.append(sys_temp)
        total = 0
        count = 0
        for root in roots:
            if _cancelled(cancel):
                return None
            for dirpath, _dirs, files in os.walk(root, onerror=lambda _e: None):
                if _cancelled(cancel):
                    return None
                for fn in files:
                    try:
                        total += os.path.getsize(os.path.join(dirpath, fn))
                        count += 1
                    except OSError:
                        pass
        return {"total_bytes": total, "size_text": _format_size(total), "file_count": count}

    @staticmethod
    def _pending_reboot() -> bool:
        """是否存在待处理的重启操作"""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SYSTEM\CurrentControlSet\Control\Session Manager")
            try:
                winreg.QueryValueEx(key, "PendingFileRenameOperations")
                return True
            except FileNotFoundError:
                return False
            finally:
                winreg.CloseKey(key)
        except OSError:
            return False

    # ════════════════════ 启动项管理 ════════════════════

    def list_startup(self) -> list:
        """列出全部启动项（注册表 + 启动文件夹），含禁用项"""
        items = []
        # 1. 注册表 Run 项
        for hive, subkey in STARTUP_REG_KEYS:
            try:
                key = winreg.OpenKey(_hive(hive), subkey)
            except OSError:
                continue
            try:
                idx = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, idx)
                    except OSError:
                        break
                    idx += 1
                    if not isinstance(data, str) or not data.strip():
                        continue
                    status = "enabled"
                    if name.startswith(DISABLED_PREFIX):
                        status = "disabled"
                    items.append(self._reg_item(hive, subkey, name, data, status))
            finally:
                winreg.CloseKey(key)
        # 2. 启动文件夹
        for folder in self._startup_folders():
            if not os.path.isdir(folder):
                continue
            for fn in os.listdir(folder):
                if fn.lower().endswith(".lnk"):
                    full = os.path.join(folder, fn)
                    items.append({
                        "item_id": _make_id("file", full),
                        "type": "file", "name": fn, "source": full,
                        "status": "enabled", "detail": "启动文件夹快捷方式",
                    })
            # 3. 已禁用的快捷方式（备份目录）
            backup_dir = os.path.join(folder, BACKUP_DIR_NAME)
            if os.path.isdir(backup_dir):
                for fn in os.listdir(backup_dir):
                    if fn.lower().endswith(".lnk"):
                        full = os.path.join(backup_dir, fn)
                        items.append({
                            "item_id": _make_id("file", full),
                            "type": "file", "name": fn, "source": full,
                            "status": "disabled", "detail": "启动文件夹快捷方式（已禁用）",
                        })
        items.sort(key=lambda x: (x["status"] != "enabled", x["name"].lower()))
        return items

    @staticmethod
    def _reg_item(hive, subkey, name, data, status) -> dict:
        return {
            "item_id": _make_id("reg", hive, subkey, name),
            "type": "reg",
            "hive": hive, "subkey": subkey, "value_name": name,
            "name": name, "source": data,
            "status": status, "detail": f"{hive}\\{subkey}",
        }

    @staticmethod
    def _startup_folders() -> list:
        folders = []
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            folders.append(os.path.join(appdata, "Microsoft", "Windows",
                                        "Start Menu", "Programs", "Startup"))
        progdata = os.environ.get("ProgramData", "")
        if progdata:
            folders.append(os.path.join(progdata, "Microsoft", "Windows",
                                        "Start Menu", "Programs", "StartUp"))
        return folders

    def toggle_startup(self, item_id: str, action: str) -> dict:
        """禁用/启用启动项（可逆，操作记录写入备份文件）"""
        if action not in ("disable", "enable"):
            return {"success": False, "error": f"未知操作: {action}"}
        info = _parse_id(item_id)
        if not info:
            return {"success": False, "error": "无效的启动项标识"}
        backup = self._load_backup()

        try:
            if info["t"] == "reg":
                result = self._toggle_reg_startup(info, action, backup)
            elif info["t"] == "file":
                result = self._toggle_file_startup(info, action, backup)
            else:
                return {"success": False, "error": "未知启动项类型"}
        except OSError as e:
            return {"success": False, "error": f"注册表/文件操作失败: {e}"}
        if result.get("success"):
            self._save_backup(backup)
        return result

    def _toggle_reg_startup(self, info: dict, action: str, backup: dict) -> dict:
        hive, subkey, value_name = info["hive"], info["subkey"], info["value_name"]
        key = winreg.OpenKey(_hive(hive), subkey, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE)
        try:
            if action == "disable":
                if value_name.startswith(DISABLED_PREFIX):
                    return {"success": False, "error": "该启动项已处于禁用状态"}
                data, _ = winreg.QueryValueEx(key, value_name)
                backup_name = DISABLED_PREFIX + value_name
                winreg.SetValueEx(key, backup_name, 0, winreg.REG_SZ, str(data))
                winreg.DeleteValue(key, value_name)
                backup["startup"][info["id"]] = {
                    "type": "reg", "hive": hive, "subkey": subkey,
                    "value_name": value_name, "backup_name": backup_name,
                    "action": "disable", "timestamp": datetime.now().isoformat(),
                }
                return {"success": True, "message": f"已禁用启动项：{value_name}"}
            else:  # enable
                rec = backup["startup"].get(info["id"])
                if not rec or rec.get("backup_name") != value_name:
                    # 无备份记录但值名带前缀，直接还原
                    if value_name.startswith(DISABLED_PREFIX):
                        original = value_name[len(DISABLED_PREFIX):]
                        data, _ = winreg.QueryValueEx(key, value_name)
                        winreg.SetValueEx(key, original, 0, winreg.REG_SZ, str(data))
                        winreg.DeleteValue(key, value_name)
                        backup["startup"].pop(info["id"], None)
                        return {"success": True, "message": f"已启用启动项：{original}"}
                    return {"success": False, "error": "未找到该启动项的禁用记录"}
                data, _ = winreg.QueryValueEx(key, rec["backup_name"])
                winreg.SetValueEx(key, rec["value_name"], 0, winreg.REG_SZ, str(data))
                winreg.DeleteValue(key, rec["backup_name"])
                backup["startup"].pop(info["id"], None)
                return {"success": True, "message": f"已启用启动项：{rec['value_name']}"}
        finally:
            winreg.CloseKey(key)

    def _toggle_file_startup(self, info: dict, action: str, backup: dict) -> dict:
        path = info["path"]
        if not os.path.isfile(path):
            return {"success": False, "error": f"文件不存在: {path}"}
        folder = os.path.dirname(path)
        backup_dir = os.path.join(folder, BACKUP_DIR_NAME)

        if action == "disable":
            if BACKUP_DIR_NAME + os.sep in path:
                return {"success": False, "error": "该启动项已处于禁用状态"}
            os.makedirs(backup_dir, exist_ok=True)
            dest = os.path.join(backup_dir, os.path.basename(path))
            os.replace(path, dest)
            backup["startup"][info["id"]] = {
                "type": "file", "original_path": path, "backup_path": dest,
                "action": "disable", "timestamp": datetime.now().isoformat(),
            }
            return {"success": True, "message": f"已禁用启动项：{os.path.basename(path)}"}
        else:  # enable
            rec = backup["startup"].get(info["id"])
            orig = rec["original_path"] if rec else None
            if not orig or not os.path.isfile(path):
                return {"success": False, "error": "未找到该启动项的禁用记录"}
            os.makedirs(os.path.dirname(orig), exist_ok=True)
            os.replace(path, orig)
            backup["startup"].pop(info["id"], None)
            return {"success": True, "message": f"已启用启动项：{os.path.basename(orig)}"}

    # ════════════════════ 服务优化 ════════════════════

    def list_services(self) -> dict:
        """列出服务：readonly=系统服务（只读），manageable=第三方服务（可管理）"""
        services = self._enum_services()
        sys_root = _win_dir.lower()
        readonly, manageable = [], []
        for svc in services:
            img = svc.get("image_path", "")
            exp = os.path.expandvars(img).replace("\\SystemRoot\\", sys_root + "\\").strip('"')
            third_party = bool(exp) and not exp.lower().startswith(sys_root + "\\")
            entry = {
                "name": svc["name"],
                "display": svc.get("display_name") or svc["name"],
                "state": svc.get("state", "unknown"),
                "start_type": svc.get("start_type", "unknown"),
                "image_path": img,
            }
            (manageable if third_party else readonly).append(entry)
        manageable.sort(key=lambda x: x["display"].lower())
        readonly.sort(key=lambda x: x["display"].lower())
        return {"readonly": readonly, "manageable": manageable,
                "readonly_count": len(readonly), "manageable_count": len(manageable)}

    @staticmethod
    def _enum_services() -> list:
        """枚举服务（HKLM\\SYSTEM\\CurrentControlSet\\Services，仅 Win32 服务）"""
        services = []
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
        except OSError:
            return services
        try:
            idx = 0
            while True:
                try:
                    name = winreg.EnumKey(key, idx)
                except OSError:
                    break
                idx += 1
                try:
                    sk = winreg.OpenKey(key, name)
                    try:
                        svc_type, _ = winreg.QueryValueEx(sk, "Type")
                        if svc_type not in (0x10, 0x20):  # 仅 Win32 服务
                            continue
                        start, _ = winreg.QueryValueEx(sk, "Start")
                        entry = {
                            "name": name,
                            "start_type": {2: "auto", 3: "manual", 4: "disabled"}.get(start, "unknown"),
                            "start_value": start,
                        }
                        for attr, key_name in (("display_name", "DisplayName"),
                                               ("image_path", "ImagePath"),
                                               ("state", "State")):
                            try:
                                val, _ = winreg.QueryValueEx(sk, key_name)
                                entry[attr] = val
                            except FileNotFoundError:
                                entry[attr] = ""
                        services.append(entry)
                    finally:
                        winreg.CloseKey(sk)
                except OSError:
                    continue
        finally:
            winreg.CloseKey(key)
        return services

    def toggle_service(self, name: str, action: str) -> dict:
        """修改第三方服务启动类型（auto/manual/disabled），记录原值可还原"""
        mapping = {"auto": SERVICE_START_AUTO, "manual": SERVICE_START_MANUAL,
                   "disabled": SERVICE_START_DISABLED}
        if action not in mapping:
            return {"success": False, "error": f"未知操作: {action}"}
        if not name or "\\" in name or name.startswith("."):
            return {"success": False, "error": "非法的服务名"}
        # 仅允许第三方服务
        svcs = {s["name"]: s for s in self._enum_services()}
        svc = svcs.get(name)
        if not svc:
            return {"success": False, "error": f"服务不存在: {name}"}
        img = svc.get("image_path", "")
        exp = os.path.expandvars(img).replace("\\SystemRoot\\", _win_dir + "\\").strip('"')
        if not exp or exp.lower().startswith(_win_dir.lower() + "\\"):
            return {"success": False, "error": f"系统关键服务不可修改: {name}"}

        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 rf"SYSTEM\CurrentControlSet\Services\{name}",
                                 0, winreg.KEY_READ | winreg.KEY_SET_VALUE)
        except OSError as e:
            return {"success": False, "error": f"无法打开服务注册表项（需要管理员权限）: {e}"}
        try:
            backup = self._load_backup()
            services_rec = backup.setdefault("services", {})
            if name not in services_rec:
                services_rec[name] = {"original_start": svc["start_value"],
                                      "timestamp": datetime.now().isoformat()}
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, mapping[action])
            self._save_backup(backup)
            return {"success": True, "message": f"已设置服务「{svc.get('display_name') or name}」为 {action}"}
        finally:
            winreg.CloseKey(key)

    # ════════════════════ 内存释放 ════════════════════

    def release_memory(self, cancel=None) -> dict:
        """对高占用进程执行工作集收缩（SetProcessWorkingSetSize(-1,-1)）

        cancel: 可选取消令牌；置位后在进程枚举循环中立即停止。
        """
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_SET_QUOTA = 0x0100
        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", wt.LONG),
                ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_wchar * 260),
            ]

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wt.DWORD), ("PageFaultCount", wt.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        released = 0
        processed = 0
        try:
            snapshot = kernel32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
            if snapshot in (0, -1):
                return {"success": False, "error": "无法创建进程快照"}
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                kernel32.CloseHandle(snapshot)
                return {"success": False, "error": "无法枚举进程"}
            try:
                while True:
                    if _cancelled(cancel):
                        break
                    pid = entry.th32ProcessID
                    if pid > 4:  # 跳过 System/Idle
                        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA,
                                                      False, pid)
                        if handle:
                            try:
                                counters = PROCESS_MEMORY_COUNTERS()
                                counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
                                if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters),
                                                              ctypes.sizeof(counters)):
                                    before = counters.WorkingSetSize
                                    if before > MEM_MIN_WORKING_SET_MB * 1024 * 1024:
                                        kernel32.SetProcessWorkingSetSize(handle,
                                                                          ctypes.c_size_t(-1),
                                                                          ctypes.c_size_t(-1))
                                        after = ctypes.c_size_t(0)
                                        counters2 = PROCESS_MEMORY_COUNTERS()
                                        counters2.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
                                        if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters2),
                                                                      ctypes.sizeof(counters2)):
                                            after = counters2.WorkingSetSize
                                        released += max(0, before - after)
                                        processed += 1
                            finally:
                                kernel32.CloseHandle(handle)
                    if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                        break
            finally:
                kernel32.CloseHandle(snapshot)
        except Exception as e:
            return {"success": False, "error": str(e)}

        return {
            "success": True,
            "cancelled": _cancelled(cancel),
            "released_bytes": released,
            "released_text": _format_size(released),
            "processed": processed,
        }

    # ════════════════════ 一键优化 ════════════════════

    def one_click(self, cancel=None) -> dict:
        """一键优化：清理临时类垃圾 + 释放内存 + 给出启动项建议（不自动禁用）

        cancel: 可选取消令牌；在三个阶段之间检查，置位后返回已完成的部分结果。
        """
        from engine.junk_cleaner import JunkCleaner
        cleaner = JunkCleaner()
        clean_result = cleaner.execute_clean(["temp_files", "crash_dumps", "update_cache"],
                                             cancel=cancel)
        if _cancelled(cancel):
            return {
                "success": True,
                "cancelled": True,
                "clean": clean_result,
                "memory": None,
                "recommendations": [],
            }
        mem_result = self.release_memory(cancel=cancel)
        if _cancelled(cancel):
            return {
                "success": True,
                "cancelled": True,
                "clean": clean_result,
                "memory": mem_result,
                "recommendations": [],
            }

        # 启动项建议：路径不在 Windows / Program Files 下的启用项
        recommendations = []
        sys_root = _win_dir.lower()
        for item in self.list_startup():
            if item["status"] != "enabled":
                continue
            src = (item.get("source") or "").lower()
            if src and not (src.startswith(sys_root) or "program files" in src):
                recommendations.append({
                    "item_id": item["item_id"], "name": item["name"],
                    "source": item.get("source", ""),
                })

        return {
            "success": True,
            "clean": clean_result,
            "memory": mem_result,
            "recommendations": recommendations[:20],
        }

    # ════════════════════ 备份记录 ════════════════════

    def _load_backup(self) -> dict:
        with self._lock:
            if self._backup is None:
                if os.path.isfile(_BACKUP_FILE):
                    try:
                        with open(_BACKUP_FILE, "r", encoding="utf-8") as f:
                            self._backup = json.load(f)
                    except (OSError, json.JSONDecodeError):
                        self._backup = {}
                else:
                    self._backup = {}
                self._backup.setdefault("startup", {})
                self._backup.setdefault("services", {})
            return self._backup

    def _save_backup(self, backup: dict):
        with self._lock:
            try:
                with open(_BACKUP_FILE, "w", encoding="utf-8") as f:
                    json.dump(backup, f, ensure_ascii=False, indent=2)
                self._backup = backup
            except OSError:
                pass


# ── 启动项标识编解码 ──

def _hive(name: str):
    return {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}.get(name, winreg.HKEY_CURRENT_USER)


def _make_id(*parts) -> str:
    """把 (类型, 各级路径...) 编码为 URL 安全的稳定标识"""
    import base64
    raw = "|".join(str(p) for p in parts).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _parse_id(item_id: str) -> dict:
    """解析 item_id → {t, id, hive/subkey/value_name | path}"""
    import base64
    try:
        raw = base64.urlsafe_b64decode(item_id.encode("ascii")).decode("utf-8")
    except Exception:
        return None
    parts = raw.split("|")
    if not parts:
        return None
    t = parts[0]
    if t == "reg" and len(parts) >= 4:
        return {"t": "reg", "id": item_id, "hive": parts[1],
                "subkey": parts[2], "value_name": parts[3]}
    if t == "file" and len(parts) >= 2:
        return {"t": "file", "id": item_id, "path": parts[1]}
    return None
