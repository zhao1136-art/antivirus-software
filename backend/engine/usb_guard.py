"""
御天 U盘免疫与外设管控模块

职责：
  1. U盘免疫：在可移动磁盘根目录创建隐藏的 autorun.inf 目录，
     阻止 Autorun 型病毒利用 autorun.inf 自动传播。
  2. 禁用自动播放：通过注册表关闭可移动磁盘的自动运行。
  3. 外设管控：通过注册表启用/禁用 USB 存储设备（USBSTOR 服务），
     管理外接存储接入权限。

均为本地安全管控，非内核、无需驱动，重启后按注册表配置生效。
"""
import os
import sys
import string
import ctypes
import threading

IS_WINDOWS = sys.platform == "win32"

# 自动播放注册表路径（NoDriveTypeAutoRun 位掩码）
AUTORUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
AUTORUN_VAL = "NoDriveTypeAutoRun"
# 0xFF = 全部禁用；常见屏蔽可移动盘的掩码
AUTORUN_DISABLE_ALL = 0xFF
AUTORUN_ENABLE_VALUE = 0x91

# USB 大容量存储设备服务（USBSTOR）
USBSTOR_KEY = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
USBSTOR_VAL = "Start"
START_DISABLED = 4  # 禁用
START_ENABLED = 3   # 手动/启用


def _drive_removable(letter: str) -> bool:
    """判断盘符（如 'D'）是否为可移动磁盘"""
    if not IS_WINDOWS:
        return False
    try:
        path = f"{letter}:\\"
        dt = ctypes.windll.kernel32.GetDriveTypeW(path)
        return dt == 2  # DRIVE_REMOVABLE
    except Exception:
        return False


def _list_removable_drives() -> list[str]:
    """枚举当前所有可移动磁盘盘符（如 'D'）"""
    out = []
    if not IS_WINDOWS:
        return out
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for i, ch in enumerate(string.ascii_uppercase):
            if mask & (1 << i) and _drive_removable(ch):
                out.append(ch)
    except Exception:
        pass
    return out


class UsbGuard:
    """U盘免疫与外设管控（单实例，线程安全）"""

    def __init__(self):
        self._lock = threading.Lock()
        self._immunized = set()   # 已执行免疫的盘符（本次运行）
        self._autorun_off = None  # 上次设置的自动播放状态
        self._usb_storage = None  # 上次设置的 USB 存储状态

    # ── U盘免疫 ─────────────────────────────────────────────
    def _immunize_one(self, letter: str) -> dict:
        """对单个盘符执行免疫：创建只读的 autorun.inf 目录"""
        root = f"{letter}:\\"
        target = os.path.join(root, "autorun.inf")
        ok = False
        msg = ""
        try:
            if os.path.isdir(target):
                # 已存在目录则视为已免疫（autorun.inf 同名文件无法被病毒创建）
                ok, msg = True, "已存在 autorun.inf 免疫目录"
            elif os.path.exists(target):
                # 存在同名文件：尽量改名为目录占位（受保护时跳过）
                try:
                    os.remove(target)
                except Exception:
                    pass
                try:
                    os.mkdir(target)
                    ok, msg = True, "已覆盖占用其为免疫目录"
                except Exception:
                    ok, msg = False, "autorun.inf 为文件且受保护，无法免疫"
            else:
                os.mkdir(target)
                ok, msg = True, "已创建 autorun.inf 免疫目录"
            # 设置隐藏 + 系统属性，降低被误删概率
            try:
                ctypes.windll.kernel32.SetFileAttributesW(
                    target, 0x2 | 0x4  # HIDDEN | SYSTEM
                )
            except Exception:
                pass
        except PermissionError:
            ok, msg = False, "权限不足（请以管理员运行）"
        except Exception as e:
            ok, msg = False, str(e)
        if ok:
            self._immunized.add(letter)
        return {"drive": f"{letter}:\\", "ok": ok, "msg": msg}

    def immunize(self, letter: str | None = None) -> dict:
        """对指定盘符（或全部可移动磁盘）执行免疫"""
        letters = [letter.upper().rstrip(":\\")] if letter \
            else _list_removable_drives()
        results = [self._immunize_one(l) for l in letters]
        return {"results": results}

    # ── 自动播放开关 ────────────────────────────────────────
    def set_autorun(self, enabled: bool) -> dict:
        """启用/禁用自动播放（针对可移动磁盘）"""
        if not IS_WINDOWS:
            return {"ok": False, "msg": "非 Windows 环境"}
        try:
            import winreg
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, AUTORUN_KEY, 0,
                                    winreg.KEY_SET_VALUE) as k:
                if enabled:
                    winreg.DeleteValue(k, AUTORUN_VAL)
                    code = AUTORUN_ENABLE_VALUE
                else:
                    code = AUTORUN_DISABLE_ALL
                    winreg.SetValueEx(k, AUTORUN_VAL, 0, winreg.REG_DWORD, code)
            self._autorun_off = not enabled
            return {"ok": True, "enabled": enabled}
        except Exception as e:
            return {"ok": False, "msg": f"{type(e).__name__}: {e}"}

    # ── USB 存储设备管控 ────────────────────────────────────
    def set_usb_storage(self, enabled: bool) -> dict:
        """
        启用/禁用 USB 存储设备接入。
        enabled=False 时禁用 USBSTOR 服务，禁止新 U 盘被识别（外设管控）。
        需要管理员权限；对已接入设备需重插或重启生效。
        """
        if not IS_WINDOWS:
            return {"ok": False, "msg": "非 Windows 环境"}
        try:
            import winreg
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, USBSTOR_KEY, 0,
                                    winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, USBSTOR_VAL, 0, winreg.REG_DWORD,
                                  START_ENABLED if enabled else START_DISABLED)
            self._usb_storage = enabled
            return {"ok": True, "enabled": enabled,
                    "msg": "USB 存储已允许" if enabled else "USB 存储已禁用（新设备需重插生效）"}
        except PermissionError:
            return {"ok": False, "msg": "权限不足，请以管理员身份运行"}
        except Exception as e:
            return {"ok": False, "msg": f"{type(e).__name__}: {e}"}

    # ── 状态 ────────────────────────────────────────────────
    def get_status(self) -> dict:
        drives = _list_removable_drives()
        autorun_on = self._read_autorun() if IS_WINDOWS else None
        usb_storage = self._read_usb_storage() if IS_WINDOWS else None
        return {
            "removable_drives": drives,
            "immunized_drives": sorted(self._immunized),
            "autorun_enabled": autorun_on,
            "usb_storage_enabled": usb_storage,
        }

    @staticmethod
    def _read_autorun() -> bool | None:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTORUN_KEY) as k:
                v, _ = winreg.QueryValueEx(k, AUTORUN_VAL)
                return int(v) != AUTORUN_DISABLE_ALL
        except (FileNotFoundError, OSError):
            return True  # 无策略值默认启用
        except Exception:
            return None

    @staticmethod
    def _read_usb_storage() -> bool | None:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, USBSTOR_KEY) as k:
                v, _ = winreg.QueryValueEx(k, USBSTOR_VAL)
                return int(v) != START_DISABLED
        except FileNotFoundError:
            return True
        except OSError:
            return None
        except Exception:
            return None


# 单例
_global: UsbGuard | None = None


def get_usb_guard() -> UsbGuard:
    global _global
    if _global is None:
        _global = UsbGuard()
    return _global