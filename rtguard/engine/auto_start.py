"""
开机自启管理模块
通过写入 HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run 注册御天自启
"""
import os
import sys
import ctypes
import ctypes.wintypes as wt

# Windows API
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True) if sys.platform == "win32" else None

REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_NAME = "安盾安全中心"


def _get_exe_path() -> str:
    """获取当前可执行文件路径"""
    if getattr(sys, 'frozen', False):
        exe = sys.executable
    else:
        # 开发模式：返回 python app.py 形式的命令
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        exe = os.path.join(base, "backend", "app.py")
        # 尝试找 python
        python = sys.executable
        return f'"{python}" "{exe}"'
    return f'"{exe}"'


def is_enabled() -> bool:
    """检查开机自启是否已启用"""
    if not advapi32:
        return False
    hKey = wt.HANDLE()
    ret = advapi32.RegOpenKeyExW(
        wt.HANDLE(0x80000001),  # HKEY_CURRENT_USER
        REG_PATH,
        0,
        0x00020019,  # KEY_READ
        ctypes.byref(hKey)
    )
    if ret != 0:
        return False
    buf = ctypes.create_unicode_buffer(1024)
    buf_size = wt.DWORD(ctypes.sizeof(buf))
    ret = advapi32.RegQueryValueExW(hKey, REG_NAME, None, None, buf, ctypes.byref(buf_size))
    advapi32.RegCloseKey(hKey)
    return ret == 0


def enable() -> bool:
    """启用开机自启"""
    if not advapi32:
        return False
    hKey = wt.HANDLE()
    ret = advapi32.RegCreateKeyExW(
        wt.HANDLE(0x80000001),  # HKEY_CURRENT_USER
        REG_PATH,
        0, None, 0,
        0x2001F,  # KEY_ALL_ACCESS
        None, ctypes.byref(hKey), None
    )
    if ret != 0:
        return False
    exe_path = _get_exe_path()
    ret = advapi32.RegSetValueExW(
        hKey, REG_NAME, 0, 1,  # REG_SZ = 1
        exe_path.encode('utf-16-le') + b'\x00\x00',
        (len(exe_path) + 1) * 2
    )
    advapi32.RegCloseKey(hKey)
    return ret == 0


def disable() -> bool:
    """禁用开机自启"""
    if not advapi32:
        return False
    hKey = wt.HANDLE()
    ret = advapi32.RegOpenKeyExW(
        wt.HANDLE(0x80000001),  # HKEY_CURRENT_USER
        REG_PATH,
        0,
        0x2001F,  # KEY_ALL_ACCESS
        ctypes.byref(hKey)
    )
    if ret != 0:
        return True  # 键不存在也算成功
    advapi32.RegDeleteValueW(hKey, REG_NAME)
    advapi32.RegCloseKey(hKey)
    return True


def toggle() -> dict:
    """切换开机自启状态"""
    if is_enabled():
        ok = disable()
        return {"enabled": False, "success": ok}
    else:
        ok = enable()
        return {"enabled": True, "success": ok}


def status() -> dict:
    """获取开机自启状态"""
    return {"enabled": is_enabled()}



