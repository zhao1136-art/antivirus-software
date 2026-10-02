"""
Shell 集成模块 - 右键菜单"使用安盾扫描"
通过注册表 HKEY_CLASSES_ROOT 添加文件/文件夹右键菜单
"""
import sys
import ctypes
import ctypes.wintypes as wt
import os

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True) if sys.platform == "win32" else None

# HKEY_CLASSES_ROOT
HKEY_CLASSES_ROOT = wt.HANDLE(0x80000000)

# Shell 菜单注册路径
SHELL_KEY_ALL = r"*\shell\AndunScan"
SHELL_KEY_DIR = r"Directory\shell\AndunScan"
SHELL_KEY_DRIVE = r"Drive\shell\AndunScan"


def _get_exe_for_shell() -> str:
    """获取用于右键菜单的可执行文件路径"""
    if getattr(sys, 'frozen', False):
        return f'"{sys.executable}"'
    # 开发模式下用 python app.py
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = os.path.join(base, "backend", "app.py")
    python = sys.executable
    return f'"{python}" "{app}"'


def _reg_write(hRoot, subKey, value_name, value_data):
    """写入注册表值"""
    hKey = wt.HANDLE()
    ret = advapi32.RegCreateKeyExW(
        hRoot, subKey, 0, None, 0,
        0x2001F, None, ctypes.byref(hKey), None
    )
    if ret != 0:
        return False
    # 写入值
    if isinstance(value_data, str):
        data = value_data.encode('utf-16-le') + b'\x00\x00'
        data_len = (len(value_data) + 1) * 2
        type_id = 1  # REG_SZ
    else:
        data = value_data
        data_len = len(data)
        type_id = 1

    ret = advapi32.RegSetValueExW(
        hKey, value_name, 0, type_id, data, data_len
    )
    advapi32.RegCloseKey(hKey)
    return ret == 0


def _reg_create_key(hRoot, subKey):
    """创建注册表键"""
    hKey = wt.HANDLE()
    ret = advapi32.RegCreateKeyExW(
        hRoot, subKey, 0, None, 0,
        0x2001F, None, ctypes.byref(hKey), None
    )
    if ret == 0:
        advapi32.RegCloseKey(hKey)
    return ret == 0


def register() -> bool:
    """注册右键菜单"""
    if not advapi32:
        return False

    exe = _get_exe_for_shell()
    cmd = f'{exe} scan "%1"'

    ok = True
    for key_path in [SHELL_KEY_ALL, SHELL_KEY_DIR, SHELL_KEY_DRIVE]:
        # 创建主键 & 设置显示名称
        if not _reg_create_key(HKEY_CLASSES_ROOT, key_path):
            ok = False
            continue
        if not _reg_write(HKEY_CLASSES_ROOT, key_path, None, "使用御天扫描"):
            ok = False
        if not _reg_write(HKEY_CLASSES_ROOT, key_path, "Icon",
                          os.path.join(getattr(sys, '_MEIPASS',
                                              os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                       "御天图标.ico")):
            pass  # icon 不是必须的
        # 创建 command 子键
        cmd_key = key_path + r"\command"
        if not _reg_create_key(HKEY_CLASSES_ROOT, cmd_key):
            ok = False
        if not _reg_write(HKEY_CLASSES_ROOT, cmd_key, None, cmd):
            ok = False

    return ok


def unregister() -> bool:
    """移除右键菜单"""
    if not advapi32:
        return False
    ok = True
    for key_path in [SHELL_KEY_ALL, SHELL_KEY_DIR, SHELL_KEY_DRIVE]:
        # RegDeleteTreeW - 递归删除
        hKey = wt.HANDLE()
        ret = advapi32.RegOpenKeyExW(
            HKEY_CLASSES_ROOT,
            key_path.rsplit('\\', 1)[0] if '\\' in key_path else "",
            0, 0x2001F, ctypes.byref(hKey)
        )
        if ret == 0:
            sub_key = key_path.rsplit('\\', 1)[1] if '\\' in key_path else key_path
            advapi32.RegDeleteTreeW(hKey, sub_key)
            advapi32.RegCloseKey(hKey)
    return ok


def is_registered() -> bool:
    """检查右键菜单是否已注册"""
    if not advapi32:
        return False
    hKey = wt.HANDLE()
    ret = advapi32.RegOpenKeyExW(
        HKEY_CLASSES_ROOT, SHELL_KEY_ALL + r"\command",
        0, 0x00020019, ctypes.byref(hKey)
    )
    if ret == 0:
        advapi32.RegCloseKey(hKey)
        return True
    return False


def status() -> dict:
    return {"registered": is_registered()}


