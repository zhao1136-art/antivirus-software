# -*- coding: utf-8 -*-
"""御天安全卫士 · 安装程序公共模块
提供产品信息常量、注册表读写、快捷方式创建/删除等共用逻辑。
"""
import os
import sys
import ctypes
import subprocess
import tempfile

# ---------------- 产品信息 ----------------
APP_NAME = "御天安全卫士"          # 产品显示名
APP_EXE = "御天.exe"               # 主程序
UNINSTALLER_EXE = "删除程序.exe"    # 删除程序
PUBLISHER = "Caelire"
APP_VERSION = "1.0.0"

# ---------------- 注册表路径 ----------------
# 添加/删除程序 卸载入口（HKLM，需管理员）
UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\御天安全卫士"
# 程序路径关联（App Paths，便于 shell 启动）
APP_PATHS_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\御天.exe"
# 开机自启（HKCU）
RUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "御天安全卫士"

# ---------------- 快捷方式 ----------------
SHORTCUT_NAME = "御天安全卫士.lnk"

def is_admin():
    """当前进程是否以管理员权限运行"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_self():
    """以管理员权限重新启动自身"""
    if is_admin():
        return True
    params = " ".join('"{0}"'.format(a) for a in sys.argv[1:])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1)
    return ret > 32


def msgbox(text, title=APP_NAME, flags=0x40):  # 0x40 = MB_ICONINFORMATION
    ctypes.windll.user32.MessageBoxW(None, text, title, flags)


# ---------------- 注册表 ----------------
def write_uninstall_registry(install_dir):
    """写入卸载信息 + App Paths 注册表"""
    import winreg
    from winreg import KEY_ALL_ACCESS
    # 卸载键（HKLM）
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY, 0,
                            KEY_ALL_ACCESS) as key:
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, APP_NAME)
        winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, APP_VERSION)
        winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, PUBLISHER)
        winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ,
                          os.path.join(install_dir, APP_EXE))
        winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, install_dir)
        winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_EXPAND_SZ,
                          '"{0}"'.format(os.path.join(install_dir, UNINSTALLER_EXE)))
        winreg.SetValueEx(key, "QuietUninstallString", 0, winreg.REG_EXPAND_SZ,
                          '"{0}" /quiet'.format(os.path.join(install_dir, UNINSTALLER_EXE)))
        winreg.SetValueEx(key, "EstimatedSize", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
    # App Paths（HKLM）
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, APP_PATHS_KEY, 0,
                            KEY_ALL_ACCESS) as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ,
                          os.path.join(install_dir, APP_EXE))
        winreg.SetValueEx(key, "Path", 0, winreg.REG_SZ, install_dir + ";")


def write_run_registry(install_dir):
    """写入开机自启（HKCU Run），指向主程序"""
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE)
    except OSError:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY)
    with key:
        winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ,
                          '"{0}"'.format(os.path.join(install_dir, APP_EXE)))


def remove_registry_entries():
    """删除卸载信息 / App Paths / 开机自启"""
    import winreg
    for hive, subkey in [(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY),
                         (winreg.HKEY_LOCAL_MACHINE, APP_PATHS_KEY)]:
        try:
            winreg.DeleteKey(hive, subkey)
        except OSError:
            pass
    # 开机自启：仅删除指向本软件的值
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE)
        try:
            val, _ = winreg.QueryValueEx(key, RUN_VALUE)
            if APP_EXE in val:
                winreg.DeleteValue(key, RUN_VALUE)
        except OSError:
            pass
        key.Close()
    except OSError:
        pass


def get_install_location():
    """从注册表读取安装目录（供卸载程序定位）"""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY) as key:
            val, _ = winreg.QueryValueEx(key, "InstallLocation")
            if val and os.path.isdir(val):
                return val
    except OSError:
        pass
    return None


# ---------------- 快捷方式 ----------------
def _vbs_quote(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def create_shortcut(lnk_path, target, workdir=None, icon=None, args=""):
    """通过 WScript 创建 .lnk 快捷方式"""
    try:
        vbs = os.path.join(tempfile.gettempdir(), "yt_lnk_%d.vbs" % os.getpid())
        with open(vbs, "w", encoding="utf-8") as f:
            f.write(
                'Set sh = WScript.CreateObject("WScript.Shell")\n'
                'Set l = sh.CreateShortcut("{0}")\n'
                'l.TargetPath = "{1}"\n'
                'l.Arguments = "{2}"\n'
                'l.WorkingDirectory = "{3}"\n'
                'l.IconLocation = "{4}"\n'
                'l.WindowStyle = 1\n'
                'l.Save()\n'.format(
                    _vbs_quote(lnk_path), _vbs_quote(target), _vbs_quote(args),
                    _vbs_quote(workdir or os.path.dirname(target)),
                    _vbs_quote(icon or target)))
        subprocess.run(["wscript.exe", "//nologo", vbs],
                       creationflags=0x08000000,  # CREATE_NO_WINDOW
                       check=True, timeout=15)
        return True
    except Exception:
        return False


def create_desktop_shortcut(target_path):
    desktop = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
    if not os.path.isdir(desktop):
        return False
    return create_shortcut(
        os.path.join(desktop, SHORTCUT_NAME), target_path,
        workdir=os.path.dirname(target_path), icon=target_path)


def create_startmenu_shortcut(target_path):
    sm = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows",
                      "Start Menu", "Programs")
    if not os.path.isdir(sm):
        return False
    return create_shortcut(
        os.path.join(sm, SHORTCUT_NAME), target_path,
        workdir=os.path.dirname(target_path), icon=target_path)


def remove_shortcuts():
    """删除桌面 / 开始菜单快捷方式"""
    dirs = [
        os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
        os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows",
                     "Start Menu", "Programs"),
        os.path.join(os.environ.get("PROGRAMDATA", ""), "Microsoft", "Windows",
                     "Start Menu", "Programs"),
    ]
    for d in dirs:
        try:
            p = os.path.join(d, SHORTCUT_NAME)
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass
