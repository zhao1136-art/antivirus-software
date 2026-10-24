"""
御天 安装程序 - Windows 标准安装/卸载
用法：
  双击运行 -> 安装
  已安装时运行 -> 询问是否卸载
"""
import sys
import os
import shutil
import subprocess
import ctypes
import winreg

APP_NAME = "御天"
APP_VERSION = "1.1.0"
APP_PUBLISHER = "御天安全"
APP_DISPLAY_NAME = f"{APP_NAME} {APP_VERSION}"
INSTALL_DIR = os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), APP_NAME)
UNINSTALL_KEY = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{APP_NAME}"
START_MENU = os.path.join(os.environ["ProgramData"], "Microsoft", "Windows", "Start Menu", "Programs")
DESKTOP = os.path.join(os.environ["USERPROFILE"], "Desktop")

# 源文件目录
if getattr(sys, 'frozen', False):
    SOURCE_DIR = sys._MEIPASS
else:
    SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))

MB_OK = 0
MB_ICONINFORMATION = 0x40
MB_ICONWARNING = 0x30
MB_ICONERROR = 0x10
MB_YESNO = 4
MB_SYSTEMMODAL = 0x1000
IDYES = 6


def msgbox(title: str, message: str, flags: int = MB_OK | MB_ICONINFORMATION):
    try:
        return ctypes.windll.user32.MessageBoxW(0, message, title, flags | MB_SYSTEMMODAL)
    except Exception:
        print(f"[{title}] {message}")
        return 0


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def request_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)


def is_installed() -> bool:
    return os.path.exists(os.path.join(INSTALL_DIR, "御天.exe"))


def create_shortcut(target: str, lnk_path: str, icon: str = "", desc: str = ""):
    """使用 PowerShell 创建快捷方式"""
    icon_arg = icon if icon else target
    ps = f'''
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("{lnk_path}")
$Shortcut.TargetPath = "{target}"
$Shortcut.IconLocation = "{icon_arg}"
$Shortcut.Description = "{desc}"
$Shortcut.Save()
'''
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, timeout=10)
    except Exception as e:
        print(f"创建快捷方式失败: {lnk_path} - {e}")


def register_uninstaller():
    """注册到 Windows 添加/删除程序"""
    try:
        uninstaller = os.path.join(INSTALL_DIR, "uninstall.exe")
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY) as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, APP_DISPLAY_NAME)
            winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, f'"{uninstaller}"')
            winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, os.path.join(INSTALL_DIR, "御天.exe"))
            winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, APP_PUBLISHER)
            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, APP_VERSION)
            winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
            total_size = 0
            for root, dirs, files in os.walk(INSTALL_DIR):
                for f in files:
                    try:
                        total_size += os.path.getsize(os.path.join(root, f))
                    except Exception:
                        pass
            winreg.SetValueEx(key, "EstimatedSize", 0, winreg.REG_DWORD, total_size // 1024)
    except Exception as e:
        msgbox("注册信息", f"注册卸载信息失败: {e}", MB_ICONWARNING)


def unregister_uninstaller():
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"移除注册表失败: {e}")


def remove_shortcuts():
    lnk = os.path.join(START_MENU, APP_NAME, f"{APP_NAME}.lnk")
    if os.path.exists(lnk):
        os.remove(lnk)
    parent = os.path.join(START_MENU, APP_NAME)
    if os.path.exists(parent):
        try:
            os.rmdir(parent)
        except Exception:
            pass
    dlnk = os.path.join(DESKTOP, f"{APP_NAME}.lnk")
    if os.path.exists(dlnk):
        os.remove(dlnk)


def install():
    exe_path = os.path.join(INSTALL_DIR, "御天.exe")

    if is_installed():
        r = msgbox(APP_NAME, f"{APP_NAME} 已安装在:\n{INSTALL_DIR}\n\n是否覆盖安装？", MB_YESNO | MB_ICONWARNING)
        if r != IDYES:
            return
        try:
            os.system('taskkill /f /im 御天.exe 2>nul')
            os.system('taskkill /f /im file_guard.exe 2>nul')
        except Exception:
            pass

    os.makedirs(INSTALL_DIR, exist_ok=True)

    try:
        # 复制源文件目录中的所有内容
        for item in os.listdir(SOURCE_DIR):
            src = os.path.join(SOURCE_DIR, item)
            dst = os.path.join(INSTALL_DIR, item)
            if item == "installer.exe":
                continue  # 跳过安装程序自身
            if os.path.isdir(src):
                if os.path.exists(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)

        # 复制自身为卸载程序
        if getattr(sys, 'frozen', False):
            shutil.copy2(sys.executable, os.path.join(INSTALL_DIR, "uninstall.exe"))
    except Exception as e:
        msgbox("安装失败", f"文件复制失败:\n{e}", MB_ICONERROR)
        return

    # 快捷方式
    start_folder = os.path.join(START_MENU, APP_NAME)
    os.makedirs(start_folder, exist_ok=True)
    create_shortcut(exe_path, os.path.join(start_folder, f"{APP_NAME}.lnk"), exe_path, f"{APP_NAME} 安全中心")
    create_shortcut(exe_path, os.path.join(DESKTOP, f"{APP_NAME}.lnk"), exe_path, f"{APP_NAME} 安全中心")

    register_uninstaller()

    msgbox(APP_NAME, f"安装完成！\n\n安装路径: {INSTALL_DIR}\n桌面和开始菜单已创建快捷方式")


def uninstall():
    r = msgbox(APP_NAME, f"确定要卸载 {APP_NAME} 吗？\n\n安装目录: {INSTALL_DIR}\n\n所有文件将被删除。", MB_YESNO | MB_ICONWARNING)
    if r != IDYES:
        return

    try:
        os.system('taskkill /f /im 御天.exe 2>nul')
        os.system('taskkill /f /im file_guard.exe 2>nul')
    except Exception:
        pass

    remove_shortcuts()
    unregister_uninstaller()

    errors = []
    try:
        if os.path.exists(INSTALL_DIR):
            shutil.rmtree(INSTALL_DIR)
    except Exception as e:
        errors.append(str(e))

    if errors:
        msgbox("卸载", f"卸载完成，但部分文件无法删除:\n\n" + "\n".join(errors[:5]), MB_ICONWARNING)
    else:
        msgbox(APP_NAME, "卸载完成！")


def main():
    request_admin()

    if is_installed():
        uninstall()
    else:
        install()


if __name__ == "__main__":
    main()