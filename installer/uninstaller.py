# -*- coding: utf-8 -*-
"""御天安全卫士 · 删除程序（卸载器）
功能：结束进程 → 删除注册表/快捷方式 → 删除安装目录。
运行方式：可从安装目录直接运行（带确认界面），也可被安装/系统以参数调用。
  --quiet     静默卸载（不弹确认，供「添加/删除程序」/安装程序调用）
  --cleanup <目录>  仅删除指定目录及自身（由主进程复制到临时目录后调用，
                   避免自删除时自身文件被占用）。
"""
import os
import sys
import time
import shutil
import ctypes
import subprocess
import tempfile

from installer_common import (
    APP_NAME, remove_registry_entries, remove_shortcuts,
    get_install_location, msgbox,
)


def kill_processes():
    """结束御天主程序进程"""
    try:
        subprocess.run(
            ["taskkill", "/F", "/IM", "御天.exe"],
            capture_output=True, creationflags=0x08000000, timeout=10)
    except Exception:
        pass


def cleanup_folder(path, retries=6):
    """尽力删除目录（含重试，等待句柄释放）"""
    if not path or not os.path.isdir(path):
        return
    for i in range(retries):
        try:
            shutil.rmtree(path, ignore_errors=True)
            if not os.path.exists(path):
                return
        except Exception:
            pass
        time.sleep(1)
    # 兜底：交给 cmd 延迟删除
    try:
        subprocess.Popen(
            'cmd /c "ping -n 3 127.0.0.1 > nul & rmdir /s /q \"{0}\""'.format(path),
            creationflags=0x08000000 | 0x00000008)  # 无窗口 + 脱离
    except Exception:
        pass


def spawn_self_to_temp(install_dir):
    """复制自身到临时目录并异步执行清理，随后退出主进程释放文件占用"""
    try:
        tmp = os.path.join(tempfile.gettempdir(), "御天_卸载_临时.exe")
        shutil.copy2(sys.executable, tmp)
        subprocess.Popen(
            [tmp, "--cleanup", install_dir],
            cwd=tempfile.gettempdir(),
            creationflags=0x08000000 | 0x00000008)  # 无窗口 + 脱离
    except Exception:
        pass


def main():
    args = sys.argv[1:]

    # 子进程模式：清理目录 + 删除自身
    if args and args[0] == "--cleanup":
        target = args[1] if len(args) > 1 else ""
        cleanup_folder(target)
        try:
            time.sleep(2)
            os.remove(sys.executable)
        except Exception:
            pass
        return 0

    # 定位安装目录
    install_dir = get_install_location()
    if not install_dir:
        # 回退：自身所在目录
        d = os.path.dirname(os.path.abspath(sys.executable))
        if os.path.isfile(os.path.join(d, "御天.exe")):
            install_dir = d

    if not install_dir:
        msgbox("未找到御天安全卫士的安装信息，无法卸载。", APP_NAME, 0x30)
        return 1

    # 确认（静默模式跳过）
    if not (args and args[0] == "--quiet"):
        ret = ctypes.windll.user32.MessageBoxW(
            None,
            "确定要卸载 御天安全卫士 吗？\n\n安装目录：%s\n\n卸载将删除程序文件与配置，且不可恢复。" % install_dir,
            "御天安全卫士 卸载", 0x34)  # MB_YESNO | MB_ICONQUESTION
        if ret != 6:  # IDYES
            return 0

    # 1. 结束进程
    kill_processes()
    time.sleep(1)

    # 2. 清理注册表与快捷方式
    remove_registry_entries()
    remove_shortcuts()

    # 3. 删除安装目录（复制自身到临时目录后执行，避免占用）
    spawn_self_to_temp(install_dir)

    # 4. 提示完成（临时目录的子进程负责删目录）
    msgbox("御天安全卫士 已卸载完成。", APP_NAME, 0x40)
    return 0


if __name__ == "__main__":
    sys.exit(main())
