# -*- coding: utf-8 -*-
"""御天安全卫士 · 安装程序
功能：
  1. 从官网下载 御天.zip（http://shadu.zh.kg/downloads/yutian.zip），
     若安装程序旁已有 御天.zip 则直接使用（离线/测试方便）。
  2. 用户自选安装目录（文件夹选择对话框）。
  3. 下载 / 解压全程显示进度条。
  4. 解压 → 创建注册表 / 快捷方式 → 启动主程序。
"""
import os
import sys
import zipfile
import ctypes
import shutil
import tempfile
import subprocess
import urllib.request
import urllib.error

from ctypes import wintypes
from installer_common import (
    APP_NAME, APP_EXE, UNINSTALLER_EXE,
    is_admin, elevate_self, msgbox,
    write_uninstall_registry, write_run_registry,
    create_desktop_shortcut, create_startmenu_shortcut,
)

DEFAULT_INSTALL_DIR = r"C:\Program Files\御天安全卫士"
ZIP_URL = "http://shadu.zh.kg/downloads/yutian.zip"
ZIP_FILENAME = "yutian.zip"


# ======================================================================
# Win32 极简进度窗口（无第三方依赖，纯 ctypes）
# ======================================================================
user32 = ctypes.windll.user32
_WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_long, wintypes.HWND, wintypes.UINT,
                              wintypes.WPARAM, wintypes.LPARAM)
PROGRESS_CLASS = "msctls_progress32"
_WS_CAPTION = 0x00C00000          # 标题栏
_WS_SYSMENU = 0x00080000          # 系统菜单
_WS_POPUP = 0x80000000            # 弹出窗口
_WS_CHILD = 0x40000000
_WS_VISIBLE = 0x10000000
_PBM_SETRANGE32 = 0x0406
_PBM_SETPOS = 0x0402
_PBM_SETSTATE = 0x0410
_PBST_NORMAL = 0x0001


class WNDCLASSW(ctypes.Structure):
    """Windows 窗口类结构（ctypes.wintypes 未内置，需自行定义）"""
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", _WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


# 句柄相关函数明确 64 位返回类型，避免句柄被截断
user32.LoadCursorW.restype = wintypes.HANDLE
user32.GetSysColorBrush.restype = wintypes.HBRUSH
user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT,
                                  wintypes.WPARAM, wintypes.LPARAM]
user32.DefWindowProcW.restype = ctypes.c_long


class WinProgress(object):
    """极简进度窗口：创建窗口 + 进度条，set() 更新进度"""

    def __init__(self, title=APP_NAME):
        self.hwnd = None
        self.hbar = None
        self._wndproc = _WNDPROC(self._wnd_proc)
        self._title = title

    @staticmethod
    def _wnd_proc(hwnd, msg, wparam, lparam):
        if msg == 0x0010:  # WM_CLOSE -> 走默认销毁
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def show(self, text=""):
        """显示窗口，total 为进度最大值"""
        hinst = ctypes.windll.kernel32.GetModuleHandleW(None)
        clsname = "YutianProgressWnd"
        wc = WNDCLASSW()
        wc.lpfnWndProc = self._wndproc
        wc.hInstance = hinst
        wc.lpszClassName = clsname
        wc.hCursor = user32.LoadCursorW(None, 32512)  # IDC_ARROW
        wc.hbrBackground = user32.GetSysColorBrush(15)  # COLOR_3DFACE
        user32.RegisterClassW(ctypes.byref(wc))

        sw = user32.GetSystemMetrics(0)   # 屏幕宽
        sh = user32.GetSystemMetrics(1)   # 屏幕高
        w, h = 480, 120
        x, y = (sw - w) // 2, (sh - h) // 2
        style = _WS_CAPTION | _WS_SYSMENU | _WS_POPUP
        self.hwnd = user32.CreateWindowExW(
            0, clsname, self._title, style,
            x, y, w, h, None, None, hinst, None)
        self.hbar = user32.CreateWindowExW(
            0, PROGRESS_CLASS, "", _WS_CHILD | _WS_VISIBLE,
            20, 55, 440, 26, self.hwnd, None, hinst, None)
        # 静态文本（用于显示阶段说明，如“正在下载/正在解压”）
        self.hlabel = user32.CreateWindowExW(
            0, "STATIC", text, _WS_CHILD | _WS_VISIBLE,
            20, 22, 440, 24, self.hwnd, None, hinst, None)
        user32.ShowWindow(self.hwnd, 5)   # SW_SHOW
        user32.UpdateWindow(self.hwnd)
        self.set_range(0, 100)
        self.set(0)
        self._pump()

    def set_range(self, low, high):
        if self.hbar:
            user32.SendMessageW(self.hbar, _PBM_SETRANGE32, low, high)

    def set(self, value):
        """更新进度（当前值）"""
        if self.hbar:
            user32.SendMessageW(self.hbar, _PBM_SETPOS, value, 0)
        self._pump()

    def set_text(self, text):
        if self.hlabel:
            user32.SetWindowTextW(self.hlabel, text)
            self._pump()

    def _pump(self):
        """抽取并派发消息，保证窗口及时刷新、可响应关闭"""
        msg = wintypes.MSG()
        while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    def close(self):
        if self.hwnd:
            user32.DestroyWindow(self.hwnd)
            self._pump()
            self.hwnd = None
            self.hbar = None


# ======================================================================
# 文件夹选择对话框（SHBrowseForFolder，纯 ctypes）
# ======================================================================
def browse_for_folder(title, initial):
    """弹出文件夹选择对话框，返回所选路径；取消返回 None"""
    shell32 = ctypes.windll.shell32
    ole32 = ctypes.windll.ole32
    # 关键：明确 64 位指针返回类型，避免 PIDL 指针被截断
    shell32.SHBrowseForFolderW.restype = ctypes.c_void_p
    shell32.SHGetPathFromIDListW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR]
    shell32.SHGetPathFromIDListW.restype = wintypes.BOOL
    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    BIF_RETURNONLYFSDIRS = 0x00000001
    BIF_NEWDIALOGSTYLE = 0x00000040

    class BROWSEINFO(ctypes.Structure):
        _fields_ = [
            ("hwndOwner", wintypes.HWND),
            ("pidlRoot", ctypes.c_void_p),
            ("pszDisplayName", wintypes.LPWSTR),
            ("lpszTitle", wintypes.LPCWSTR),
            ("ulFlags", wintypes.UINT),
            ("lpfn", ctypes.c_void_p),
            ("lParam", ctypes.c_void_p),
            ("iImage", ctypes.c_int),
        ]

    display = ctypes.create_unicode_buffer(260)
    bi = BROWSEINFO()
    bi.hwndOwner = None
    bi.pszDisplayName = ctypes.cast(display, ctypes.c_wchar_p)
    bi.lpszTitle = title
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE
    pidl = shell32.SHBrowseForFolderW(ctypes.byref(bi))
    if not pidl:
        return None
    buf = ctypes.create_unicode_buffer(260)
    if not shell32.SHGetPathFromIDListW(pidl, buf):
        ole32.CoTaskMemFree(pidl)
        return None
    ole32.CoTaskMemFree(pidl)
    path = buf.value.strip()
    return path or None


# ======================================================================
# 网络下载 / 解压（带进度）
# ======================================================================
def download_file(url, dest, progress=None):
    """下载文件到 dest，实时更新进度"""
    req = urllib.request.Request(
        url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "YutianInstaller/1.0",
            "Accept": "*/*",
        })
    resp = urllib.request.urlopen(req, timeout=60)
    total = int(resp.headers.get("Content-Length", 0) or 0)
    if progress:
        progress.set_range(0, total or 100)
    tmp = dest + ".part"
    done = 0
    try:
        with open(tmp, "wb") as f:
            while True:
                chunk = resp.read(1024 * 256)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if progress:
                    progress.set(done)
    finally:
        try:
            resp.close()
        except Exception:
            pass
    if total and done < total:
        raise RuntimeError("下载不完整：预期 %d 字节，实际 %d 字节" % (total, done))
    os.replace(tmp, dest)


def extract_zip(zip_path, target_dir, progress=None):
    """解压 zip 到目标目录，按文件数更新进度"""
    os.makedirs(target_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        bad = zf.testzip()
        if bad:
            raise RuntimeError("压缩包损坏，首个坏文件：%s" % bad)
        names = zf.namelist()
        total = len(names)
        if progress:
            progress.set_range(0, total)
        for i, name in enumerate(names, 1):
            zf.extract(name, target_dir)
            if progress:
                progress.set(i)
    return total


# ======================================================================
# 安装流程
# ======================================================================
def get_local_zip():
    """安装程序旁若有 御天.zip / yutian.zip 则直接使用（离线优先）"""
    base = os.path.dirname(os.path.abspath(sys.executable))
    for name in ("御天.zip", ZIP_FILENAME):
        p = os.path.join(base, name)
        if os.path.isfile(p):
            return p
    return None


def resolve_zip(progress):
    """确定安装包来源：优先本地，其次官网下载"""
    local = get_local_zip()
    if local:
        return local, False  # (路径, 是否来自网络)
    # 下载到临时目录
    dest = os.path.join(tempfile.gettempdir(), ZIP_FILENAME)
    progress.set_text("正在从官网下载安装包…")
    try:
        download_file(ZIP_URL, dest, progress)
    except urllib.error.HTTPError as e:
        raise RuntimeError("下载失败（HTTP %s）：%s" % (e.code, ZIP_URL))
    except Exception as e:
        raise RuntimeError("下载失败：%s\n地址：%s" % (e, ZIP_URL))
    return dest, True


def deploy_uninstaller(install_dir):
    """将内嵌的 删除程序.exe 部署到安装目录"""
    src = os.path.join(getattr(sys, "_MEIPASS",
                               os.path.dirname(os.path.abspath(sys.executable))),
                       UNINSTALLER_EXE)
    if os.path.isfile(src):
        shutil.copy2(src, os.path.join(install_dir, UNINSTALLER_EXE))


def launch_main(install_dir):
    """安装完成后启动御天主程序"""
    main_exe = os.path.join(install_dir, APP_EXE)
    if os.path.isfile(main_exe):
        try:
            subprocess.Popen([main_exe], cwd=install_dir)
        except Exception:
            pass


def get_installed_version(install_dir):
    """从已安装目录读取版本号，用于判断覆盖安装"""
    for d in (install_dir, os.path.join(install_dir, "_internal")):
        vp = os.path.join(d, "version.py")
        if os.path.isfile(vp):
            try:
                ns = {}
                exec(compile(open(vp, encoding="utf-8").read(), vp, "exec"), ns)
                return ns.get("__version__", "")
            except Exception:
                pass
    return ""


def main():
    # ---------- 管理员检查 ----------
    if not is_admin():
        msgbox("安装 御天安全卫士 需要管理员权限。\n请确认 UAC 弹窗，以管理员身份运行安装程序。",
               APP_NAME, 0x40)
        if elevate_self():
            sys.exit(0)
        else:
            msgbox("获取管理员权限失败，无法继续安装。", APP_NAME, 0x10)
            return 1

    # ---------- 确定安装目录 ----------
    from installer_common import get_install_location
    target = DEFAULT_INSTALL_DIR
    existing = get_install_location()
    if existing and os.path.isdir(existing):
        old_ver = get_installed_version(existing)
        ret = ctypes.windll.user32.MessageBoxW(
            None,
            "检测到已安装 御天安全卫士。\n"
            "当前路径：%s\n旧版本：%s\n\n"
            "是否覆盖安装？\n"
            "（选「是」覆盖到原路径，选「否」重新选择安装位置）" % (existing, old_ver or "未知"),
            APP_NAME, 0x24)  # MB_YESNO | MB_ICONQUESTION
        if ret == 6:  # IDYES
            target = existing
        else:
            picked = browse_for_folder("请选择 御天安全卫士 的安装文件夹", DEFAULT_INSTALL_DIR)
            if picked:
                target = picked
    else:
        # 首次安装：让用户自选目录，取消则用默认
        picked = browse_for_folder("请选择 御天安全卫士 的安装文件夹", DEFAULT_INSTALL_DIR)
        if picked:
            target = picked

    ret = ctypes.windll.user32.MessageBoxW(
        None,
        "欢迎安装 御天安全卫士！\n\n"
        "安装目录：%s\n"
        "安装包来源：官网自动下载\n"
        "功能：病毒查杀 · APK 检测 · 无文件攻击防护 · 防火墙\n\n"
        "是否开始安装？" % target,
        APP_NAME, 0x24)  # MB_YESNO | MB_ICONQUESTION
    if ret != 6:  # IDYES
        return 0

    # ---------- 进度窗口 ----------
    prog = WinProgress()
    prog.show("准备安装…")

    try:
        # 1. 获取安装包（本地或官网下载）
        zip_path, from_net = resolve_zip(prog)
        zip_size = os.path.getsize(zip_path) / 1048576

        # 2. 解压（先清理旧目录）
        prog.set_text("正在解压安装包…")
        if os.path.isdir(target):
            try:
                shutil.rmtree(target, ignore_errors=True)
            except Exception:
                pass
        file_count = extract_zip(zip_path, target, prog)

        # 3. 部署删除程序
        deploy_uninstaller(target)
    except Exception as e:
        prog.close()
        msgbox("安装失败：\n%s" % e, APP_NAME, 0x10)
        return 1

    # 4. 注册表
    try:
        write_uninstall_registry(target)
        write_run_registry(target)
    except Exception as e:
        msgbox("写入注册表信息失败（部分功能可能不可用）：\n%s" % e, APP_NAME, 0x30)

    # 5. 快捷方式
    main_path = os.path.join(target, APP_EXE)
    try:
        create_startmenu_shortcut(main_path)
        create_desktop_shortcut(main_path)
    except Exception:
        pass

    # 6. 完成
    prog.set_text("安装完成")
    prog.set(100)
    prog.close()
    src_note = "官网下载（%.1f MB）" % zip_size if from_net else "本地安装包"
    ret = ctypes.windll.user32.MessageBoxW(
        None,
        "御天安全卫士 安装完成！\n\n"
        "文件数：%d | 安装来源：%s\n路径：%s\n\n"
        "是否立即启动程序？" % (file_count, src_note, target),
        APP_NAME, 0x24)  # MB_YESNO | MB_ICONQUESTION
    if ret == 6:  # IDYES
        launch_main(target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
