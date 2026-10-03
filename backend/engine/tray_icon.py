"""
系统托盘图标模块 —— 使用 Shell_NotifyIconW 创建托盘图标
提供右击菜单：打开/退出安盾
"""
import os
import sys
import ctypes
import ctypes.wintypes as wt
import threading
import time

IS_WINDOWS = sys.platform == 'win32'

WM_USER = 0x0400
WM_DESTROY = 0x0002

# Shell_NotifyIcon 常量
NIM_ADD = 0
NIM_DELETE = 2
NIIF_USER = 4
NIF_ICON = 0x0002
NIF_MESSAGE = 0x0001
NIF_TIP = 0x0004
NIF_SHOWTIP = 0x0080
NIM_MODIFY = 1
NIF_INFO = 0x0010
NIIF_WARNING = 0x02
NIIF_INFO = 0x01

# 鼠标消息
WM_LBUTTONUP = 0x0202
WM_RBUTTONUP = 0x0205
WM_CONTEXTMENU = 0x007B

# 弹出菜单
TPM_LEFTALIGN = 0x0000
TPM_RETURNCMD = 0x0100

user32 = None
shell32 = None


# ── 按需的托盘气泡通知（"用户没在看页面"时的兜底通道）──
_notifier = None
_notifier_lock = threading.Lock()


def notify(title: str, text: str, warning: bool = True) -> bool:
    """弹一个系统托盘气泡。首次调用会按需拉起一个常驻的隐藏托盘图标。

    浏览器后台标签页会把 setInterval 节流到约每分钟一次，网页里的右下角
    弹窗在 15 秒决策窗口内可能来不及出现；托盘气泡不受浏览器限制。
    """
    global _notifier
    if not IS_WINDOWS:
        return False
    try:
        with _notifier_lock:
            if _notifier is None:
                t = TrayIcon()
                t.start()
                for _ in range(60):          # 等窗口创建好，最多约 3 秒
                    if getattr(t, "_hwnd", None):
                        break
                    time.sleep(0.05)
                _notifier = t
            return _notifier.notify(title, text, warning)
    except Exception:
        return False


if IS_WINDOWS:
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    shell32 = ctypes.WinDLL('shell32', use_last_error=True)

    # Shell_NotifyIconW
    shell32.Shell_NotifyIconW.argtypes = [wt.DWORD, wt.LPVOID]
    shell32.Shell_NotifyIconW.restype = wt.BOOL

    # CreatePopupMenu
    user32.CreatePopupMenu.restype = wt.HANDLE
    user32.AppendMenuW.argtypes = [wt.HANDLE, wt.UINT, wt.UINT, wt.LPCWSTR]
    user32.AppendMenuW.restype = wt.BOOL
    user32.TrackPopupMenu.argtypes = [wt.HANDLE, wt.UINT, wt.INT, wt.INT, wt.INT, wt.HANDLE, wt.LPVOID]
    user32.TrackPopupMenu.restype = wt.BOOL
    user32.DestroyMenu.argtypes = [wt.HANDLE]
    user32.DestroyMenu.restype = wt.BOOL

    # LoadImageW (for icon)
    user32.LoadImageW.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.UINT, wt.INT, wt.INT, wt.UINT]
    user32.LoadImageW.restype = wt.HANDLE
    IMAGE_ICON = 1
    LR_LOADFROMFILE = 0x0010


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD),
        ("hWnd", wt.HANDLE),
        ("uID", wt.UINT),
        ("uFlags", wt.UINT),
        ("uCallbackMessage", wt.UINT),
        ("hIcon", wt.HANDLE),
        ("szTip", ctypes.c_wchar * 128),
        ("dwState", wt.DWORD),
        ("dwStateMask", wt.DWORD),
        ("szInfo", ctypes.c_wchar * 256),
        ("uVersion", wt.UINT),
        ("szInfoTitle", ctypes.c_wchar * 64),
        ("dwInfoFlags", wt.DWORD),
        ("guidItem", ctypes.c_byte * 16),
        ("hBalloonIcon", wt.HANDLE),
    ]


class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", wt.HANDLE),
        ("message", wt.UINT),
        ("wParam", wt.WPARAM),
        ("lParam", wt.LPARAM),
        ("time", wt.DWORD),
        ("pt", ctypes.wintypes.POINT),
    ]


class TrayIcon:
    """系统托盘图标"""

    def __init__(self):
        self._running = False
        self._thread: threading.Thread | None = None
        self._hwnd = None
        self._icon_handle = None
        self._on_show = None
        self._on_exit = None

    def set_callbacks(self, on_show=None, on_exit=None):
        """设置回调：on_show 打开窗口, on_exit 退出程序"""
        self._on_show = on_show
        self._on_exit = on_exit

    def start(self):
        if not IS_WINDOWS or self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._tray_loop, daemon=True, name="TrayIcon")
        self._thread.start()

    def stop(self):
        self._running = False
        if self._hwnd:
            user32.PostMessageW(self._hwnd, WM_DESTROY, 0, 0)

    def _tray_loop(self):
        """创建隐藏窗口 + 托盘图标 + 消息循环"""
        try:
            # 注册窗口类
            hinstance = user32.GetModuleHandleW(None)
            class_name = "AndunTrayClass"
            wc = ctypes.create_unicode_buffer(256)
            wc.value = class_name

            WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_long, wt.HANDLE, wt.UINT, wt.WPARAM, wt.LPARAM)

            def wnd_proc(hwnd, msg, wparam, lparam):
                if msg == WM_USER + 1:
                    return self._handle_tray_msg(hwnd, wparam, lparam)
                if msg == WM_DESTROY:
                    user32.PostQuitMessage(0)
                    return 0
                return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

            wc_proc = WNDPROC(wnd_proc)

            class WNDCLASS(ctypes.Structure):
                _fields_ = [
                    ("style", wt.UINT),
                    ("lpfnWndProc", ctypes.c_void_p),
                    ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", wt.HANDLE),
                    ("hIcon", wt.HANDLE),
                    ("hCursor", wt.HANDLE),
                    ("hbrBackground", wt.HANDLE),
                    ("lpszMenuName", wt.LPCWSTR),
                    ("lpszClassName", wt.LPCWSTR),
                ]

            wc_struct = WNDCLASS()
            wc_struct.style = 0
            wc_struct.lpfnWndProc = ctypes.cast(wc_proc, ctypes.c_void_p)
            wc_struct.cbClsExtra = 0
            wc_struct.cbWndExtra = 0
            wc_struct.hInstance = hinstance
            wc_struct.hIcon = 0
            wc_struct.hCursor = 0
            wc_struct.hbrBackground = 0
            wc_struct.lpszMenuName = None
            wc_struct.lpszClassName = class_name

            user32.RegisterClassW(ctypes.byref(wc_struct))

            self._hwnd = user32.CreateWindowExW(
                0, class_name, "AndunTray", 0,
                0, 0, 0, 0, 0, None, hinstance, None
            )
            if not self._hwnd:
                return

            # 加载图标
            base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            icon_path = os.path.join(base, "御天图标.ico")
            if not os.path.isfile(icon_path):
                icon_path = os.path.join(base, "御天图标.ico")
            if os.path.isfile(icon_path):
                self._icon_handle = user32.LoadImageW(
                    0, icon_path, IMAGE_ICON, 32, 32, LR_LOADFROMFILE
                )

            # 创建 NOTIFYICONDATA
            nid = NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
            nid.hWnd = self._hwnd
            nid.uID = 1
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP
            nid.uCallbackMessage = WM_USER + 1
            nid.hIcon = self._icon_handle or user32.LoadIconW(0, 32512)  # IDI_APPLICATION
            nid.szTip = "御天 安全中心"

            shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))

            # 消息循环
            msg = MSG()
            ret = ctypes.c_int(0)
            while self._running:
                r = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if r <= 0:
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))

            # 清理
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
            if self._icon_handle:
                user32.DestroyIcon(self._icon_handle)
            user32.DestroyWindow(self._hwnd)
            user32.UnregisterClassW(class_name, hinstance)

        except Exception:
            pass

    def notify(self, title: str, text: str, warning: bool = True) -> bool:
        """弹一个系统托盘气泡（图标已存在时用 NIM_MODIFY + NIF_INFO）。

        为什么需要它：浏览器后台标签页会把 setInterval 节流到约每分钟一次，
        网页里的右下角弹窗在 15 秒决策窗口内可能来不及出现；
        托盘气泡不受浏览器限制，是"用户没在看页面"时的兜底通道。
        """
        if not IS_WINDOWS or not getattr(self, "_hwnd", None):
            return False
        try:
            nid = NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
            nid.hWnd = self._hwnd
            nid.uID = 1
            nid.uFlags = NIF_INFO
            nid.szInfo = (text or "")[:255]
            nid.szInfoTitle = (title or "")[:63]
            nid.dwInfoFlags = NIIF_WARNING if warning else NIIF_INFO
            return bool(shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid)))
        except Exception:
            return False

    def _handle_tray_msg(self, hwnd, wparam, lparam):
        """处理托盘图标的鼠标/菜单事件"""
        if lparam == WM_LBUTTONUP:
            # 左键单击 → 打开窗口
            if self._on_show:
                self._on_show()
        elif lparam == WM_RBUTTONUP or lparam == WM_CONTEXTMENU:
            # 右键 → 弹出菜单
            pt = ctypes.wintypes.POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            hmenu = user32.CreatePopupMenu()
            if hmenu:
                MF_STRING = 0
                user32.AppendMenuW(hmenu, MF_STRING, 1, "打开 安盾")
                user32.AppendMenuW(hmenu, MF_STRING, 2, "退出")
                cmd = user32.TrackPopupMenu(hmenu, TPM_RETURNCMD | TPM_LEFTALIGN,
                                             pt.x, pt.y, 0, hwnd, None)
                user32.DestroyMenu(hmenu)
                if cmd == 1 and self._on_show:
                    self._on_show()
                elif cmd == 2 and self._on_exit:
                    self._on_exit()
        return 0
