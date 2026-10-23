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
MF_STRING = 0x0000
WM_NULL = 0x0000

# MessageBox（退出二次确认用）
MB_YESNO = 0x0004
MB_ICONQUESTION = 0x0020
IDYES = 6

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
    # ⚠️ AppendMenuW 的第三个参数是 **UINT_PTR**（x64 为 8 字节），不是 UINT(4 字节)。
    #    真实签名：BOOL AppendMenuW(HMENU, UINT uFlags, UINT_PTR uIDNewItem, LPCWSTR)
    #    原先声明成 wt.UINT 不符合签名。实测本机 libffi 会零扩展、id 读回来是对的，
    #    所以它没有实际发作 —— 但这属于不该留的 ABI 错配，按 UINT_PTR 写对。
    user32.AppendMenuW.argtypes = [wt.HANDLE, wt.UINT, ctypes.c_size_t, wt.LPCWSTR]
    user32.AppendMenuW.restype = wt.BOOL
    user32.TrackPopupMenu.argtypes = [wt.HANDLE, wt.UINT, wt.INT, wt.INT, wt.INT, wt.HANDLE, wt.LPVOID]
    user32.TrackPopupMenu.restype = wt.BOOL
    user32.DestroyMenu.argtypes = [wt.HANDLE]
    user32.DestroyMenu.restype = wt.BOOL

    # 托盘菜单用到的其余 API
    user32.GetCursorPos.argtypes = [ctypes.POINTER(wt.POINT)]
    user32.GetCursorPos.restype = wt.BOOL
    user32.SetForegroundWindow.argtypes = [wt.HWND]
    user32.SetForegroundWindow.restype = wt.BOOL
    user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    user32.PostMessageW.restype = wt.BOOL
    user32.MessageBoxW.argtypes = [wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.UINT]
    user32.MessageBoxW.restype = ctypes.c_int

    # LoadImageW (for icon)
    user32.LoadImageW.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.UINT, wt.INT, wt.INT, wt.UINT]
    user32.LoadImageW.restype = wt.HANDLE
    IMAGE_ICON = 1
    LR_LOADFROMFILE = 0x0010

    # ── 64 位下必须显式声明 restype/argtypes ──
    # 不声明时 ctypes 默认把返回值当 c_int(32 位)，HMODULE/HWND/LRESULT 这些
    # 64 位指针会被截断成野值：GetModuleHandleW 拿到的 hInstance 是垃圾，
    # 于是 RegisterClassW / CreateWindowExW 失败，窗口建不出来 ——
    # 表现为 TrayIcon.start() 之后 _hwnd 一直是 None。
    # GetModuleHandleW 在 kernel32 里，**不在 user32**。
    # 原先写成 user32.GetModuleHandleW(None)，那是个不存在的函数，
    # 一调用就抛 AttributeError，被 _tray_loop 的裸 except 吞掉 ——
    # 于是托盘窗口永远建不出来，_hwnd 一直是 None。
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.GetModuleHandleW.restype = wt.HMODULE
    kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]

    user32.RegisterClassW.restype = wt.ATOM
    user32.RegisterClassW.argtypes = [ctypes.c_void_p]

    user32.UnregisterClassW.restype = wt.BOOL
    user32.UnregisterClassW.argtypes = [wt.LPCWSTR, wt.HANDLE]

    user32.CreateWindowExW.restype = wt.HWND
    user32.CreateWindowExW.argtypes = [
        wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        wt.HWND, wt.HANDLE, wt.HANDLE, ctypes.c_void_p,
    ]

    user32.DefWindowProcW.restype = ctypes.c_void_p
    user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]

    user32.DestroyWindow.restype = wt.BOOL
    user32.DestroyWindow.argtypes = [wt.HWND]

    user32.PostQuitMessage.argtypes = [ctypes.c_int]

    user32.DestroyIcon.restype = wt.BOOL
    user32.DestroyIcon.argtypes = [wt.HANDLE]

    user32.LoadIconW.restype = wt.HANDLE
    user32.LoadIconW.argtypes = [wt.HANDLE, wt.LPCWSTR]


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
        self._last_error = ""
        # 菜单是否正开着：TrackPopupMenu 是模态的，期间仍可能投递 WM_USER+1，
        # 不加这道闸门会套娃弹出第二个菜单，返回值也会串台。
        self._menu_open = False

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
            hinstance = kernel32.GetModuleHandleW(None)
            class_name = "AndunTrayClass"
            wc = ctypes.create_unicode_buffer(256)
            wc.value = class_name

            WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_long, wt.HANDLE, wt.UINT, wt.WPARAM, wt.LPARAM)

            def wnd_proc(hwnd, msg, wparam, lparam):
                # WNDPROC 声明为返回 c_long，所以这里**必须**永远返回整数。
                # 之前直接 `return user32.DefWindowProcW(...)`，其 restype 是
                # c_void_p，可能得到 None -> ctypes 转换回调返回值时抛
                # TypeError: 'NoneType' object cannot be interpreted as an integer，
                # 而且是每条消息都抛一次（被忽略，但会刷满 stderr）。
                if msg == WM_USER + 1:
                    return self._handle_tray_msg(hwnd, wparam, lparam) or 0
                if msg == WM_DESTROY:
                    user32.PostQuitMessage(0)
                    return 0
                r = user32.DefWindowProcW(hwnd, msg, wparam, lparam)
                return int(r) if r else 0

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

        except Exception as exc:
            # 不要裸吞异常：托盘窗口建不出来时，这里曾经是唯一的线索来源，
            # 而 except: pass 让它彻底不可见，排查只能靠猜。
            self._last_error = "%s: %s" % (type(exc).__name__, exc)
            try:
                import logging
                logging.getLogger("yutian").warning("托盘图标初始化失败: %s", exc, exc_info=True)
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

    @staticmethod
    def _log(msg: str):
        """托盘内部留痕：出问题时日志里能直接看到，不用靠猜。"""
        try:
            print(f"[TrayIcon] {msg}", flush=True)
        except Exception:
            pass
        try:
            import logging
            logging.getLogger("yutian").info("TrayIcon %s", msg)
        except Exception:
            pass

    def _confirm_exit(self, hwnd) -> bool:
        """退出前二次确认。

        这是防"应用自己消失"的最后一道闸门：菜单里「退出」直接走
        `os._exit(0)`，一旦 TrackPopupMenu 的返回值不是预期的（或是被误触发），
        整个进程会**没有确认、没有保存**地消失。加一道询问后，任何误触发都会
        变成一次可见的弹窗，而不是静默死亡。

        取不到 MessageBox 时**保守返回 False**（不退出）—— 宁可这次退不掉，
        也不能在没确认的情况下把进程杀掉。
        """
        try:
            res = user32.MessageBoxW(
                hwnd,
                "确定要退出御天吗？\n\n退出后实时防护与后台监控会同时停止。",
                "御天 · 确认退出",
                MB_YESNO | MB_ICONQUESTION,
            )
            return res == IDYES
        except Exception as exc:
            self._log(f"退出确认对话框失败，保守起见不退出: {exc}")
            return False

    def _handle_tray_msg(self, hwnd, wparam, lparam):
        """处理托盘图标的鼠标/菜单事件。

        ⚠️ 这是全局**唯一**能把整个程序杀掉的地方（菜单「退出」→ os._exit(0)）。
        历史上后端会"自己消失"，日志里只留下托盘 on_exit 的痕迹却查不到原因，
        所以这里做了四处加固：菜单重入闸门、MSDN 要求的置前台 + WM_NULL、
        退出二次确认、以及把原始返回值写进日志。
        """
        if lparam == WM_LBUTTONUP:
            if self._on_show:
                self._on_show()
            return 0

        if lparam != WM_RBUTTONUP and lparam != WM_CONTEXTMENU:
            return 0

        # 闸门：菜单已开着就别再开一个
        if self._menu_open:
            self._log(f"菜单已打开，忽略重复的托盘消息 lparam={lparam}")
            return 0
        self._menu_open = True
        cmd = 0
        try:
            pt = ctypes.wintypes.POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            hmenu = user32.CreatePopupMenu()
            if not hmenu:
                self._log("CreatePopupMenu 失败")
                return 0
            try:
                user32.AppendMenuW(hmenu, MF_STRING, 1, "打开 安盾")
                user32.AppendMenuW(hmenu, MF_STRING, 2, "退出")
                # MSDN 明确要求：TrackPopupMenu 之前把 owner 设为前台窗口，
                # 之后再补一条 WM_NULL。缺这两步时菜单可能不消失、焦点错乱，
                # 返回值也不可靠。
                try:
                    user32.SetForegroundWindow(hwnd)
                except Exception:
                    pass
                cmd = user32.TrackPopupMenu(
                    hmenu, TPM_RETURNCMD | TPM_LEFTALIGN,
                    pt.x, pt.y, 0, hwnd, None)
                try:
                    user32.PostMessageW(hwnd, WM_NULL, 0, 0)
                except Exception:
                    pass
            finally:
                user32.DestroyMenu(hmenu)
        finally:
            self._menu_open = False

        self._log(f"托盘菜单返回 cmd={cmd} (wparam={wparam} lparam={lparam})")

        if cmd == 1 and self._on_show:
            self._on_show()
        elif cmd == 2 and self._on_exit:
            if self._confirm_exit(hwnd):
                self._log("用户确认退出")
                self._on_exit()
            else:
                self._log("退出已被取消（用户选择否，或确认框不可用）")
        return 0
