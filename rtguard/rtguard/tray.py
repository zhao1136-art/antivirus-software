"""托盘图标（纯 ctypes，无第三方依赖，无外部 .ico）。

设计要点：

* 只使用 ``shell32.Shell_NotifyIconW`` + ``user32`` 的窗口类注册 / 消息循环；
  ``NOTIFYICONDATAW`` 的 ``cbSize`` 用 ``ctypes.sizeof`` 计算（64 位下 976 字节），
  不写死魔数。
* 消息循环跑在 daemon 线程里；``start()`` 失败（无桌面会话、Shell_NotifyIconW
  返回 0 等）一律捕获并返回 False，**不抛异常、不阻塞**。
* **避免 GIL 死锁**：窗口过程（WNDPROC）运行在 Win32 回调上下文里，
  里面只在 ``HWND_MESSAGE`` 这种轻量窗口上做 ``PostMessageW``，把工作交回
  消息循环线程；Python 回调（``on_open`` / ``on_quit``）只在消息循环里调用，
  且调用回调时不再持有任何阻塞的 Win32 调用。
"""

from __future__ import annotations

import ctypes
import sys
import threading
from ctypes import wintypes

__all__ = ["TrayIcon"]

# --------------------------------------------------------------------- 常量

WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_COMMAND = 0x0111
WM_RBUTTONUP = 0x0205
WM_LBUTTONDBLCLK = 0x0203
WM_CONTEXTMENU = 0x007B

WM_APP = 0x8000
WM_TRAY_CALLBACK = WM_APP + 1  # uCallbackMessage
WM_TRAY_SHOW_MENU = WM_APP + 2  # 请求弹菜单—投递到消息循环
WM_TRAY_OPEN = WM_APP + 3  # 请求「打开」—投递到消息循环
WM_TRAY_QUIT_LOOP = WM_APP + 4  # 请求「退出」/结束消息循环

NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIM_SETVERSION = 0x00000004

NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
NIF_STATE = 0x00000008
NIF_INFO = 0x00000010

NIIF_INFO = 0x00000001
NIIF_NOSOUND = 0x00000010

MF_STRING = 0x00000000
MF_SEPARATOR = 0x00000800
TPM_RIGHTBUTTON = 0x0002
TPM_RETURNCMD = 0x0100

IDI_APPLICATION = 32512
IDI_SHIELD = 32517

ID_MENU_OPEN = 1001
ID_MENU_QUIT = 1002

_HWND_MESSAGE = -3
_SZ_TIP = 128
_SZ_INFO = 256
_SZ_INFO_TITLE = 64

_IS_WINDOWS = sys.platform == "win32"


# --------------------------------------------------------------- 结构体定义

if _IS_WINDOWS:  # pragma: no branch - 非 Windows 下整个模块只是不可用
    LRESULT = ctypes.c_ssize_t
    WPARAM = ctypes.c_size_t
    LPARAM = ctypes.c_ssize_t
    UINT_PTR = ctypes.c_size_t
    WNDPROC = ctypes.WINFUNCTYPE(
        LRESULT, wintypes.HWND, wintypes.UINT, WPARAM, LPARAM
    )

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [
            ("style", wintypes.UINT),
            ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HICON),
            ("hCursor", wintypes.HANDLE),
            ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
        ]

    class NOTIFYICONDATAW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("hWnd", wintypes.HWND),
            ("uID", wintypes.UINT),
            ("uFlags", wintypes.UINT),
            ("uCallbackMessage", wintypes.UINT),
            ("hIcon", wintypes.HICON),
            ("szTip", wintypes.WCHAR * _SZ_TIP),
            ("dwState", wintypes.DWORD),
            ("dwStateMask", wintypes.DWORD),
            ("szInfo", wintypes.WCHAR * _SZ_INFO),
            ("uVersion", wintypes.UINT),
            ("szInfoTitle", wintypes.WCHAR * _SZ_INFO_TITLE),
            ("dwInfoFlags", wintypes.DWORD),
            ("guidItem", ctypes.c_byte * 16),
            ("hBalloonIcon", wintypes.HICON),
        ]

    class MSG(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("message", wintypes.UINT),
            ("wParam", WPARAM),
            ("lParam", LPARAM),
            ("time", wintypes.DWORD),
            ("pt_x", ctypes.c_long),
            ("pt_y", ctypes.c_long),
        ]

    # ------------------------------------------------------------ 函数原型

    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)

    _RegisterClassW = _user32.RegisterClassW
    _RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
    _RegisterClassW.restype = wintypes.ATOM

    _UnregisterClassW = _user32.UnregisterClassW
    _UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
    _UnregisterClassW.restype = wintypes.BOOL

    _CreateWindowExW = _user32.CreateWindowExW
    _CreateWindowExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HMENU,
        wintypes.HINSTANCE,
        wintypes.LPVOID,
    ]
    _CreateWindowExW.restype = wintypes.HWND

    _DefWindowProcW = _user32.DefWindowProcW
    _DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
    _DefWindowProcW.restype = LRESULT

    _DestroyWindow = _user32.DestroyWindow
    _DestroyWindow.argtypes = [wintypes.HWND]
    _DestroyWindow.restype = wintypes.BOOL

    _GetMessageW = _user32.GetMessageW
    _GetMessageW.argtypes = [ctypes.POINTER(MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    _GetMessageW.restype = wintypes.BOOL

    _TranslateMessage = _user32.TranslateMessage
    _TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
    _TranslateMessage.restype = wintypes.BOOL

    _DispatchMessageW = _user32.DispatchMessageW
    _DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
    _DispatchMessageW.restype = LRESULT

    _PostMessageW = _user32.PostMessageW
    _PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, WPARAM, LPARAM]
    _PostMessageW.restype = wintypes.BOOL

    _PostQuitMessage = _user32.PostQuitMessage
    _PostQuitMessage.argtypes = [ctypes.c_int]
    _PostQuitMessage.restype = None

    _LoadIconW = _user32.LoadIconW
    _LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    _LoadIconW.restype = wintypes.HICON
    _CreatePopupMenu = _user32.CreatePopupMenu
    _CreatePopupMenu.argtypes = []
    _CreatePopupMenu.restype = wintypes.HMENU

    _AppendMenuW = _user32.AppendMenuW
    _AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, UINT_PTR, wintypes.LPCWSTR]
    _AppendMenuW.restype = wintypes.BOOL

    _DestroyMenu = _user32.DestroyMenu
    _DestroyMenu.argtypes = [wintypes.HMENU]
    _DestroyMenu.restype = wintypes.BOOL

    _TrackPopupMenu = _user32.TrackPopupMenu
    _TrackPopupMenu.argtypes = [
        wintypes.HMENU,
        wintypes.UINT,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.LPVOID,
    ]
    _TrackPopupMenu.restype = wintypes.BOOL

    _GetCursorPos = _user32.GetCursorPos
    _GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
    _GetCursorPos.restype = wintypes.BOOL

    _SetForegroundWindow = _user32.SetForegroundWindow
    _SetForegroundWindow.argtypes = [wintypes.HWND]
    _SetForegroundWindow.restype = wintypes.BOOL

    _GetModuleHandleW = _kernel32.GetModuleHandleW
    _GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _GetModuleHandleW.restype = wintypes.HMODULE

    _Shell_NotifyIconW = _shell32.Shell_NotifyIconW
    _Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
    _Shell_NotifyIconW.restype = wintypes.BOOL


def _fit(text: str, size: int) -> str:
    """按 WCHAR 数组容量截断（留一个 NUL 的位置）。"""
    if not isinstance(text, str):
        text = str(text)
    return text[: size - 1]


class TrayIcon:
    """一个托盘图标 + 隐藏消息窗口 + 后台消息循环线程。"""

    def __init__(self, title: str, tooltip: str = "", on_open=None, on_quit=None):
        self.title = title or "rtguard"
        self.tooltip = tooltip or title or "rtguard"
        self.on_open = on_open if callable(on_open) else None
        self.on_quit = on_quit if callable(on_quit) else None

        self._hwnd = None
        self._hicon = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._lock = threading.RLock()
        self._running = False
        self._started = False
        self._error: str | None = None
        self._wndproc_ref = None  # 保持 WNDPROC 回调引用，防止被 GC
        self._class_name = f"RtGuardTray_{id(self):x}"

        self._nid = NOTIFYICONDATAW() if _IS_WINDOWS else None

    # ---------------------------------------------------------------- 属性

    @property
    def hwnd(self):
        """隐藏消息窗口句柄（未启动时为 None）。"""
        return self._hwnd

    @property
    def last_error(self) -> str | None:
        """上一次失败的简述，便于日志排查。"""
        return self._error

    # ---------------------------------------------------------------- 内部

    def _ensure_icon(self):
        if self._hicon:
            return self._hicon
        # MAKEINTRESOURCEW：低位数值资源 id 通过指针值传递，配合 LPCWSTR 形参。
        for res_id in (IDI_SHIELD, IDI_APPLICATION):
            try:
                icon = _LoadIconW(None, ctypes.cast(ctypes.c_void_p(res_id), wintypes.LPCWSTR))
            except Exception:
                icon = None
            if icon:
                self._hicon = icon
                return icon
        return None

    def _fill_nid(self, flags: int):
        nid = self._nid
        ctypes.memset(ctypes.byref(nid), 0, ctypes.sizeof(nid))
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = flags
        nid.uCallbackMessage = WM_TRAY_CALLBACK
        nid.hIcon = self._hicon
        nid.szTip = _fit(self.tooltip, _SZ_TIP)
        return nid

    def _wndproc(self, hwnd, msg, wparam, lparam):
        """窗口过程：只做极轻量的 PostMessageW + DefWindowProcW。

        绝不在这里调用 Python 业务回调，避免在 Win32 回调上下文里重入 /
        持锁阻塞导致 GIL 死锁。
        """
        try:
            if msg == WM_TRAY_CALLBACK:
                event = int(lparam) & 0xFFFF
                if event in (WM_RBUTTONUP, WM_CONTEXTMENU):
                    self._post(WM_TRAY_SHOW_MENU)
                elif event == WM_LBUTTONDBLCLK:
                    self._post(WM_TRAY_OPEN)
                return 0
            if msg == WM_COMMAND:
                cmd = int(wparam) & 0xFFFF
                if cmd == ID_MENU_OPEN:
                    self._post(WM_TRAY_OPEN)
                    return 0
                if cmd == ID_MENU_QUIT:
                    self._post(WM_TRAY_QUIT_LOOP)
                    return 0
            if msg in (WM_CLOSE, WM_TRAY_QUIT_LOOP):
                self._post(WM_TRAY_QUIT_LOOP)
                _PostQuitMessage(0)
                return 0
        except Exception:
            pass
        # 返回 Python int，避免把 c_ssize_t 实例当回调返回值传递。
        return int(_DefWindowProcW(hwnd, msg, wparam, lparam))

    def _post(self, msg: int) -> None:
        try:
            if self._hwnd:
                _PostMessageW(self._hwnd, msg, 0, 0)
        except Exception:
            pass

    def _show_menu(self) -> None:
        """在光标处弹出「打开 / 退出」菜单（仅在消息循环线程调用）。"""
        try:
            menu = _CreatePopupMenu()
            if not menu:
                return
            try:
                _AppendMenuW(menu, MF_STRING, ID_MENU_OPEN, "打开(&O)")
                _AppendMenuW(menu, MF_SEPARATOR, 0, None)
                _AppendMenuW(menu, MF_STRING, ID_MENU_QUIT, "退出(&Q)")
                pt = wintypes.POINT()
                _GetCursorPos(ctypes.byref(pt))
                if self._hwnd:
                    # 让本窗口成为前台，保证弹出菜单在点击别处时会自动消失；
                    # 随后补投一条空消息（MSDN 推荐做法），仍是轻量 PostMessageW。
                    _SetForegroundWindow(self._hwnd)
                    _PostMessageW(self._hwnd, WM_TRAY_CALLBACK, 0, 0)
                _TrackPopupMenu(
                    menu,
                    TPM_RIGHTBUTTON,
                    pt.x,
                    pt.y,
                    0,
                    self._hwnd,
                    None,
                )
            finally:
                _DestroyMenu(menu)
        except Exception:
            pass

    def _invoke(self, callback) -> None:
        """在消息循环线程里安全地调用 Python 回调。"""
        if callback is None:
            return
        try:
            callback()
        except Exception:
            pass

    def _loop(self) -> None:
        hwnd = None
        registered = False
        added = False
        try:
            hinstance = _GetModuleHandleW(None)

            self._wndproc_ref = WNDPROC(self._wndproc)
            wc = WNDCLASSW()
            ctypes.memset(ctypes.byref(wc), 0, ctypes.sizeof(wc))
            wc.style = 0
            wc.lpfnWndProc = self._wndproc_ref
            wc.hInstance = hinstance
            wc.lpszClassName = self._class_name

            if not _RegisterClassW(ctypes.byref(wc)):
                err = ctypes.get_last_error()
                if err not in (0, 1410):  # 1410 = ERROR_CLASS_ALREADY_EXISTS
                    self._error = f"RegisterClassW failed (err={err})"
                    return
            registered = True

            # 消息专用窗口：不可见、不进任务栏 / Alt-Tab。
            hwnd = _CreateWindowExW(
                0,
                self._class_name,
                self.title,
                0,
                0,
                0,
                0,
                0,
                wintypes.HWND(_HWND_MESSAGE),
                None,
                hinstance,
                None,
            )
            if not hwnd:
                self._error = f"CreateWindowExW failed (err={ctypes.get_last_error()})"
                return

            self._hwnd = hwnd
            self._ensure_icon()
            if not self._hicon:
                self._error = "LoadIconW failed"
                return

            nid = self._fill_nid(NIF_MESSAGE | NIF_ICON | NIF_TIP)
            if not _Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
                self._error = (
                    f"Shell_NotifyIconW(NIM_ADD) returned 0 (err={ctypes.get_last_error()})"
                )
                return
            added = True

            self._running = True
            self._ready.set()

            msg = MSG()
            while True:
                ret = _GetMessageW(ctypes.byref(msg), None, 0, 0)
                if ret in (0, -1):  # WM_QUIT 或错误
                    break
                if msg.message == WM_TRAY_SHOW_MENU:
                    self._show_menu()
                    continue
                if msg.message == WM_TRAY_OPEN:
                    self._invoke(self.on_open)
                    continue
                if msg.message == WM_TRAY_QUIT_LOOP:
                    self._invoke(self.on_quit)
                    break
                _TranslateMessage(ctypes.byref(msg))
                _DispatchMessageW(ctypes.byref(msg))
        except Exception as exc:  # 任何异常都不能冒泡到线程外
            self._error = f"{type(exc).__name__}: {exc}"
        finally:
            self._running = False
            self._ready.set()
            try:
                if added:
                    nid = self._fill_nid(NIF_MESSAGE | NIF_ICON | NIF_TIP)
                    _Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
            except Exception:
                pass
            try:
                if hwnd:
                    _DestroyWindow(hwnd)
            except Exception:
                pass
            try:
                if registered:
                    _UnregisterClassW(self._class_name, _GetModuleHandleW(None))
            except Exception:
                pass
            self._hwnd = None

    # ---------------------------------------------------------------- 接口

    def start(self) -> bool:
        """创建托盘图标并启动消息循环线程。成功返回 True，任何失败返回 False。"""
        if not _IS_WINDOWS:
            self._error = "not a Windows platform"
            return False
        with self._lock:
            if self._started and self._running:
                return True
            try:
                self._error = None
                self._ready.clear()
                self._thread = threading.Thread(
                    target=self._loop, name="rtguard-tray", daemon=True
                )
                self._thread.start()
                self._started = True
            except Exception as exc:
                self._error = f"{type(exc).__name__}: {exc}"
                self._started = False
                return False

            # 只等「窗口/图标是否就绪」，不做任何无限等待；失败也不阻塞。
            self._ready.wait(timeout=5.0)
            ok = bool(self._running and self._hwnd)
            if not ok and self._error is None:
                self._error = "tray icon did not become ready"
            return ok

    def stop(self) -> None:
        """结束消息循环并删除托盘图标。可重复调用，不抛异常。"""
        with self._lock:
            thread = self._thread
            hwnd = self._hwnd
            self._thread = None
        if hwnd and _IS_WINDOWS:
            try:
                _PostMessageW(hwnd, WM_CLOSE, 0, 0)
            except Exception:
                pass
        if thread is not None and thread.is_alive():
            if thread is not threading.current_thread():
                try:
                    thread.join(timeout=3.0)
                except Exception:
                    pass
            if thread.is_alive():
                try:
                    _PostQuitMessage(0)
                except Exception:
                    pass
        with self._lock:
            self._started = False
            self._running = False
            self._hwnd = None

    def notify(self, title: str, text: str, timeout_ms: int = 5000) -> bool:
        """弹出气泡通知。失败返回 False，不抛异常。

        ``timeout_ms`` 在 Vista 及以后由系统通知设置决定，这里仅作参数保留；
        为了让调用方仍能表达意图，剩余时间由系统策略控制。
        """
        if not _IS_WINDOWS or not self._hwnd:
            return False
        try:
            nid = self._fill_nid(NIF_INFO | NIF_ICON)
            nid.szInfoTitle = _fit(title or self.title, _SZ_INFO_TITLE)
            nid.szInfo = _fit(text, _SZ_INFO)
            nid.dwInfoFlags = NIIF_INFO
            ok = bool(_Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid)))
            if not ok:
                self._error = (
                    f"Shell_NotifyIconW(NIM_MODIFY) returned 0 (err={ctypes.get_last_error()})"
                )
            return ok
        except Exception as exc:
            self._error = f"{type(exc).__name__}: {exc}"
            return False

    # ---------------------------------------------------------------- 其他

    def __enter__(self) -> "TrayIcon":
        self.start()
        return self

    def __exit__(self, *exc_info) -> bool:
        self.stop()
        return False

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return (
            f"<TrayIcon {self.title!r} running={self._running} "
            f"hwnd={self._hwnd} error={self._error!r}>"
        )
