"""
御天 弹窗广告拦截模块

拦截软件弹窗和浏览器恶意广告弹窗。
"""
import os
import sys
import time
import json
import threading
import subprocess
import ctypes
from ctypes import wintypes
from datetime import datetime
from collections import defaultdict

IS_WINDOWS = sys.platform == 'win32'

DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data"
)
LOG_FILE = os.path.join(DATA_DIR, "logs", "adblock.log")

# 已知弹窗广告窗口类名/标题黑名单（部分）
KNOWN_AD_CLASSES = [
    "Internet Explorer_TridentMgdBtn",  # 旧版 IE 弹窗
    "TXGuiFoundation",                  # 腾讯系弹窗
    "Qt5QWindowIcon",                   # Qt 弹窗
    "Chrome_WidgetWin_0",               # Chrome 弹窗（需过滤）
    "Chrome_WidgetWin_1",
    "#32770",                           # 对话框
    "browser_ad_window",
    "AdPopup",
    "PopupWindow",
]

KNOWN_AD_TITLES = [
    "广告", "推广", "弹窗", "活动", "优惠", "推荐",
    "ad", "ads", "popup", "advertisement", "sponsor",
    "推广", "热点", "资讯推荐", "今日推荐",
]

# 已知弹窗进程名黑名单
KNOWN_AD_PROCESSES = [
    "adpopup.exe", "adshow.exe", "popup.exe",
    "softad.exe", "adbox.exe", "adservice.exe",
]


class AdBlock:
    """弹窗广告拦截"""

    def __init__(self):
        self._enabled = False
        self._running = False
        self._stop_event = threading.Event()
        self._blocked_count = 0
        self._blocked_history: list[dict] = []
        self._lock = threading.Lock()
        self._whitelist: set[str] = set()  # 白名单进程
        self._strict_mode = False
        os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)

    def _log(self, msg: str):
        t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{t}] {msg}\n")
        except Exception:
            pass

    def enable(self):
        if self._enabled:
            return
        self._enabled = True
        self._log("弹窗拦截已启用")
        if not self._running:
            self._start()

    def disable(self):
        self._enabled = False
        self._log("弹窗拦截已禁用")

    def _start(self):
        self._running = True
        self._stop_event.clear()
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()

    def stop(self):
        self._enabled = False
        self._stop_event.set()
        self._running = False

    def _monitor_loop(self):
        """轮询检测并关闭弹窗"""
        if not IS_WINDOWS:
            return
        try:
            user32 = ctypes.windll.user32
            enum_windows = user32.EnumWindows
            get_window_text = user32.GetWindowTextW
            get_window_text_length = user32.GetWindowTextLengthW
            get_class_name = user32.GetClassNameW
            is_window_visible = user32.IsWindowVisible
            send_message = user32.SendMessageW
            WM_CLOSE = 0x0010

            # 回调函数
            EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
            results = []

            def callback(hwnd, lparam):
                if not is_window_visible(hwnd):
                    return True
                length = get_window_text_length(hwnd)
                buf = ctypes.create_unicode_buffer(length + 1)
                get_window_text(hwnd, buf, length + 1)
                title = buf.value.strip()
                if not title:
                    return True
                cls_buf = ctypes.create_unicode_buffer(256)
                get_class_name(hwnd, cls_buf, 256)
                class_name = cls_buf.value

                # 检查是否在黑名单中
                matched = False
                reason = ""
                for ad_cls in KNOWN_AD_CLASSES:
                    if ad_cls.lower() in class_name.lower():
                        matched = True
                        reason = f"窗口类名匹配: {class_name}"
                        break
                if not matched:
                    for ad_title in KNOWN_AD_TITLES:
                        if ad_title in title.lower():
                            matched = True
                            reason = f"标题匹配: {title}"
                            break

                if matched:
                    results.append((hwnd, title, class_name, reason))
                return True

            while not self._stop_event.is_set():
                if not self._enabled:
                    self._stop_event.wait(1)
                    continue
                try:
                    results.clear()
                    enum_windows(EnumWindowsProc(callback), 0)
                    for hwnd, title, class_name, reason in results:
                        try:
                            send_message(hwnd, WM_CLOSE, 0, 0)
                            with self._lock:
                                self._blocked_count += 1
                                self._blocked_history.insert(0, {
                                    "time": datetime.now().isoformat(),
                                    "title": title,
                                    "class": class_name,
                                    "reason": reason
                                })
                                if len(self._blocked_history) > 100:
                                    self._blocked_history = self._blocked_history[:100]
                            self._log(f"拦截弹窗: {title} ({reason})")
                        except Exception:
                            pass
                except Exception:
                    pass
                self._stop_event.wait(3)  # 每 3 秒扫描一次
        except Exception:
            pass

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self._enabled,
                "blocked_count": self._blocked_count,
                "history": list(self._blocked_history[:20]),
                "strict_mode": self._strict_mode
            }

    def set_strict_mode(self, enabled: bool):
        self._strict_mode = enabled
        if enabled:
            # 严格模式下增加更多检测规则
            KNOWN_AD_CLASSES.extend(["DirectUIHWND", "AfxWnd42", "MozillaDialogClass"])
        self._log(f"弹窗拦截严格模式: {'开启' if enabled else '关闭'}")

    def get_status(self) -> dict:
        return {
            "enabled": self._enabled,
            "running": self._running,
            "blocked_total": self._blocked_count,
            "strict_mode": self._strict_mode
        }