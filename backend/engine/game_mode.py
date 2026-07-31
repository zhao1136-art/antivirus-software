"""
游戏模式模块
检测全屏游戏进程 → 降低扫描优先级、暂停非关键保护、抑制弹窗
"""
import sys
import time
import threading
import ctypes
import ctypes.wintypes as wt
from typing import Optional, Callable

user32 = ctypes.windll.user32 if sys.platform == "win32" else None
kernel32 = ctypes.windll.kernel32 if sys.platform == "win32" else None


class GameMode:
    """游戏模式检测器"""

    # 已知游戏进程名（小写）— 避免误将普通全屏窗口当游戏
    GAME_PROCESS_KEYWORDS = [
        "game", "play", "unity", "ue4", "ue5", "unreal", "steam", "epic",
        "origin", "battle", "cod", "wow", "lol", "dota", "csgo", "cs2",
        "valorant", "overwatch", "apex", "fortnite", "minecraft", "gta",
        "cyberpunk", "witcher", "diablo", "star", "warframe", "destiny",
        "borderlands", "elder", "scroll", "fallout", "red dead", "rdr2",
        "final fantasy", "ffxiv", "monster hunt", "rainbow", "siege",
        "assassin", "creed", "far cry", "watch dog", "dark soul", "elden",
        "resident evil", "devil may cry", "metal gear", "death stranding",
        "ghost recon", "the division", "tom clancy", "nba", "fifa", "pes",
        "madden", "wwe", "need for speed", "forza", "horizon", "flight sim",
        "xbox", "ps remote", "nvidia", "geforce",
    ]

    def __init__(self):
        self._running = False
        self._in_game = False
        self._thread: Optional[threading.Thread] = None
        self._on_game_start: Optional[Callable] = None
        self._on_game_end: Optional[Callable] = None
        self._poll_interval = 2  # 轮询间隔秒
        self._last_game_window = ""

    def set_callbacks(self, on_game_start=None, on_game_end=None):
        """设置游戏开始/结束回调"""
        self._on_game_start = on_game_start
        self._on_game_end = on_game_end

    @property
    def in_game(self) -> bool:
        return self._in_game

    def start(self):
        if not user32 or self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="GameMode")
        self._thread.start()

    def stop(self):
        self._running = False

    def _is_fullscreen(self, hwnd) -> bool:
        """检测窗口是否全屏"""
        if not hwnd:
            return False

        # 获取窗口矩形
        rect = ctypes.wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        win_w = rect.right - rect.left
        win_h = rect.bottom - rect.top

        # 获取屏幕尺寸
        screen_w = user32.GetSystemMetrics(0)  # SM_CXSCREEN
        screen_h = user32.GetSystemMetrics(1)  # SM_CYSCREEN

        # 全屏判定：窗口大小匹配屏幕
        return (win_w >= screen_w and win_h >= screen_h) or \
               (win_w >= screen_w - 10 and win_h >= screen_h - 10)

    def _get_foreground_process_name(self) -> str:
        """获取前台窗口的进程名"""
        try:
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return ""

            pid = ctypes.wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

            hProc = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
            if not hProc:
                return ""
            try:
                buf = ctypes.create_unicode_buffer(260)
                size = ctypes.wintypes.DWORD(260)
                ctypes.windll.psapi.GetModuleBaseNameW(hProc, None, buf, size)
                proc_name = buf.value.lower()
            finally:
                kernel32.CloseHandle(hProc)
            return proc_name
        except Exception:
            return ""

    def _is_game_process(self, proc_name: str) -> bool:
        """根据进程名判断是否为游戏"""
        if not proc_name:
            return False
        pn = proc_name.lower().replace(".exe", "")
        for kw in self.GAME_PROCESS_KEYWORDS:
            if kw in pn:
                return True
        return False

    def check_now(self) -> dict:
        """单次检测当前是否为游戏模式"""
        if not user32:
            return {"in_game": False, "error": "not supported"}

        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return {"in_game": False}

        fullscreen = self._is_fullscreen(hwnd)
        proc_name = self._get_foreground_process_name()
        is_game = self._is_game_process(proc_name)

        # 窗口标题
        title_buf = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(hwnd, title_buf, 256)
        title = title_buf.value or ""

        in_game = fullscreen and (is_game or proc_name)
        # 如果全屏且无法判断进程名，保守视为非游戏
        if fullscreen and not is_game and proc_name:
            # 无游戏关键词但全屏 → 可能是视频播放器或其他
            in_game = False

        return {
            "in_game": in_game,
            "fullscreen": fullscreen,
            "process": proc_name,
            "title": title,
            "window": title,
        }

    def _monitor_loop(self):
        """后台监控循环"""
        while self._running:
            try:
                status = self.check_now()
                was_in_game = self._in_game
                self._in_game = status.get("in_game", False)

                if self._in_game and not was_in_game:
                    # 进入游戏模式
                    window = status.get("window", "")
                    print(f"[GameMode] 进入游戏模式: {window}")
                    if self._on_game_start:
                        self._on_game_start(window)
                    self._last_game_window = window

                elif not self._in_game and was_in_game:
                    # 退出游戏模式
                    print(f"[GameMode] 退出游戏模式")
                    if self._on_game_end:
                        self._on_game_end()
                    self._last_game_window = ""

                time.sleep(self._poll_interval)
            except Exception:
                time.sleep(self._poll_interval)


# 单例
_game_mode: Optional[GameMode] = None


def get_game_mode() -> GameMode:
    global _game_mode
    if _game_mode is None:
        _game_mode = GameMode()
    return _game_mode
