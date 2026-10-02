"""
御天 Logo 启动画面 — 纯 webview 实现（无需 tkinter）
淡入动画（CSS）→ 等待引擎加载 → 淡出 → 主窗口切换
退出时：淡出动画 + 资源释放逻辑
"""
import os
import sys
import threading
import time
import base64

# ── 常量 ──
FADE_IN_MS = 600          # 淡入动画总时长（毫秒）
FADE_OUT_MS = 600         # 淡出动画总时长（毫秒）
WINDOW_W = 340
WINDOW_H = 380


def _find_icon_file():
    """查找图标文件（御天图标.ico）"""
    base = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base, "御天图标.ico"),
        os.path.join(os.path.dirname(base), "御天图标.ico"),
        os.path.join(base, "..", "御天图标.ico"),
    ]
    if getattr(sys, 'frozen', False):
        try:
            candidates.append(os.path.join(sys._MEIPASS, "御天图标.ico"))
        except Exception:
            pass
    for p in candidates:
        p = os.path.normpath(p)
        if os.path.isfile(p):
            return p
    return None


def _get_icon_data_uri():
    """读取 ico 文件并返回 data URI，用于 HTML 内嵌显示"""
    icon_path = _find_icon_file()
    if not icon_path:
        return None
    try:
        with open(icon_path, 'rb') as f:
            data = base64.b64encode(f.read()).decode('ascii')
        return f'data:image/x-icon;base64,{data}'
    except Exception:
        return None


def _build_icon_html():
    """生成图标 HTML：优先用真实图标文件，找不到则回退到 emoji"""
    data_uri = _get_icon_data_uri()
    if data_uri:
        return f'<img src="{data_uri}" style="width:80px;height:80px;margin-bottom:20px;filter:drop-shadow(0 0 20px rgba(0,188,212,0.5));" alt="御天">'
    return '<div class="icon">&#x1F6E1;&#xFE0F;</div>'


# ── 启动画面 HTML ──────────────────────────────────────

_SPLASH_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background: #0a1f2e;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100vh;
    font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
    overflow: hidden;
    user-select: none;
    -webkit-user-select: none;
}
.container {
    opacity: 0;
    animation: fadeIn {fade_in_ms}ms ease forwards;
    text-align: center;
}
.icon-emoji {
    font-size: 72px;
    margin-bottom: 20px;
    filter: drop-shadow(0 0 20px rgba(0, 188, 212, 0.5));
}
.title {
    font-size: 36px;
    font-weight: bold;
    color: #f4f4f9;
    margin-bottom: 10px;
    letter-spacing: 4px;
}
.status {
    font-size: 11px;
    color: #8f8fab;
    margin-top: 8px;
    min-height: 16px;
}
.spinner {
    width: 24px;
    height: 24px;
    border: 2px solid rgba(0, 188, 212, 0.2);
    border-top-color: #00bcd4;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    margin: 16px auto 0;
}
@keyframes fadeIn {
    to { opacity: 1; }
}
@keyframes spin {
    to { transform: rotate(360deg); }
}
.fade-out {
    animation: fadeOut {fade_out_ms}ms ease forwards !important;
}
@keyframes fadeOut {
    to { opacity: 0; }
}
</style>
</head>
<body>
<div class="container" id="splash">
    {icon_html}
    <div class="title">御天</div>
    <div class="status" id="status">正在启动引擎...</div>
    <div class="spinner"></div>
</div>
<script>
function setStatus(text) {
    document.getElementById('status').textContent = text;
}
function fadeOut() {
    document.getElementById('splash').classList.add('fade-out');
}
</script>
</body>
</html>""".replace("{fade_in_ms}", str(FADE_IN_MS)).replace("{fade_out_ms}", str(FADE_OUT_MS))


def get_splash_html():
    """返回带真实图标的 splash HTML（运行时动态注入）"""
    icon_html = _build_icon_html()
    return _SPLASH_HTML.replace("{icon_html}", icon_html)


# ── 退出画面 HTML ──────────────────────────────────────

_EXIT_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background: #0a1f2e;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100vh;
    font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
    overflow: hidden;
    user-select: none;
    -webkit-user-select: none;
}
.container {
    text-align: center;
    animation: fadeOut {fade_out_ms}ms ease 200ms forwards;
}
.icon {
    font-size: 72px;
    margin-bottom: 20px;
    filter: drop-shadow(0 0 20px rgba(0, 188, 212, 0.5));
}
.title {
    font-size: 36px;
    font-weight: bold;
    color: #f4f4f9;
    margin-bottom: 10px;
    letter-spacing: 4px;
}
.status {
    font-size: 11px;
    color: #8f8fab;
    margin-top: 8px;
}
@keyframes fadeOut {
    to { opacity: 0; }
}
</style>
</head>
<body>
<div class="container">
    {exit_icon_html}
    <div class="title">御天</div>
    <div class="status">正在安全退出...</div>
</div>
</body>
</html>""".replace("{fade_out_ms}", str(FADE_OUT_MS))


def get_exit_html():
    """返回带真实图标的退出 HTML"""
    icon_html = _build_icon_html()
    return _EXIT_HTML.replace("{exit_icon_html}", icon_html)


class LogoSplash:
    """Logo 启动画面（纯 webview 实现，无需 tkinter）"""

    def __init__(self):
        self._window = None  # 由 app.py 创建后通过 set_window 设置
        self._engine_loaded = False
        self._ready = threading.Event()
        self._fade_in_done = threading.Event()

    def set_window(self, window):
        """设置 webview 窗口引用（由 app.py 在创建窗口后调用）"""
        self._window = window

    def set_status(self, text: str):
        """更新加载状态文字（可在后台线程调用）"""
        if self._window:
            try:
                self._window.evaluate_js(f'setStatus({text!r})')
            except Exception:
                pass

    def mark_engine_loaded(self):
        """标记引擎加载完成"""
        self._engine_loaded = True
        self._ready.set()

    def wait_until_ready(self, timeout=30):
        """
        等待淡入动画和引擎加载都完成。
        timeout: 最大等待秒数，超时后自动放行。
        """
        # 1. 等淡入动画播完
        self._fade_in_done.wait(timeout=5)
        # 2. 等引擎加载完毕
        if not self._engine_loaded:
            self.set_status("引擎加载中，请稍候...")
            _deadline = time.time() + timeout
            while not self._ready.is_set():
                if time.time() > _deadline:
                    self.set_status("引擎加载超时，跳过...")
                    print("[LogoSplash] 引擎加载超时，强制放行")
                    break
                self._ready.wait(timeout=0.1)


# ══════════════════════════════════════════════════════════════
#  退出淡出动画（独立使用，无需依赖 LogoSplash 实例）
# ══════════════════════════════════════════════════════════════

def show_exit_fadeout(on_complete=None):
    """
    在独立进程中显示退出淡出动画（用子进程 webview 窗口）。
    on_complete: 动画结束后回调

    由于主 webview 即将关闭，退出动画改用简单的延时方案：
    等待淡出时间后直接回调，不创建新窗口（避免 webview 冲突）。
    """
    # 淡出延时
    delay = (FADE_OUT_MS + 200) / 1000.0

    def _thread():
        time.sleep(delay)
        if on_complete:
            on_complete()

    t = threading.Thread(target=_thread, daemon=True)
    t.start()
    return t