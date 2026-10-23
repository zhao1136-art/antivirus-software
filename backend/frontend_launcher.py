"""
御天 前端单独启动器（诊断/隔离验证用）

故意不加载任何后端（FastAPI/引擎/自保护/watchdog），
只做：把 frontend 目录用一个轻量静态 HTTP 服务托管 + 用系统默认浏览器打开。

用途：单独验证 frontend/ 下的 HTML 版界面能否正常渲染，
把前端渲染问题与应用主进程启动问题隔离开。

注意：主程序界面已改为 ui_tk/ 下的 Tkinter 实现，webview 链路已整体移除，
      因此本工具也不再使用 pywebview，改为浏览器打开（零第三方依赖）。

用法（开发模式）:
    python frontend_launcher.py                # 起静态服务并打开默认浏览器
"""
import os
import sys
import socket
import threading
import http.server
import functools


def frontend_dir() -> str:
    """定位前端目录（兼容开发模式 backend/frontend 与打包模式 _internal/frontend）。"""
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, "frontend")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")


def _free_port() -> int:
    """获取一个空闲本地端口，避免与残留进程冲突。"""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    fd = frontend_dir()
    if not os.path.isdir(fd):
        print("[前端启动器] frontend 目录不存在:", fd)
        return
    os.chdir(fd)  # 静态服务器以此目录为根

    port = _free_port()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=fd)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    url = f"http://127.0.0.1:{port}/index.html"
    print("[前端启动器] 前端已就绪:", url)
    print("[前端启动器] 提示: 本页面不连后端，个别数据无法加载是正常现象，用于验证界面能否显示。")

    # 用系统默认浏览器打开（原先默认开 pywebview 桌面窗口）
    import webbrowser
    webbrowser.open(url)
    print("[前端启动器] 已用系统默认浏览器打开。Ctrl+C 退出（会一并停掉静态服务）。")
    try:
        while True:
            threading.Event().wait(60)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()