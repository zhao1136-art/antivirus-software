"""
御天 前端单独启动器（诊断/隔离验证用）

故意不加载任何后端（FastAPI/引擎/自保护/watchdog），
只做：把 frontend 目录用一个轻量静态 HTTP 服务托管 + 用 pywebview 弹出窗口加载。

用途：单独验证“前端页面 + webview 窗口”能否正常显示，
把前端渲染问题与应用主进程启动崩溃问题隔离开。

用法（开发模式）:
    python frontend_launcher.py                # 弹出桌面窗口加载前端
    python frontend_launcher.py --browser      # 改用默认浏览器打开前端
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

    if "--browser" in sys.argv:
        import webbrowser
        webbrowser.open(url)
        try:
            while True:
                threading.Event().wait(60)
        except KeyboardInterrupt:
            pass
        return

    # 默认：pywebview 桌面窗口
    import webview
    w = webview.create_window(
        "御天 安全中心（前端预览）",
        url,
        width=1100,
        height=700,
        min_size=(900, 600),
        resizable=True,
    )
    # frozen 模式下 win32 后端可能无法弹窗，这里显式捕获异常避免静默退出
    try:
        webview.start()
    except Exception as e:
        import traceback
        print("[前端启动器] webview 无法启动:")
        traceback.print_exc()
        print("[前端启动器] 可改用 --browser 参数在默认浏览器中打开验证前端。")


if __name__ == "__main__":
    main()