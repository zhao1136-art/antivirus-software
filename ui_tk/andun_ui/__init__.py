"""御天 Tkinter 桌面界面。

主程序的正式界面，由 ``backend/app.py`` 在主线程启动；也可用
``ui_tk/run_ui.py`` 单独运行（此时界面自己拉起后端进程）。
"""

# 与主程序版本保持一致（backend/app.py 的 ENGINE_VERSION）
__version__ = "1.1.0"
__all__ = ["__version__"]
