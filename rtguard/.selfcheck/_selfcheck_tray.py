import ctypes
import sys

sys.path.insert(0, r"H:\Caelire\rtguard")

import rtguard.tray as tray

print("== 3. tray: import / 构造 / start() ==")
print("NOTIFYICONDATAW 结构体大小 (ctypes.sizeof) =", ctypes.sizeof(tray.NOTIFYICONDATAW), "bytes")
print("  （64 位 Windows NOTIFYICONDATAW 期望 976，未硬编码魔数）")

events = []
t = tray.TrayIcon(
    "rtguard 实时防护",
    tooltip="rtguard 实时防护 — 运行中",
    on_open=lambda: events.append("open"),
    on_quit=lambda: events.append("quit"),
)
print("构造成功:", repr(t))

ok = t.start()
print("start() 返回值 =", ok)
print("start() 未抛异常: True")
print("hwnd =", t.hwnd)
print("last_error =", t.last_error)

n = t.notify("rtguard", "自检通知：托盘模块可用")
print("notify() 返回值 =", n)

# 按要求：不调用 stop() 之后再 start()；此处仅看线程是否存活（daemon）
print("消息循环线程存活 =", t._thread.is_alive() if t._thread else None)

# 清理：进程退出时 daemon 线程自动结束；这里显式结束一次以确认 stop() 不抛异常
t.stop()
print("stop() 未抛异常: True")
print("TRay CHECK DONE")
