"""最小诊断：单根目录，打开 debug，打印真实 Win32 错误文本。"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rtguard.watcher import DirWatcher  # noqa: E402

base = os.path.join(tempfile.gettempdir(), "rtguard-diag-%d" % os.getpid())
os.makedirs(base, exist_ok=True)
print("test dir:", base)

events = []
w = DirWatcher(lambda p, a: (events.append((a, p)), print("EVENT", a, p)), dirs=[base])
w.debug = True
w.start()
time.sleep(0.8)
print("--- writing file ---")
with open(os.path.join(base, "probe.txt"), "w") as fh:
    fh.write("hi")
time.sleep(1.0)
print("stats:", {k: v for k, v in w.stats.items() if k != "last_errors"})
print("last_errors:")
for msg, n in w.stats["last_errors"].items():
    print("   x%-4d %s" % (n, msg))
w.stop()
print("events:", events)
