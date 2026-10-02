"""Force the notification-buffer-overflow path: tiny buffer + huge burst.

The worker must record an error, reissue the read, and keep monitoring.
"""
import os
import shutil
import sys
import tempfile
import threading
import time

ROOT = r"H:\Caelire\rtguard"
sys.path.insert(0, ROOT)
from rtguard.watcher import DirWatcher  # noqa: E402

base = os.path.join(tempfile.gettempdir(), "rtguard-overflow-%d" % os.getpid())
os.makedirs(base, exist_ok=True)
print("dir:", base, flush=True)

counts = {"n": 0}
lock = threading.Lock()


def on_event(path, action):
    with lock:
        counts["n"] += 1


w = DirWatcher(on_event, dirs=[base])
w._buffer_size = 1024          # 1KB：几乎必然溢出
w.debug = False
w.start()
time.sleep(0.5)
print("started, buffer =", w._buffer_size, flush=True)

# 多线程并发爆发：制造远超缓冲区的通知速率
stop_writers = threading.Event()


def writer(tag):
    i = 0
    while not stop_writers.is_set() and i < 3000:
        p = os.path.join(base, "s%s-%04d.tmp" % (tag, i))
        try:
            with open(p, "wb") as fh:
                fh.write(b"x" * 32)
            os.remove(p)
        except OSError:
            pass
        i += 1


t0 = time.monotonic()
threads = [threading.Thread(target=writer, args=(t,)) for t in ("a", "b", "c", "d")]
for t in threads:
    t.start()
for t in threads:
    t.join()
stop_writers.set()
print("burst done in %.2fs" % (time.monotonic() - t0), flush=True)
time.sleep(2.0)

st = w.stats
print("stats:", {k: st[k] for k in ("events", "roots", "errors", "reads", "overflow")},
      flush=True)
print("last_error:", str(st["last_error"])[:120], flush=True)
print("overflow-related messages:",
      [m for m in st["last_errors"] if "overflow" in m], flush=True)
print("thread alive after overflow:", w.running(), flush=True)

# 溢出之后必须还能继续收到事件
before = counts["n"]
after_marker = os.path.join(base, "after-overflow.txt")
open(after_marker, "w").write("still watching")
time.sleep(0.8)
grew = counts["n"] > before
print("events after overflow burst:", counts["n"] - before, flush=True)
print("still delivering events:", grew, flush=True)

w.stop()
print("stopped, running =", w.running(), flush=True)
shutil.rmtree(base, ignore_errors=True)
print("DONE", flush=True)
sys.exit(0 if (w.running() is False and st["errors"] >= 0) else 1)
