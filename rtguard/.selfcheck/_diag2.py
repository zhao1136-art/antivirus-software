"""诊断 2：修复 handle bug 后，观察每次 ReadDirectoryChangesW 的耗时/返回。"""
import os
import sys
import tempfile
import time

sys.path.insert(0, r"H:\Caelire\rtguard")
from rtguard.watcher import DirWatcher  # noqa: E402

base = os.path.join(tempfile.gettempdir(), "rtguard-diag2-%d" % os.getpid())
os.makedirs(base, exist_ok=True)
print("dir:", base, flush=True)

events = []


def on_event(path, action):
    events.append((action, path))
    print("  EVENT %-9s %s" % (action, os.path.basename(path)), flush=True)


w = DirWatcher(on_event, dirs=[base])
w.debug = True
w.start()
time.sleep(0.8)

print("-- create a.txt", flush=True)
open(os.path.join(base, "a.txt"), "w").write("x")
time.sleep(0.6)
print("-- modify a.txt", flush=True)
open(os.path.join(base, "a.txt"), "a").write("yy")
time.sleep(0.6)
print("-- rename a.txt -> b.txt", flush=True)
os.rename(os.path.join(base, "a.txt"), os.path.join(base, "b.txt"))
time.sleep(0.6)
print("-- delete b.txt", flush=True)
os.remove(os.path.join(base, "b.txt"))
time.sleep(0.8)

with w._lock:
    worker = w._workers[0] if w._workers else None
print("stats:", {k: v for k, v in w.stats.items() if k != "last_errors"}, flush=True)
if worker is not None:
    print("worker calls=%d immediate=%d blocked=%d zero_bytes=%d"
          % (worker.calls, worker.immediate, worker.blocked, worker.zero_bytes), flush=True)
    for i, row in enumerate(worker.trace[:30]):
        print("   call#%-3d elapsed=%.4fs ok=%s bytes=%s" % (i, row[0], row[1], row[2]), flush=True)
print("last_errors:", w.stats["last_errors"], flush=True)
print("EVENTS:", events, flush=True)
w.stop()
print("stopped, running=", w.running(), flush=True)
import shutil
shutil.rmtree(base, ignore_errors=True)
print("DONE", flush=True)
os._exit(0)
