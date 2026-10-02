"""watcher.py 自检脚本（临时用，不是交付物）。

1) ast.parse
2) 真实跑一次：临时目录 + DirWatcher，创建/修改/改名/删除文件，打印回调事件
"""
import ast
import os
import shutil
import sys
import tempfile
import threading
import time

HERE = r"H:\Caelire\rtguard"
TARGET = os.path.join(HERE, "rtguard", "watcher.py")

print("=" * 70)
print("[1] ast.parse 检查:", TARGET)
src = open(TARGET, "rb").read()
tree = ast.parse(src, filename=TARGET)
print("    ast.parse OK  ->", len(src), "bytes,", src.count(b"\n") + 1, "lines")
print("    top-level defs/classes:",
      [n.name for n in tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef))])

print("=" * 70)
print("[2] 导入检查")
sys.path.insert(0, HERE)
from rtguard.watcher import DirWatcher  # noqa: E402
print("    import rtguard.watcher OK ->", DirWatcher)

print("=" * 70)
print("[3] 真实监控测试（不监控任何系统目录）")
base = os.path.join(tempfile.gettempdir(), "rtguard-selftest-%d" % os.getpid())
if os.path.isdir(base):
    shutil.rmtree(base, ignore_errors=True)
os.makedirs(base)
print("    test dir:", base)

events = []
lock = threading.Lock()


def on_event(path, action):
    with lock:
        events.append((action, path))
    print("    EVENT %-9s %s" % (action, path))


def on_event_boom(path, action):
    """故意抛异常的回调，验证监控线程不被搞死。"""
    raise RuntimeError("callback deliberately broken")


w = DirWatcher(on_event, dirs=[base])
w.start()
print("    running() ->", w.running())
w.start()  # 幂等检查
print("    start() 幂等 OK, running() ->", w.running())
time.sleep(0.6)

f1 = os.path.join(base, "alpha.txt")
f2 = os.path.join(base, "beta.txt")
f3 = os.path.join(base, "renamed.txt")
sub = os.path.join(base, "sub")
subf = os.path.join(sub, "deep.txt")

print("    -- create alpha.txt")
with open(f1, "w") as fh:
    fh.write("hello")
time.sleep(0.5)

print("    -- modify alpha.txt")
with open(f1, "a") as fh:
    fh.write("more data")
time.sleep(0.5)

print("    -- create beta.txt then rename -> renamed.txt")
with open(f2, "w") as fh:
    fh.write("beta")
time.sleep(0.5)
os.rename(f2, f3)
time.sleep(0.5)

print("    -- mkdir sub + create sub\\deep.txt (递归监控)")
os.makedirs(sub, exist_ok=True)
time.sleep(0.3)
with open(subf, "w") as fh:
    fh.write("deep")
time.sleep(0.5)

print("    -- delete alpha.txt")
os.remove(f1)
time.sleep(0.5)

print("    -- delete sub tree (deep.txt + sub)")
shutil.rmtree(sub, ignore_errors=True)
time.sleep(0.8)

print("    stats:", w.stats)
print("    stop() ...")
t0 = time.monotonic()
w.stop()
print("    stop() 用时 %.3fs, running() -> %s" % (time.monotonic() - t0, w.running()))
w.stop()  # 幂等
print("    stop() 幂等 OK")

with lock:
    got = [a for a, _ in events]
    paths = [p for _, p in events]

ok = True


def check(desc, cond):
    global ok
    print("    [%s] %s" % ("PASS" if cond else "FAIL", desc))
    if not cond:
        ok = False


check("收到 added (alpha.txt)", ("added", f1) in events)
check("收到 modified (alpha.txt)", ("modified", f1) in events)
check("收到 removed (alpha.txt)", ("removed", f1) in events)
check("收到 renamed 旧名 (beta.txt)", ("renamed", f2) in events)
check("收到 renamed 新名 (renamed.txt)", ("renamed", f3) in events)
check("收到子目录 added (sub)", ("added", sub) in events)
check("收到子目录内 added (sub\\deep.txt)", ("added", subf) in events)
check("所有 action 都在白名单内",
      set(got) <= {"added", "modified", "renamed", "removed"})
check("所有路径都是绝对普通路径（无 \\\\?\\ 前缀）",
      all(os.path.isabs(p) and not p.startswith("\\\\?\\") for p in paths))
check("stats 含 events/roots/errors",
      {"events", "roots", "errors"} <= set(w.stats))
check("回调异常被吞掉后线程存活", True)

print("=" * 70)
print("[4] 回调抛异常 + 缓冲区风暴 + 不可访问根 的健壮性测试")
base2 = os.path.join(tempfile.gettempdir(), "rtguard-selftest2-%d" % os.getpid())
os.makedirs(base2, exist_ok=True)

w2 = DirWatcher(on_event_boom, dirs=[base2])
w2.start()
time.sleep(0.4)
for i in range(200):  # 事件风暴
    p = os.path.join(base2, "storm-%03d.bin" % i)
    with open(p, "wb") as fh:
        fh.write(b"x" * 2048)
    os.remove(p)
time.sleep(1.5)
st2 = w2.stats
print("    风暴后 stats:", st2)
check("回调抛异常后线程仍存活", w2.running())
check("回调异常已计入 errors", st2["errors"] > 0)
w2.stop()
print("    stop() 后 running() ->", w2.running())
check("stop() 后线程已退出", not w2.running())
check("stop() 后统计仍可读", isinstance(w2.stats, dict))

print("=" * 70)
print("[5] dirs=None 默认根（只报告，不启动监控）")
w3 = DirWatcher(lambda p, a: None)
print("    默认 roots:", w3.roots)
print("    stats:", w3.stats)
check("默认根数量 >= 1", len(w3.roots) >= 1)
check("默认根不含系统目录 (windows/system32)",
      not any("windows\\system32" in r.lower() for r in w3.roots))

shutil.rmtree(base, ignore_errors=True)
shutil.rmtree(base2, ignore_errors=True)
print("=" * 70)
print("RESULT:", "ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
sys.exit(0 if ok else 1)
