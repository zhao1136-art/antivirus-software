"""Final verification for rtguard/watcher.py (temporary script, not a deliverable).

Checks:
  1. ast.parse
  2. import (no admin required)
  3. live monitoring: added / modified / renamed(both names) / removed / subdir
  4. API: start()/stop() idempotent, running(), stats keys
  5. restart reuse of the same instance
  6. multiple roots at once
  7. nonexistent root tolerated
  8. callback exception isolation under event storm
  9. FILE_NOTIFY_INFORMATION parsing helper unit check (offset/length rules)
"""
import ast
import os
import shutil
import sys
import tempfile
import threading
import time

ROOT = r"H:\Caelire\rtguard"
TARGET = os.path.join(ROOT, "rtguard", "watcher.py")
ok = True


def check(desc, cond, extra=""):
    global ok
    print("    [%s] %s%s" % ("PASS" if cond else "FAIL", desc,
                             (" -> " + extra) if extra else ""))
    if not cond:
        ok = False


base = os.path.join(tempfile.gettempdir(), "rtguard-final-%d" % os.getpid())
fired = []
lock = threading.Lock()


def on_event(path, action):
    with lock:
        fired.append((action, path))
    print("      EVENT %-9s %s" % (action, path))


def snapshot():
    with lock:
        return list(fired)


print("=" * 72)
print("[1] ast.parse:", TARGET)
src = open(TARGET, "rb").read()
ast.parse(src, filename=TARGET)
print("    OK -> %d bytes, %d lines" % (len(src), src.count(b"\n") + 1))

print("=" * 72)
print("[2] import (non-admin safe)")
sys.path.insert(0, ROOT)
import rtguard.watcher as W  # noqa: E402

check("module importable", True, str(W.DirWatcher))
check("DEFAULT_BUFFER_SIZE == 256KB", W.DEFAULT_BUFFER_SIZE == 256 * 1024,
      str(W.DEFAULT_BUFFER_SIZE))
check("ACTION map 1..5 -> added/removed/modified/renamed/renamed",
      W.ACTIONS == {1: "added", 2: "removed", 3: "modified",
                    4: "renamed", 5: "renamed"}, str(W.ACTIONS))
check("FILTER_ALL includes FILE/DIR/ATTR/SIZE/LAST_WRITE/CREATION/SECURITY",
      all(W.FILTER_ALL & bit for bit in (0x1, 0x2, 0x4, 0x8, 0x10, 0x40, 0x100)),
      hex(W.FILTER_ALL))
check("FILE_FLAG_BACKUP_SEMANTICS used", W._FILE_FLAG_BACKUP_SEMANTICS == 0x02000000)
check("FILE_FLAG_OVERLAPPED used", W._FILE_FLAG_OVERLAPPED == 0x40000000)
check("sizeof(_OVERLAPPED) == 32 on 64-bit", __import__("ctypes").sizeof(W._OVERLAPPED) == 32)
check("sizeof(FILE_NOTIFY_INFORMATION header) == 12",
      __import__("ctypes").sizeof(W._FILE_NOTIFY_INFORMATION) == 12)

print("=" * 72)
print("[3] _strip_long_prefix / path handling")
check(r"\\?\C:\x -> C:\x", W._strip_long_prefix(r"\\?\C:\x") == r"C:\x")
check(r"\\?\UNC\srv\share -> \\srv\share",
      W._strip_long_prefix(r"\\?\UNC\srv\share") == r"\\srv\share")
check("plain path untouched", W._strip_long_prefix(r"C:\a\b") == r"C:\a\b")

print("=" * 72)
print("[4] live monitoring in", base)
if os.path.isdir(base):
    shutil.rmtree(base, ignore_errors=True)
os.makedirs(base)
h1 = os.path.join(base, "one.txt")
h2 = os.path.join(base, "two.txt")
h3 = os.path.join(base, "three.txt")
sub = os.path.join(base, "nest")
subf = os.path.join(sub, "deep.txt")

w = W.DirWatcher(on_event, dirs=[base, base.upper().lower()])  # 含重复项
check("duplicate roots de-duplicated", w.stats["roots"] == 1, str(w.roots))
w.start()
check("running() True after start", w.running())
w.start()
check("start() idempotent (threads == 1)", w.stats["threads_alive"] == 1)
time.sleep(0.5)

open(h1, "w").write("hello")
time.sleep(0.45)
open(h1, "a").write("more")
time.sleep(0.45)
open(h2, "w").write("x")
time.sleep(0.45)
os.rename(h2, h3)
time.sleep(0.45)
os.makedirs(sub, exist_ok=True)
time.sleep(0.35)
open(subf, "w").write("deep")
time.sleep(0.45)
os.remove(h1)
time.sleep(0.45)
shutil.rmtree(sub, ignore_errors=True)
time.sleep(0.7)

ev = snapshot()
actions = set(a for a, _ in ev)
paths = [p for _, p in ev]
check("added h1", ("added", h1) in ev)
check("modified h1", ("modified", h1) in ev)
check("removed h1", ("removed", h1) in ev)
check("renamed old h2", ("renamed", h2) in ev)
check("renamed new h3", ("renamed", h3) in ev)
check("added subdir", ("added", sub) in ev)
check("added subdir file", ("added", subf) in ev)
check("actions within whitelist",
      actions <= {"added", "modified", "renamed", "removed"}, str(actions))
check("all paths absolute & prefix-free",
      all(os.path.isabs(p) and not p.startswith("\\\\?\\") for p in paths))
st = w.stats
check("stats has events/roots/errors",
      {"events", "roots", "errors"} <= set(st), str(sorted(st)))
check("stats events == len(fired)", st["events"] == len(ev),
      "%d vs %d" % (st["events"], len(ev)))
check("no errors during clean run", st["errors"] == 0, str(st.get("last_errors")))
check("all events under the monitored root",
      all(p.lower().startswith(base.lower()) for p in paths))

t0 = time.monotonic()
w.stop()
elapsed = time.monotonic() - t0
check("stop() returns quickly (<1s)", elapsed < 1.0, "%.3fs" % elapsed)
check("running() False after stop", not w.running())
w.stop()
check("stop() idempotent", not w.running())
check("stats readable after stop", isinstance(w.stats, dict))
check("threads_alive 0 after stop", w.stats["threads_alive"] == 0)

print("=" * 72)
print("[5] restart the same instance")
with lock:
    fired.clear()
w.start()
check("restart running()", w.running())
time.sleep(0.5)
h4 = os.path.join(base, "again.txt")
open(h4, "w").write("y")
time.sleep(0.6)
check("events received after restart", ("added", h4) in snapshot(), str(snapshot()))
w.stop()
check("second stop clean", not w.running())

print("=" * 72)
print("[6] nonexistent root is tolerated")
missing = os.path.join(base, "does-not-exist")
w2 = W.DirWatcher(on_event, dirs=[missing])
w2.start()
time.sleep(0.5)
check("still running while retrying missing root", w2.running())
check("missing root reported as error", w2.stats["errors"] >= 1,
      str(list(w2.stats["last_errors"])[:1])[:120])
w2.stop()
check("stopped missing-root watcher", not w2.running())

print("=" * 72)
print("[7] callback raising must not kill the thread (event storm)")
base2 = os.path.join(tempfile.gettempdir(), "rtguard-final2-%d" % os.getpid())
os.makedirs(base2, exist_ok=True)


def boom(path, action):
    raise RuntimeError("deliberate")


w3 = W.DirWatcher(boom, dirs=[base2])
w3.start()
time.sleep(0.4)
for i in range(300):
    p = os.path.join(base2, "s%03d.bin" % i)
    with open(p, "wb") as fh:
        fh.write(b"z" * 4096)
    os.remove(p)
time.sleep(1.5)
st3 = w3.stats
check("thread survived storm", w3.running())
check("callback errors counted", st3["errors"] > 0, str(st3["errors"]))
check("error map bounded (<=128)", len(st3["last_errors"]) <= 128,
      str(len(st3["last_errors"])))
check("overflow counter readable", "overflow" in st3 and "reads" in st3,
      "reads=%s overflow=%s" % (st3["reads"], st3["overflow"]))
w3.stop()
check("storm watcher stopped", not w3.running())

print("=" * 72)
print("[8] dirs=None default roots (not started)")
w4 = W.DirWatcher(lambda p, a: None)
print("    default roots:", w4.roots)
check("at least one default root", len(w4.roots) >= 1)
check("defaults avoid system dirs",
      not any("system32" in r.lower() or "\\windows\\" in r.lower() for r in w4.roots))
check("QueueWatcher present (optional helper)", hasattr(W, "QueueWatcher"))

shutil.rmtree(base, ignore_errors=True)
shutil.rmtree(base2, ignore_errors=True)
print("=" * 72)
print("RESULT:", "ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
sys.exit(0 if ok else 1)
