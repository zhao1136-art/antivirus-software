"""API shape + dependency audit (temporary)."""
import ast
import inspect
import os
import sys

ROOT = r"H:\Caelire\rtguard"
TARGET = os.path.join(ROOT, "rtguard", "watcher.py")
src = open(TARGET, encoding="utf-8").read()
tree = ast.parse(src, filename=TARGET)

std = {"ctypes", "threading", "os", "sys", "time", "queue", "__future__"}
mods = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for a in node.names:
            mods.add(a.name.split(".")[0])
    elif isinstance(node, ast.ImportFrom):
        if node.module:
            mods.add(node.module.split(".")[0])

print("imported top-level modules:", sorted(mods))
print("third-party imports:", sorted(mods - std - {"ctypes", "wintypes"}))
print("std-lib only:", mods <= std)

sys.path.insert(0, ROOT)
from rtguard.watcher import DirWatcher  # noqa: E402

print("\n--- public API ---")
print("class DirWatcher:", inspect.signature(DirWatcher.__init__))
for name in ("start", "stop", "running"):
    print("  %-9s %s" % (name, inspect.signature(getattr(DirWatcher, name))))
print("  stats is property:", isinstance(DirWatcher.__dict__["stats"], property))

d = DirWatcher(lambda p, a: None, dirs=[ROOT])
print("\nstats after construction:", d.stats)
print("running() before start:", d.running())
d.stop()                     # stop before start must be a no-op
print("stop() before start: ok (no exception)")
d.start()
print("stats while running:", d.stats)
d.stop()
d.stop()
print("stop() twice: ok")
print("\nrequired keys present:",
      {"events", "roots", "errors"} <= set(d.stats))
print("stats values:", {k: d.stats[k] for k in ("events", "roots", "errors")})
print("\nmodule docstring length:", len(DirWatcher.__doc__ or ""))
