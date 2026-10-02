import ast
import sys
import os

sys.path.insert(0, r"H:\Caelire\rtguard")

FILES = [
    r"H:\Caelire\rtguard\rtguard\quarantine.py",
    r"H:\Caelire\rtguard\rtguard\tray.py",
]

print("== 1. ast.parse ==")
for f in FILES:
    with open(f, "r", encoding="utf-8") as fh:
        src = fh.read()
    ast.parse(src, filename=f)
    nlines = src.count("\n") + (0 if src.endswith("\n") else 1)
    print(f"OK  ast.parse  {os.path.basename(f):16s} lines={nlines}")

print()
print("== 2. import ==")
import rtguard.quarantine as q
import rtguard.tray as t
print("OK  import rtguard.quarantine ->", q.Quarantine)
print("OK  import rtguard.tray       ->", t.TrayIcon)
print("    NOTIFYICONDATAW.cbSize expect =", __import__("ctypes").sizeof(t.NOTIFYICONDATAW))
