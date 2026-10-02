"""临时：对比 cdecl vs stdcall 调用约定对带参导出的影响"""
import ctypes
import subprocess
import sys
import os

DLL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "native_guard_build.dll")

CASES = [
    ("windll  inject_scan_memory(pid)", "d=ctypes.WinDLL(DLL)", "guard_inject_scan_memory", "f(ctypes.c_uint32(4))"),
    ("cdecl   inject_scan_memory(pid)", "d=ctypes.CDLL(DLL)",  "guard_inject_scan_memory", "f(ctypes.c_uint32(4))"),
    ("windll  enum_modules(pid)",       "d=ctypes.WinDLL(DLL)", "guard_inject_enum_modules", "f(ctypes.c_uint32(4))"),
    ("cdecl   enum_modules(pid)",       "d=ctypes.CDLL(DLL)",  "guard_inject_enum_modules", "f(ctypes.c_uint32(4))"),
]

for label, load, fn, call in CASES:
    s = (
        "import ctypes,sys\n"
        f"DLL={DLL!r}\n"
        f"d={load}\n"
        f"f=getattr(d,'{fn}')\n"
        "f.restype=ctypes.c_void_p\n"
        "f.argtypes=[ctypes.c_uint32]\n"
        f"r={call}\n"
        "print('RESULT_END')\n"
    )
    p = subprocess.run([sys.executable, "-c", s], capture_output=True, text=True)
    dead = p.returncode != 0 or "RESULT_END" not in p.stdout
    print(f"[{'DEAD' if dead else 'OK'}] {label:34s} rc={p.returncode}")
    if dead:
        print("   stderr:", (p.stderr or "").strip().splitlines()[-2:] or "(none)")