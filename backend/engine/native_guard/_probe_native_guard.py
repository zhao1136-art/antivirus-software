"""
native_guard.dll 隔离探针（临时调试用）
对每个导出函数，在独立子进程中以 CDLL(cdecl) 调用；子进程崩溃(0xC0000005)不会波及本轮。
用法: python _probe_native_guard.py
"""
import ctypes
import subprocess
import sys
import os

DLL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "native_guard.dll")

# (函数名, 是否需要 args 供调用, 真正的调用代码片段)
PROBES = [
    ("guard_version", "f()"),
    ("guard_self_test", "f()"),
    ("guard_inject_scan_all", "f()"),
    ("guard_inject_enum_all_modules", "f()"),
    ("guard_inject_scan_threads", "f()"),
    ("guard_inject_scan_memory", "f(ctypes.c_uint32(4))"),
    ("guard_inject_enum_modules", "f(ctypes.c_uint32(4))"),
    ("guard_fileless_scan_cmdlines", "f()"),
    ("guard_fileless_check_wmi", "f()"),
    ("guard_persist_scan_all", "f()"),
    ("guard_net_enum_tcp", "f()"),
    ("guard_net_enum_with_risk", "f()"),
    ("guard_etw_status", "f()"),
    ("guard_etw_process_tree", "f(ctypes.c_int(5))"),
    ("guard_scan_amsi_tamper", "f()"),
    ("guard_scan_etw_tamper", "f()"),
]


def run_one(name, callcode):
    script = (
        "import ctypes,sys\n"
        "d=ctypes.CDLL(r'%s')\n"
        "f=getattr(d,'%s')\n"
        "f.restype=ctypes.c_void_p\n"
        "r=%s\n"
        "if r:\n"
        "    p=ctypes.cast(r,ctypes.c_char_p)\n"
        "    print('OK '+str(p.value.decode('utf-8','replace')[:120]))\n"
        "else:\n"
        "    print('EMPTY')\n"
        "print('EXIT_OK')\n"
    ) % (DLL, name, callcode)
    p = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    ok = p.returncode == 0 and "EXIT_OK" in p.stdout
    print(f"[{'PASS cdecl' if ok else 'CRASH/dead'}] {name:28s} rc={p.returncode}")
    if not ok:
        print("   stdout:", p.stdout.strip().splitlines()[-3:] if p.stdout else "(none)")
        print("   stderr:", p.stderr.strip().splitlines()[-3:] if p.stderr else "(none)")
    return ok


if __name__ == "__main__":
    crashed = []
    for name, callcode in PROBES:
        if not run_one(name, callcode):
            crashed.append(name)
    print("\n---- 汇总 ----")
    print("cdecl 崩溃的导出:", crashed if crashed else "无")
    sys.exit(1 if crashed else 0)