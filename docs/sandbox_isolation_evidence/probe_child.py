"""Runs INSIDE the proposed low-integrity sandbox. Writes observation JSON."""
import ctypes
import json
import os
import sys
import time

out_dir = sys.argv[1]
report = {"argv": sys.argv[1:], "pid": os.getpid(), "writes": {}, "net": [], "registry": {}}


def try_write(path, data="caelire-lowil-probe"):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(data)
        return "SUCCESS"
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


report["writes"]["sandbox_dir"] = try_write(os.path.join(out_dir, "child_self.txt"))
report["writes"]["windows_dir"] = try_write(r"C:\Windows\caelire_lowil_test.txt")
report["writes"]["system32"] = try_write(r"C:\Windows\System32\caelire_lowil_test.txt")
report["writes"]["program_files"] = try_write(r"C:\Program Files\caelire_lowil_test.txt")
desktop = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\Public"), "Desktop")
report["writes"]["desktop"] = try_write(os.path.join(desktop, "caelire_lowil_test.txt"))
report["writes"]["hklm_via_reg"] = "n/a"
report["env_temp"] = os.environ.get("TEMP")
report["env_workdir"] = os.environ.get("YUTIAN_SANDBOX_WORKDIR")

# integrity level of this process
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                         ctypes.c_void_p, ctypes.c_ulong,
                                         ctypes.POINTER(ctypes.c_ulong)]
advapi32.GetTokenInformation.restype = ctypes.c_int
kernel32.GetCurrentProcess.restype = ctypes.c_void_p
tok = ctypes.c_void_p()
advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
advapi32.OpenProcessToken.restype = ctypes.c_int
advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
if advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(tok)):
    buf = ctypes.create_string_buffer(1024)
    need = ctypes.c_ulong()
    if advapi32.GetTokenInformation(tok, 25, buf, 1024, ctypes.byref(need)):
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        s = ctypes.c_wchar_p()
        if advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(s)):
            report["integrity_sid"] = s.value
    else:
        report["integrity_sid"] = f"GetTokenInformation failed {ctypes.get_last_error()}"
else:
    report["integrity_sid"] = f"OpenProcessToken failed {ctypes.get_last_error()}"

# registry write attempt (HKCU Run key)
try:
    import winreg
    k = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,
                           r"Software\Microsoft\Windows\CurrentVersion\Run",
                           0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(k, "CaelireLowILProbe", 0, winreg.REG_SZ, "calc.exe")
    winreg.CloseKey(k)
    report["registry"]["hkcu_run"] = "SUCCESS"
except Exception as exc:
    report["registry"]["hkcu_run"] = f"{type(exc).__name__}: {exc}"

try:
    import winreg
    k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, r"Software\CaelireLowILProbe",
                           0, winreg.KEY_SET_VALUE)
    winreg.CloseKey(k)
    report["registry"]["hklm_write"] = "SUCCESS"
except Exception as exc:
    report["registry"]["hklm_write"] = f"{type(exc).__name__}: {exc}"

# outbound network attempt
import socket
for host, port in (("93.184.216.34", 80), ("8.8.8.8", 53)):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        s.close()
        report["net"].append(f"{host}:{port} CONNECTED")
    except Exception as exc:
        report["net"].append(f"{host}:{port} {type(exc).__name__}: {exc}")

with open(os.path.join(out_dir, "child_report.json"), "w", encoding="utf-8") as fh:
    json.dump(report, fh, ensure_ascii=False, indent=2)
