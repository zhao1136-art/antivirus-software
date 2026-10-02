import subprocess, sys, os, time

os.chdir(r"f:\Caelire\backend")

def kill_by_name(names):
    try:
        out = subprocess.check_output(["tasklist", "/NH", "/FO", "CSV"], stderr=subprocess.DEVNULL, text=True)
        for line in out.splitlines():
            line = line.strip()
            if not line: continue
            parts = line.split('","')
            if len(parts) < 2: continue
            pname = parts[0].lstrip('"').rsplit(".", 1)[0]
            pid_s = parts[1]
            for n in names:
                if pname.lower() == n.lower():
                    try:
                        subprocess.run(["taskkill", "/F", "/PID", pid_s], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        print(f"  [ok] kill {n} pid={pid_s}")
                    except Exception as e:
                        print(f"  [skip] kill {n}: {e}")
    except Exception as e:
        print(f"  [warn] tasklist: {e}")

print("> step 1: kill related processes")
kill_by_name(["御天", "file_guard"])
time.sleep(3)

print("> step 2: remove old dist and build")
for p in [r"dist\御天", r"build\御天"]:
    ap = os.path.abspath(p)
    if os.path.exists(ap):
        for attempt in range(6):
            r = subprocess.run(["cmd.exe", "/c", "rmdir /s /q \"" + ap + "\" >nul 2>nul & exit 0"], capture_output=True, text=True)
            if not os.path.exists(ap):
                print(f"  removed: {p}")
                break
            time.sleep(2)
        else:
            print(f"  ! cannot remove {p}, still exists")

print("> step 3: PyInstaller build")
sys.stdout.flush()

# 写入实时日志
log_path = r"f:\Caelire\backend\_pack_last.log"
with open(log_path, "w", encoding="utf-8") as log_f:
    proc = subprocess.Popen(
        [r"F:\Python314\python.exe", "-m", "PyInstaller", "御天.spec", "--clean", "--noconfirm"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    for line in proc.stdout:
        log_f.write(line); log_f.flush()
        if "INFO" in line or "ERROR" in line or "WARN" in line or "Building" in line or "completed" in line.lower():
            print(line.rstrip())
    proc.wait()
    print(f"> PyInstaller exit: {proc.returncode}")

# 验证
exe = r"dist\御天\御天.exe"
if os.path.isfile(exe):
    mb = os.path.getsize(exe) / 1024 / 1024
    fc = sum(1 for _ in os.walk(r"dist\御天") for _ in _[2])
    print(f"> BUILD OK: {exe}  {mb:.2f} MB, {fc} files")
else:
    print(f"> BUILD FAIL: {exe} missing")
    sys.exit(1)
sys.exit(0)