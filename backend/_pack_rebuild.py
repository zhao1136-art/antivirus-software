import subprocess, sys, os, shutil

os.chdir(r"f:\Caelire\backend")

# 杀掉御天相关进程，避免目录/文件被锁
def safe_kill(names):
    try:
        out = subprocess.check_output(["tasklist", "/NH", "/FO", "CSV"], stderr=subprocess.DEVNULL, text=True)
        for line in out.splitlines():
            line = line.strip()
            if not line: continue
            pname = line.split('","')[0].lstrip('"').rsplit(".", 1)[0]  # 去掉 .exe
            pid_s = line.split('","')[1] if '","' in line else None
            for n in names:
                if pname.lower() == n.lower() and pid_s:
                    try:
                        subprocess.run(["taskkill", "/F", "/PID", pid_s], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        print(f"  killed {n} (PID {pid_s})")
                    except Exception:
                        pass
    except Exception as e:
        print(f"  (tasklist fail: {e})")

print("Killing locked processes...")
safe_kill(["御天", "file_guard", "python"])
import time; time.sleep(2)

print("Cleaning dist/build...")
for d in [r"dist\御天", r"build\御天"]:
    if os.path.exists(d):
        r = subprocess.run(["cmd.exe", "/c", "rmdir /s /q \"" + os.path.abspath(d) + "\""], capture_output=True, text=True)
        print(f"  {d}: code={r.returncode}")

print("\nStarting PyInstaller...")
sys.stdout.flush()

result = subprocess.run(
    [r"F:\Python314\python.exe", "-m", "PyInstaller", "御天.spec", "--clean", "--noconfirm"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
)
tail = result.stdout[-3500:] if len(result.stdout) > 3500 else result.stdout
print(tail)
print(f"\nExit code: {result.returncode}")

# 简单验证
exe = r"dist\御天\御天.exe"
if os.path.isfile(exe):
    size_mb = os.path.getsize(exe) / 1024 / 1024
    files = sum(1 for _ in os.walk(r"dist\御天") for _ in _[2])
    print(f"\nVerified OK: {exe}  {size_mb:.2f} MB, {files} files")
else:
    print(f"\nWARNING: exe not found at {exe}")
sys.exit(result.returncode)