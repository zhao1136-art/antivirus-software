import subprocess, sys, os, ctypes, time

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
                        print(f"  [kill] {n} pid={pid_s}")
                    except Exception as e:
                        print(f"  [skip] {n}: {e}")
    except Exception as e:
        print(f"  [warn] tasklist: {e}")

def hard_rmtree(target):
    """cmd del + 取消只读/系统属性 + 多次重试"""
    ap = os.path.abspath(target)
    if not os.path.exists(ap): return True
    # 先去属性
    subprocess.run(["cmd.exe", "/c", "attrib -R -S -H /S /D \"" + ap + "\\*\""], capture_output=True)
    time.sleep(1)
    for attempt in range(1, 9):
        r = subprocess.run(["cmd.exe", "/c", "rmdir /s /q \"" + ap + "\""], capture_output=True, text=True)
        if not os.path.exists(ap):
            print(f"  [ok] removed {target} (attempt {attempt})")
            return True
        time.sleep(3)
    print(f"  [fail] still cannot remove {target}")
    return False

print("> 1) kill 御天 / file_guard / python (非自身)...")
# 先拿自己 pid，避免误伤
me = os.getpid()
try:
    my_pid_list = {int(me)}
    # 父进程也加上？稳妥点只排除自己
except Exception:
    my_pid_list = set()
kill_by_name(["御天", "file_guard"])
time.sleep(3)

print("\n> 2) 强制清理旧 dist/御天 和 build/御天")
hard_rmtree(r"dist\御天")
hard_rmtree(r"dist\御天_build")
hard_rmtree(r"build\御天")

# 把 spec 的 COLLECT name 切到全新的目录名「御天2」再打包一次，彻底避开任何锁
print("\n> 3) 修改 spec，输出到 dist\\御天2 (全新目录)")
import re
spec = r"f:\Caelire\backend\御天.spec"
with open(spec, "r", encoding="utf-8") as f:
    txt = f.read()
txt2 = re.sub(r"name='御天_build'", "name='御天2'", txt)
txt2 = re.sub(r"name='御天'",        "name='御天2'", txt2)
# 但只改最后一个 COLLECT 的 name，防止 exe 的 name 也被改
# 回退：只把 COLLECT 段的 name= 单独改
if "name='御天2'" not in txt2:
    # 保底直接替换
    txt2 = txt2.replace("coll = COLLECT(", "coll = COLLECT(\n    # force fresh output")
    txt2 = re.sub(r"name='[^']+',\s*\)", "name='御天2',\n)", txt2)
with open(spec, "w", encoding="utf-8") as f:
    f.write(txt2)
print("   spec updated")

print("\n> 4) 开始 PyInstaller")
sys.stdout.flush()

log_path = r"f:\Caelire\backend\_pack_last2.log"
with open(log_path, "w", encoding="utf-8") as log_f:
    proc = subprocess.Popen(
        [r"F:\Python314\python.exe", "-m", "PyInstaller", "御天.spec", "--clean", "--noconfirm"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    last_banner = 0
    for line in proc.stdout:
        log_f.write(line); log_f.flush()
        # 关键阶段打印
        for tag in ["Building EXE", "Building COLLECT", "completed successfully.", "ERROR", "FATAL",
                    "copying bootloader", "Analyzing", "Building PKG", "Building PYZ"]:
            if tag in line:
                if time.time() - last_banner > 0.3:
                    print(line.rstrip())
                    last_banner = time.time()
    proc.wait()
    print(f"  exit code: {proc.returncode}")

# 恢复 spec（COLLECT name 改回御天）
with open(spec, "r", encoding="utf-8") as f:
    txt = f.read()
txt = txt.replace("# force fresh output", "").replace("name='御天2',", "name='御天',")
# 清理多出来的空行
with open(spec, "w", encoding="utf-8") as f:
    f.write(txt)

# 验证
exe = r"dist\御天2\御天.exe"
if os.path.isfile(exe):
    mb = os.path.getsize(exe) / 1024 / 1024
    fc = sum(1 for _ in os.walk(r"dist\御天2") for _ in _[2])
    print(f"\nBUILD OK: {exe}  {mb:.2f} MB, {fc} files")
    sys.exit(0)
else:
    print(f"\nBUILD FAIL: {exe} missing")
    # 打印错误段
    print(open(log_path, encoding="utf-8").read()[-2000:])
    sys.exit(1)