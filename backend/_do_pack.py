"""
全Python打包脚本：杀进程→清理→打包到临时目录→重命名为正式目录→验证
不依赖PowerShell，不杀Python自身，避免自杀和文件锁问题
"""
import os, sys, subprocess, time, shutil, re, ctypes

os.chdir(r"f:\Caelire\backend")

LOG = r"f:\Caelire\backend\_pack_run.log"

def log(msg):
    print(msg, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

# 清空日志
with open(LOG, "w", encoding="utf-8") as f:
    f.write("")

log("=== 御天 Package Rebuild (Python) ===")
log(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
log("")

# 1) 杀御天和file_guard进程（不杀Python，避免自杀）
log("[1/5] Killing 御天.exe / file_guard.exe ...")
for name in ["御天.exe", "file_guard.exe"]:
    try:
        r = subprocess.run(
            ["taskkill", "/F", "/IM", name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        log(f"     taskkill {name}: exit={r.returncode}")
    except Exception as e:
        log(f"     taskkill {name}: {e}")
time.sleep(3)

# 2) 把dist和build里相关目录都用robocopy镜像清空（Windows最可靠的强删方式）
# robocopy empty_dir target /MIR 可以清空被锁的目录（清空内容而不是删除目录本身）
log("[2/5] Cleaning old outputs via robocopy mirror...")
empty_dir = r"f:\Caelire\backend\_empty_temp"
os.makedirs(empty_dir, exist_ok=True)

targets = [
    r"f:\Caelire\backend\dist\御天",
    r"f:\Caelire\backend\dist\御天_build",
    r"f:\Caelire\backend\dist\御天2",
    r"f:\Caelire\backend\build\御天",
]
for t in targets:
    if os.path.exists(t):
        try:
            # robocopy 镜像空目录到目标 = 清空目标
            r = subprocess.run(
                ["robocopy", empty_dir, t, "/MIR", "/R:1", "/W:1", "/NFL", "/NDL", "/NJH", "/NJS"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            # robocopy返回码<8都是成功
            log(f"     robocopy clean {os.path.basename(t)}: robocopy_exit={r.returncode}")
            time.sleep(1)
            # 尝试删除空目录
            for attempt in range(5):
                try:
                    shutil.rmtree(t, ignore_errors=False)
                    log(f"     removed {os.path.basename(t)}")
                    break
                except Exception as e:
                    log(f"     retry remove {os.path.basename(t)} ({attempt+1}): {e}")
                    time.sleep(2)
        except Exception as e:
            log(f"     clean fail {t}: {e}")

# 清理空临时目录
try:
    shutil.rmtree(empty_dir, ignore_errors=True)
except:
    pass

# 3) 修改spec输出到临时名字，避免任何已有目录锁
log("[3/5] Preparing spec (output to temp name)...")
spec_path = r"f:\Caelire\backend\御天.spec"
import datetime
stamp = datetime.datetime.now().strftime("%H%M%S")
temp_name = f"御天_pack{stamp}"
final_name = "御天"

with open(spec_path, "r", encoding="utf-8") as f:
    spec_txt = f.read()

# 只修改COLLECT段的name参数（最后一个name='xxx'）
# 使用正则：匹配coll = COLLECT( ... name='旧名', ... )
def set_collect_name(txt, new_name):
    # 找到coll = COLLECT( 到最后的 ) 之间的 name='xxx'
    idx = txt.find("coll = COLLECT(")
    if idx < 0:
        return txt
    # 从idx开始找最后一个 name='
    after = txt[idx:]
    new_after = re.sub(r"name='[^']+'", f"name='{new_name}'", after, count=1)
    return txt[:idx] + new_after

spec_orig = spec_txt
spec_tmp = set_collect_name(spec_txt, temp_name)
with open(spec_path, "w", encoding="utf-8") as f:
    f.write(spec_tmp)
log(f"     COLLECT name set to: {temp_name}")

# 4) 运行PyInstaller
log("[4/5] Running PyInstaller ... (this takes a few minutes)")
t0 = time.time()
proc = subprocess.Popen(
    [r"F:\Python314\python.exe", "-u", "-m", "PyInstaller", "御天.spec", "--clean", "--noconfirm"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    cwd=r"f:\Caelire\backend"
)

# 实时打印关键行
last_show = 0
for line in proc.stdout:
    line_s = line.rstrip()
    # 写入完整日志
    with open(LOG, "a", encoding="utf-8") as lf:
        lf.write(line)
    # 只打印阶段性关键信息
    if any(k in line_s for k in ["Building EXE", "Building COLLECT", "completed successfully",
                                   "ERROR", "FATAL", "Building PYZ", "Building PKG",
                                   "Looking for", "Warnings written", "copying bootloader",
                                   "checking EXE", "checking COLLECT", "Appending '"]):
        if time.time() - last_show > 0.5:
            log(f"     [pyi] {line_s[:200]}")
            last_show = time.time()

proc.wait()
elapsed = time.time() - t0
log(f"     PyInstaller exit code: {proc.returncode} ({elapsed:.0f}s)")

# 恢复spec
with open(spec_path, "w", encoding="utf-8") as f:
    f.write(spec_orig)
log("     spec restored.")

# 5) 把临时目录重命名为正式目录
log("[5/5] Finalizing output...")
temp_dir = rf"f:\Caelire\backend\dist\{temp_name}"
final_dir = rf"f:\Caelire\backend\dist\{final_name}"
exe_path = os.path.join(temp_dir, "御天.exe")
final_exe = os.path.join(final_dir, "御天.exe")

if proc.returncode != 0 or not os.path.isfile(exe_path):
    log("")
    log(f"=== BUILD FAILED ===")
    log(f"temp_dir exists: {os.path.exists(temp_dir)}")
    log(f"exe exists: {os.path.isfile(exe_path)}")
    log(f"Last 50 lines of log:")
    with open(LOG, "r", encoding="utf-8") as f:
        lines = f.readlines()
        for l in lines[-50:]:
            log("  " + l.rstrip())
    sys.exit(1)

# 删除旧的正式目录，把临时目录重命名过去
if os.path.exists(final_dir):
    log(f"     removing old final dir...")
    for attempt in range(8):
        try:
            shutil.rmtree(final_dir, ignore_errors=False)
            break
        except Exception as e:
            log(f"     retry remove final_dir ({attempt+1}): {e}")
            time.sleep(2)

log(f"     renaming {temp_name} -> {final_name} ...")
try:
    os.rename(temp_dir, final_dir)
except OSError:
    # 跨卷或锁问题，用move
    shutil.move(temp_dir, final_dir)

# 验证
if not os.path.isfile(final_exe):
    log("")
    log("=== RENAME FAILED ===")
    log(f"Final exe missing: {final_exe}")
    sys.exit(1)

size_mb = os.path.getsize(final_exe) / 1024 / 1024
file_count = sum(1 for _ in os.walk(final_dir) for _ in _[2])

# 验证agreement.html是最新版本（只保留协议正文，无倒计时/按钮逻辑）
agr_path = os.path.join(final_dir, "_internal", "frontend", "agreement.html")
has_deemed = False
if os.path.isfile(agr_path):
    with open(agr_path, "r", encoding="utf-8") as f:
        c = f.read()
    has_deemed = "用户协议与免责声明" in c and "COUNTDOWN_SECONDS" not in c and "btn-exit" not in c

log("")
log("=" * 50)
log("✅ BUILD SUCCESS")
log("=" * 50)
log(f"  Output dir : {final_dir}")
log(f"  Exe path   : {final_exe}")
log(f"  Exe size   : {size_mb:.2f} MB")
log(f"  File count : {file_count}")
log(f"  agreement.html updated: {'YES' if has_deemed else 'NO (check needed!)'}")
log("")
log(f"Done at {time.strftime('%Y-%m-%d %H:%M:%S')}")
sys.exit(0)
