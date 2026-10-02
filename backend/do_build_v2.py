import PyInstaller.__main__
import os, sys, shutil, time

work_dir = r"F:\Caelire\backend"
tmp_dir = r"F:\tmp"
os.chdir(work_dir)
os.environ["TMP"] = tmp_dir
os.environ["TEMP"] = tmp_dir

# 清理旧的构建目录
for d in ['dist', 'build']:
    p = os.path.join(work_dir, d)
    if os.path.exists(p):
        shutil.rmtree(p, ignore_errors=True)

# 记录日志
log_path = r"F:\tmp\build_v2_log.txt"
with open(log_path, "w", encoding="utf-8") as log:
    log.write(f"Start: {time.ctime()}\n")
    log.write(f"CWD: {os.getcwd()}\n")
    log.write(f"Spec: 御天.spec exists: {os.path.isfile('御天.spec')}\n")
    log.flush()

    try:
        PyInstaller.__main__.run([
            '御天.spec',
            '--clean',
            '--noconfirm',
            '--distpath', 'dist',
            '--workpath', 'build',
        ])
        log.write(f"Build success: {time.ctime()}\n")
    except Exception as e:
        log.write(f"Build failed: {e}\n")
        import traceback
        log.write(traceback.format_exc())

    log.write(f"End: {time.ctime()}\n")