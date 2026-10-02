import os
import sys
import subprocess
import time

work_dir = r"F:\杀毒\backend"
tmp_dir = r"F:\tmp"
marker_file = os.path.join(work_dir, "pack_status.txt")

with open(marker_file, "w", encoding="utf-8") as mf:
    mf.write(f"STARTED\n")
    mf.write(f"time: {time.time()}\n")
    mf.flush()

    try:
        os.chdir(work_dir)
        os.environ["TMP"] = tmp_dir
        os.environ["TEMP"] = tmp_dir
        mf.write(f"env set: TMP={os.environ['TMP']}, TEMP={os.environ['TEMP']}\n")
        mf.write(f"cwd: {os.getcwd()}\n")

        cmd = [r"F:\Python314\python.exe", "-m", "PyInstaller", "御天.spec", "--clean", "--noconfirm"]
        mf.write(f"cmd: {' '.join(cmd)}\n")
        mf.flush()

        t0 = time.time()
        proc = subprocess.run(cmd, cwd=work_dir, env=os.environ.copy(), capture_output=True, text=True)
        t1 = time.time()

        mf.write(f"exit_code: {proc.returncode}\n")
        mf.write(f"duration: {t1-t0:.2f}s\n")
        mf.write(f"stdout:\n{proc.stdout[-5000:]}\n")
        mf.write(f"stderr:\n{proc.stderr[-5000:]}\n")

        if proc.returncode == 0:
            dist_dir = os.path.join(work_dir, "dist")
            mf.write(f"dist_exists: {os.path.isdir(dist_dir)}\n")
            if os.path.isdir(dist_dir):
                count = 0
                total_sz = 0
                for root, dirs, files in os.walk(dist_dir):
                    for d in dirs:
                        mf.write(f"DIR: {os.path.join(root, d)}\n")
                        count += 1
                    for f in files:
                        fp = os.path.join(root, f)
                        try:
                            sz = os.path.getsize(fp)
                        except:
                            sz = 0
                        total_sz += sz
                        mf.write(f"FILE: {fp} ({sz})\n")
                        count += 1
                mf.write(f"TOTAL_ITEMS: {count}\n")
                mf.write(f"TOTAL_SIZE: {total_sz}\n")
                mf.write(f"TOTAL_SIZE_MB: {total_sz/(1024*1024):.2f}\n")
    except Exception as e:
        mf.write(f"EXCEPTION: {e}\n")
        import traceback
        mf.write(f"TRACEBACK: {traceback.format_exc()}\n")

    mf.write(f"FINISHED\n")
    mf.write(f"time: {time.time()}\n")
