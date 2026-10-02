import os
import datetime

mark = r"F:\杀毒\backend\alive_test.txt"
with open(mark, "w", encoding="utf-8") as f:
    f.write("ALIVE at " + datetime.datetime.now().isoformat() + "\n")
    f.write("CWD=" + os.getcwd() + "\n")

    # 设置环境变量并运行PyInstaller的准备
    work_dir = r"F:\杀毒\backend"
    tmp_dir = r"F:\tmp"
    os.chdir(work_dir)
    os.environ["TMP"] = tmp_dir
    os.environ["TEMP"] = tmp_dir
    f.write("After setenv: TMP=" + os.environ.get("TMP", "?") + ", TEMP=" + os.environ.get("TEMP", "?") + "\n")
    f.write("CWD=" + os.getcwd() + "\n")

    import subprocess
    spec = "御天.spec"
    f.write("Spec exists? " + str(os.path.isfile(spec)) + "\n")

    t0 = datetime.datetime.now()
    f.write("Starting PyInstaller at " + t0.isoformat() + "\n")
    f.flush()

    proc = subprocess.run(
        [r"F:\Python314\python.exe", "-m", "PyInstaller", spec, "--clean", "--noconfirm"],
        cwd=work_dir,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=3600
    )

    t1 = datetime.datetime.now()
    dur = (t1 - t0).total_seconds()
    f.write("PyInstaller finished at " + t1.isoformat() + "\n")
    f.write("Duration: " + str(dur) + "s\n")
    f.write("Exit code: " + str(proc.returncode) + "\n")
    f.write("\n=== STDOUT last 8000 ===\n")
    f.write(proc.stdout[-8000:])
    f.write("\n=== STDERR last 8000 ===\n")
    f.write(proc.stderr[-8000:])
    f.write("\n=== END ===\n")

    if proc.returncode == 0:
        f.write("\n=== DIST CONTENTS ===\n")
        dist_dir = os.path.join(work_dir, "dist")
        if os.path.isdir(dist_dir):
            total_items = 0
            total_size = 0
            for root, dirs, files in os.walk(dist_dir):
                for d in dirs:
                    f.write("DIR: " + os.path.join(root, d) + "\n")
                    total_items += 1
                for fn in files:
                    fp = os.path.join(root, fn)
                    try:
                        sz = os.path.getsize(fp)
                    except:
                        sz = 0
                    total_size += sz
                    f.write("FILE: " + fp + " size=" + str(sz) + "\n")
                    total_items += 1
            f.write("\nTOTAL ITEMS: " + str(total_items) + "\n")
            f.write("TOTAL SIZE: " + str(total_size) + " bytes = " + str(round(total_size/(1024*1024), 2)) + " MB\n")
        else:
            f.write("DIST DIR NOT FOUND\n")

    f.write("\nDONE.\n")
