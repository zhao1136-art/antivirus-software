import os
import sys
import subprocess
from datetime import datetime

work_dir = r"F:\杀毒\backend"
tmp_dir = r"F:\tmp"
python_exe = r"F:\Python314\python.exe"
spec_file = "安盾.spec"
log_file = os.path.join(work_dir, "pack_execution.log")

os.chdir(work_dir)

with open(log_file, "w", encoding="utf-8") as log:
    def writeln(msg=""):
        print(msg)
        log.write(msg + "\n")
        log.flush()

    writeln("=" * 60)
    writeln("Yutian Pack Execution Log")
    writeln("=" * 60)
    writeln()

    writeln("--- Step 1: Set TMP and TEMP environment variables ---")
    os.environ["TMP"] = tmp_dir
    os.environ["TEMP"] = tmp_dir
    writeln(f"TMP  = {os.environ.get('TMP')}")
    writeln(f"TEMP = {os.environ.get('TEMP')}")
    writeln(f"TMP dir exists: {os.path.isdir(tmp_dir)}")
    writeln()

    writeln("--- Step 2: Change to work directory ---")
    writeln(f"Current dir: {os.getcwd()}")
    writeln(f"Work dir exists: {os.path.isdir(work_dir)}")
    writeln()

    writeln("--- Step 3: Verify spec file ---")
    spec_path = os.path.join(work_dir, spec_file)
    writeln(f"Spec path: {spec_path}")
    writeln(f"Spec exists: {os.path.isfile(spec_path)}")
    if os.path.isfile(spec_path):
        stat = os.stat(spec_path)
        writeln(f"Spec size: {stat.st_size} bytes")
        writeln(f"Spec modified: {datetime.fromtimestamp(stat.st_mtime)}")
    writeln()

    writeln("--- Step 4: Check Python and PyInstaller ---")
    writeln(f"Python exe: {python_exe}")
    writeln(f"Python exists: {os.path.isfile(python_exe)}")
    try:
        r = subprocess.run([python_exe, "--version"], capture_output=True, text=True, cwd=work_dir)
        writeln(f"Python version: {r.stdout.strip()}{r.stderr.strip()}")
    except Exception as e:
        writeln(f"Python version check error: {e}")
    try:
        r = subprocess.run([python_exe, "-m", "PyInstaller", "--version"], capture_output=True, text=True, cwd=work_dir)
        writeln(f"PyInstaller version: {r.stdout.strip()}{r.stderr.strip()}")
    except Exception as e:
        writeln(f"PyInstaller version check error: {e}")
    writeln()

    writeln("--- Step 5: Run PyInstaller build ---")
    start_time = datetime.now()
    writeln(f"Start time: {start_time}")
    writeln(f"Command: {python_exe} -m PyInstaller {spec_file} --clean --noconfirm")
    writeln("-" * 60)
    log.flush()

    proc = subprocess.Popen(
        [python_exe, "-m", "PyInstaller", spec_file, "--clean", "--noconfirm"],
        cwd=work_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        universal_newlines=True,
        env={**os.environ}
    )

    for line in proc.stdout:
        line = line.rstrip()
        if line:
            print(line)
            log.write(line + "\n")
            log.flush()

    proc.wait()
    exit_code = proc.returncode
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    writeln("-" * 60)
    writeln(f"End time: {end_time}")
    writeln(f"Duration: {duration:.2f} seconds")
    writeln(f"PyInstaller exit code: {exit_code}")
    writeln()

    if exit_code == 0:
        writeln("--- Step 6: List dist directory contents ---")
        dist_dir = os.path.join(work_dir, "dist")
        writeln(f"dist dir: {dist_dir}")
        writeln(f"dist exists: {os.path.isdir(dist_dir)}")
        writeln()

        item_count = 0
        total_size = 0
        if os.path.isdir(dist_dir):
            for root, dirs, files in os.walk(dist_dir):
                for d in dirs:
                    full = os.path.join(root, d)
                    writeln(f"[DIR ]        <DIR>  {full}")
                    item_count += 1
                for f in files:
                    full = os.path.join(root, f)
                    try:
                        sz = os.path.getsize(full)
                    except:
                        sz = 0
                    total_size += sz
                    writeln(f"[FILE] {sz:>12}  {full}")
                    item_count += 1

            writeln()
            writeln(f"Summary:")
            writeln(f"  Total items: {item_count}")
            writeln(f"  Total size:  {total_size} bytes ({total_size / (1024*1024):.2f} MB)")

            exe_path = os.path.join(dist_dir, "安盾", "安盾.exe")
            if os.path.isfile(exe_path):
                exe_sz = os.path.getsize(exe_path)
                writeln(f"  Main EXE:    {exe_path}")
                writeln(f"  EXE size:    {exe_sz} bytes ({exe_sz / (1024*1024):.2f} MB)")
            else:
                onefile_exe = os.path.join(dist_dir, "御天.exe")
                if os.path.isfile(onefile_exe):
                    exe_sz = os.path.getsize(onefile_exe)
                    writeln(f"  Main EXE:    {onefile_exe}")
                    writeln(f"  EXE size:    {exe_sz} bytes ({exe_sz / (1024*1024):.2f} MB)")
    else:
        writeln(f"Build FAILED with exit code: {exit_code}")

    writeln()
    writeln("=" * 60)
    writeln("Pack execution finished")
    writeln("=" * 60)

sys.exit(exit_code)
