import subprocess
import os
import sys
import datetime

log_path = r"F:\tmp\pyinstaller_build_py.log"
work_dir = r"F:\杀毒\backend"
spec_file = "御天.spec"
python_exe = r"F:\Python314\python.exe"

os.chdir(work_dir)
os.environ["TMP"] = r"F:\tmp"
os.environ["TEMP"] = r"F:\tmp"

with open(log_path, "w", encoding="utf-8") as log:
    log.write(f"=== 开始时间: {datetime.datetime.now()} ===\n")
    log.write(f"工作目录: {os.getcwd()}\n")
    log.write(f"TMP={os.environ.get('TMP')}\n")
    log.write(f"TEMP={os.environ.get('TEMP')}\n\n")
    
    log.write("--- Python 版本检查 ---\n")
    try:
        result = subprocess.run([python_exe, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace")
        log.write(f"stdout: {result.stdout}\n")
        log.write(f"stderr: {result.stderr}\n")
        log.write(f"returncode: {result.returncode}\n\n")
    except Exception as e:
        log.write(f"ERROR: {e}\n\n")
    
    log.write("--- PyInstaller 版本检查 ---\n")
    try:
        result = subprocess.run([python_exe, "-m", "PyInstaller", "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace")
        log.write(f"stdout: {result.stdout}\n")
        log.write(f"stderr: {result.stderr}\n")
        log.write(f"returncode: {result.returncode}\n\n")
    except Exception as e:
        log.write(f"ERROR: {e}\n\n")
    
    log.write("--- 开始 PyInstaller 打包 ---\n")
    log.flush()
    
    try:
        proc = subprocess.Popen(
            [python_exe, "-m", "PyInstaller", spec_file, "--clean", "--noconfirm"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1
        )
        for line in proc.stdout:
            log.write(line)
            log.flush()
        proc.wait()
        exit_code = proc.returncode
    except Exception as e:
        exit_code = -1
        log.write(f"ERROR: {e}\n")
    
    log.write(f"\n打包退出码: {exit_code}\n")
    log.write(f"=== 结束时间: {datetime.datetime.now()} ===\n")

sys.exit(exit_code)
