import subprocess, os, sys
os.chdir(r"f:\Caelire\backend")
cmd = r'"F:\Python314\python.exe" -m PyInstaller 御天.spec --clean --noconfirm'
print(f"开始: {cmd}")
result = subprocess.run(cmd, shell=True, capture_output=False, text=True)
print(f"\n返回码: {result.returncode}")
sys.exit(result.returncode)