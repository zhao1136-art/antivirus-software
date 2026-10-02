import subprocess, sys, os
os.chdir(r"f:\Caelire\backend")
result = subprocess.run([r"F:\Python314\python.exe", "-m", "PyInstaller", "御天.spec", "--clean", "--noconfirm"], capture_output=True, text=True)
print(result.stdout)
if result.stderr:
    print("STDERR:", result.stderr)
print("Exit code:", result.returncode)
sys.exit(result.returncode)