import subprocess
import os

os.chdir(r"F:\杀毒\backend")
r = subprocess.run(
    [r"F:\Python314\python.exe", "-m", "PyInstaller",
     r"御天.spec",
     "--distpath", "dist",
     "--workpath", "build",
     "--noconfirm"],
    capture_output=True, text=True, encoding="utf-8", errors="replace"
)

with open(r"F:\杀毒\backend\pack_result.txt", "w", encoding="utf-8") as f:
    f.write(f"Exit: {r.returncode}\n\n")
    f.write("=== STDOUT (last 3000) ===\n")
    f.write(r.stdout[-3000:] if r.stdout else "(empty)\n")
    f.write("\n=== STDERR (last 3000) ===\n")
    f.write(r.stderr[-3000:] if r.stderr else "(empty)\n")

print(f"Done. Exit: {r.returncode}")
