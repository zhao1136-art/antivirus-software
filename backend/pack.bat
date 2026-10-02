@echo off
cd /d F:\杀毒\backend
F:\Python314\python.exe -m PyInstaller "安盾.spec" --distpath "dist" --workpath "build" --noconfirm > pack_log.txt 2>&1
echo Exit code: %ERRORLEVEL% >> pack_log.txt
