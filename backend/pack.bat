@echo off
cd /d H:\Caelire\backend
F:\Python314\python.exe -m PyInstaller "御天.spec" --distpath "dist" --workpath "build" --noconfirm > pack_log.txt 2>&1
echo Exit code: %ERRORLEVEL% >> pack_log.txt
