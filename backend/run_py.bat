@echo off
cd /d F:\杀毒\backend
F:\Python314\python.exe -m PyInstaller 御天.spec --clean --noconfirm
exit /b %ERRORLEVEL%