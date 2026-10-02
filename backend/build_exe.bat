@echo off
chcp 65001 >nul
echo 正在打包御天，请耐心等待...
cd /d "F:\杀毒\backend"
F:\Python314\python.exe -m PyInstaller 御天.spec --clean --noconfirm
echo.
echo 打包完成！
pause