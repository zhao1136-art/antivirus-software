@echo off
chcp 65001 >nul
echo === 安盾 引擎更新报告 - 飞书幻灯片生成 ===
echo.

set PYTHON="c:\Program Files\WindowsApps\PythonSoftwareFoundation.PythonManager_26.1.240.0_x64__3847v3x7pw1km\python.exe"

echo 正在逐页创建幻灯片...
echo 目标 PPT: M21NsZdfLlNz4kdrLmncvEmanTf
echo.

%PYTHON% "%~dp0create_slides.py"

echo.
echo === 完成 ===
echo 请在浏览器中打开: https://mcnec446sdot.feishu.cn/slides/M21NsZdfLlNz4kdrLmncvEmanTf
echo.
pause
