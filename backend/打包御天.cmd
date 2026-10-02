@echo off
REM ============================================================
REM   御天杀毒软件 — Guardian AI 集成版 打包命令 (CMD)
REM   一键执行：双击或 cmd 中运行  打包御天.cmd
REM ============================================================
chcp 65001 >nul
title 御天 — 打包 (Guardian CNN v1.0 集成)

setlocal
set PYTHON=F:\Python314\python.exe
set PIP=F:\Python314\Scripts\pip.exe
set WORKDIR=F:\Caelire\backend

echo.
echo ============================================================
echo   御天杀毒软件 — Guardian AI 集成版 打包
echo   Python:  %PYTHON%
echo   Workdir: %WORKDIR%
echo ============================================================
echo.

REM ── 1. 检查 AI 模型文件是否存在（必检）──
if NOT EXIST "F:\Caelire\ai_guardian\checkpoints\guardian_cnn_v1.pth" (
    echo [错误] 找不到 AI 模型文件: F:\Caelire\ai_guardian\checkpoints\guardian_cnn_v1.pth
    echo        请先确认模型已下载到该路径！
    pause
    exit /b 1
)
echo [1/6] AI 模型检查 OK

REM ── 2. 检查病毒库 ──
if NOT EXIST "F:\Caelire\bingduku\virus.dat" (
    echo [警告] 找不到 bingduku\virus.dat，打包时病毒库可能缺失
) else (
    echo [2/6] 病毒库检查 OK
)

REM ── 3. 检查 torch / torchvision / Pillow ──
"%PYTHON%" -c "import torch, torchvision, PIL" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [警告] torch/torchvision/Pillow 未完整安装，AI 引擎将降级为规则模式
    echo [3/6] AI 依赖检查 — 部分缺失
) else (
    echo [3/6] AI 依赖检查 OK (torch + torchvision + Pillow)
)

REM ── 4. 确保 PyInstaller 已安装 ──
"%PIP%" show pyinstaller >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [4/6] 正在安装 PyInstaller ...
    "%PIP%" install pyinstaller==6.21.0 -i https://pypi.tuna.tsinghua.edu.cn/simple
) else (
    echo [4/6] PyInstaller 已安装
)

REM ── 5. 杀死可能占用文件的进程 ──
echo [5/6] 清理旧进程（御天.exe / file_guard.exe / native_engine.exe）...
taskkill /F /IM 御天.exe       >nul 2>nul
taskkill /F /IM file_guard.exe >nul 2>nul
taskkill /F /IM native_engine.exe >nul 2>nul

REM ── 6. 清理旧的 build / dist 输出 ──
echo [6/6] 清理旧的 build/dist 输出 ...
if EXIST "%WORKDIR%\build\御天"  rmdir /S /Q "%WORKDIR%\build\御天"
if EXIST "%WORKDIR%\dist\御天"   rmdir /S /Q "%WORKDIR%\dist\御天"

echo.
echo ============================================================
echo   开始 PyInstaller 打包 (one-dir 模式)
echo   预计耗时 3~8 分钟 ...
echo ============================================================
echo.

cd /d "%WORKDIR%"
"%PYTHON%" -m PyInstaller --clean --noconfirm 御天_onedir.spec
set EXIT_CODE=%ERRORLEVEL%

echo.
echo ============================================================
if %EXIT_CODE% EQU 0 (
    echo   ✅ 打包成功！
    echo   输出目录: %WORKDIR%\dist\御天\
    echo   主程序:   %WORKDIR%\dist\御天\御天.exe
) else (
    echo   ❌ 打包失败，错误码: %EXIT_CODE%
    echo   请检查上方日志或查看 dist\build 中的 warn-御天.txt
)
echo ============================================================
endlocal
pause
