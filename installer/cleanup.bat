@echo off
chcp 65001 >nul
echo ============================================
echo   御天（安盾）卸载残留清理脚本
echo ============================================
echo.

:: ── 0. 提权检查 ──
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 需要管理员权限，请以管理员身份运行此脚本。
    echo 右键 cleanup.bat → 以管理员身份运行
    pause
    exit /b 1
)

echo [信息] 正在停止相关服务...
sc stop AndunDriver 2>nul
sc stop AndunAgent 2>nul
timeout /t 2 /nobreak >nul

:: ── 1. 清理注册表残留 ──
echo [1/4] 清理注册表残留...
reg delete "HKLM\System\CurrentControlSet\Services\AndunDriver" /f 2>nul
reg delete "HKLM\System\CurrentControlSet\Services\AndunAgent" /f 2>nul
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "AndunAgent" /f 2>nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "ANDUN_DRIVER_LOADED" /f 2>nul

:: ── 2. 清理 Minifilter 实例残留 ──
echo [2/4] 清理 Minifilter 实例...
fltmc unload AndunFlt 2>nul
:: 如果 fltmc 无法卸载（驱动已不在），使用注册表清理
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\AndunFlt" /f 2>nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{ 4d36e96f-e325-11ce-bfc1-08002be10318}" /v "UpperFilters" /f 2>nul

:: ── 3. 清理映射文件和程序数据残留 ──
echo [3/4] 清理程序数据残留...
:: 数据目录当前以 %LOCALAPPDATA%\Andun 为准（与运行时一致）；
:: 旧版本曾用 %ProgramData%\Andun，一并清理兜底
set "LOCALDATA_DIR=%LOCALAPPDATA%\Andun"
if exist "%LOCALDATA_DIR%" (
    echo   删除 %LOCALDATA_DIR%
    rmdir /s /q "%LOCALDATA_DIR%" 2>nul
)
set "PROGRAMDATA_DIR=%ProgramData%\Andun"
if exist "%PROGRAMDATA_DIR%" (
    echo   删除 %PROGRAMDATA_DIR% ^(旧版本残留^)
    rmdir /s /q "%PROGRAMDATA_DIR%" 2>nul
)

:: 清理事件缓冲和审计日志映射文件
set "MAPPED_FILES=%LOCALAPPDATA%\Andun\etw_buffer.bin"
set "AUDIT_LOG=%LOCALAPPDATA%\Andun\audit.log"
if exist "%MAPPED_FILES%" del /f /q "%MAPPED_FILES%" 2>nul
if exist "%AUDIT_LOG%" del /f /q "%AUDIT_LOG%" 2>nul

:: 清理可能的驱动文件残留
if exist "%SystemRoot%\System32\drivers\andun.sys" (
    echo   删除 %SystemRoot%\System32\drivers\andun.sys
    del /f /q "%SystemRoot%\System32\drivers\andun.sys" 2>nul
)
if exist "%SystemRoot%\System32\drivers\andun_flt.sys" (
    del /f /q "%SystemRoot%\System32\drivers\andun_flt.sys" 2>nul
)

:: ── 4. 清理 WFP 网络过滤残留 ──
echo [4/4] 清理 WFP 网络过滤提供者...
:: 使用 netsh 清理 WFP 残留（如果残留）
netsh wfp show filters 2>nul | findstr /i "Andun" >nul
if not errorlevel 1 (
    echo   检测到 WFP 残留过滤器，重启后会自动清除
)

echo.
echo ============================================
echo   清理完成！建议重启系统以确保完全清除。
echo ============================================
echo.
echo 提示：如果驱动仍在运行，请先在设备管理器中卸载驱动，或执行：
echo   sc delete AndunDriver
echo   然后重启系统。
echo.
pause