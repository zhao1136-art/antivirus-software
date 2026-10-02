@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

cd /d "F:\Caelire\backend"
set LOGFILE=_pack_final.log
if exist %LOGFILE% del /f /q %LOGFILE%
if exist _pack_SUCCESS.flag del /f /q _pack_SUCCESS.flag
if exist _pack_FAILED.flag  del /f /q _pack_FAILED.flag

echo === 御天 Package Rebuild ===
echo.

echo [1/5] Killing processes...
taskkill /F /IM "御天.exe"          >nul 2>&1
taskkill /F /IM file_guard.exe     >nul 2>&1
taskkill /F /T /IM python.exe      >nul 2>&1
taskkill /F /T /IM pythonw.exe     >nul 2>&1
ping 127.0.0.1 -n 4 >nul
echo        done.

echo [2/5] Removing old outputs...
attrib -R -S -H /S /D "dist\御天\*"    >nul 2>&1
attrib -R -S -H /S /D "dist\御天_build\*" >nul 2>&1
attrib -R -S -H /S /D "dist\御天2\*"   >nul 2>&1
attrib -R -S -H /S /D "build\御天\*"   >nul 2>&1
rmdir /s /q "dist\御天"                >nul 2>&1
rmdir /s /q "dist\御天_build"          >nul 2>&1
rmdir /s /q "dist\御天2"               >nul 2>&1
rmdir /s /q "build\御天"               >nul 2>&1
ping 127.0.0.1 -n 3 >nul
echo        done.

echo [3/5] Running PyInstaller (this may take several minutes)...
F:\Python314\python.exe -u -m PyInstaller 御天.spec --clean --noconfirm >> %LOGFILE% 2>&1
set EC=%ERRORLEVEL%
echo        PyInstaller exit code: %EC%

echo [4/5] Verifying...
set EXE=dist\御天\御天.exe
if exist "%EXE%" (
    dir "%EXE%"
    echo.
    echo === SUCCESS ===
    echo Output dir: %CD%\dist\御天\
    echo Exe:        %CD%\%EXE%
    echo SUCCESS > _pack_SUCCESS.flag
    exit /b 0
) else (
    echo.
    echo === FAILED ===
    echo Exe not found. Last lines of %LOGFILE%:
    echo.
    echo ----- log tail -----
    if exist %LOGFILE% more +0 %LOGFILE% | findstr /n "." | findstr /b ".*:" >nul
    for /f "delims=" %%L in ('type "%LOGFILE%"') do set "LASTLINE=%%L"
    rem Just show log by calling type with a pipe to more-style tail via sort trick isn't easy.
    rem  Just dump the full log -- it's small after a failure.
    type "%LOGFILE%"
    echo FAILED > _pack_FAILED.flag
    exit /b 1
)
endlocal