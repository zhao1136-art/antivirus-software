@echo off
chcp 65001 >nul
echo ========================================
echo   安盾 Native Engine - Compile Script
echo ========================================
echo.

set "MINGW_ROOT=F:\winlibs_mingw-16.1.0posix-14.0.0-ucrt-r3"
set "MINGW_BIN=%MINGW_ROOT%\mingw64\bin"

if not exist "%MINGW_BIN%\gcc.exe" (
    echo [ERROR] MinGW not found: %MINGW_BIN%\gcc.exe
    echo Please extract MinGW .7z file first.
    pause
    exit /b 1
)

set "PATH=%MINGW_BIN%;%PATH%"
cd /d "%~dp0src"

echo [1/2] Compiling native_engine.exe...
gcc -O2 -o ..\native_engine.exe native_engine_pure.c ^
    -ladvapi32 -lws2_32 -liphlpapi -lpsapi -lole32 -static -lm

if %errorlevel% neq 0 (
    echo [FAIL] EXE build failed
    pause
    exit /b 1
)

echo [2/2] Compiling native_engine.dll (optional)...
gcc -O2 -shared -o ..\native_engine.dll native_engine_pure.c ^
    -ladvapi32 -lws2_32 -liphlpapi -lpsapi -lole32 -lm

echo.
echo ========================================
echo   Build complete!
echo   EXE: native_engine.exe
echo   DLL: native_engine.dll (optional)
echo ========================================
echo.
echo Usage: native_engine.exe ^<cmd^> [args...]
echo Commands: version selftest sha256 peparse heuristic
echo           processes startup network sysinfo qmove qlist
echo.
pause
