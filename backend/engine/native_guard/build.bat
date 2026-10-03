@echo off
REM ============================================================
REM  Build native_guard.dll
REM
REM  NOTE: keep this file ASCII-only. cmd.exe parses .bat in the
REM  OEM codepage (GBK here); UTF-8 Chinese comments get mangled
REM  into bogus commands and clobber the `set` lines.
REM
REM  Two traps vs the README command `g++ ... *.cpp`:
REM
REM  1) EXCLUDE amsi_provider.cpp
REM     It defines its own DllMain, which collides with the one in
REM     native_guard_main.cpp:
REM        multiple definition of `DllMain'
REM     It is built into the separate amsi_provider.dll instead.
REM
REM  2) Add -loleaut32 explicitly
REM     The sources use `#pragma comment(lib, "oleaut32.lib")`, but
REM     MinGW's g++ ignores MSVC pragma libs. Without it:
REM        undefined reference to `__imp_VariantInit' / `__imp_VariantClear'
REM     (All the other #pragma comment(lib, ...) in the headers are
REM      likewise no-ops under MinGW; the -l flags below cover them.)
REM ============================================================
setlocal

set MINGW=F:\winlibs_mingw-16.1.0posix-14.0.0-ucrt-r3\mingw64
set GXX=%MINGW%\bin\g++.exe

if not exist "%GXX%" (
    echo [ERROR] g++ not found: %GXX%
    exit /b 1
)

cd /d "%~dp0"

echo [BUILD] native_guard.dll ...
"%GXX%" -O2 -shared -o native_guard.dll ^
    native_guard_main.cpp etw_guard.cpp etw_rules.cpp inject_guard.cpp ^
    persist_guard.cpp fileless_guard.cpp net_guard.cpp file_guard.cpp ^
    -ladvapi32 -lws2_32 -liphlpapi -lpsapi -lole32 -loleaut32 -lshell32 ^
    -lwintrust -ldbghelp -lwbemuuid -lntdll -static-libgcc -static-libstdc++

if errorlevel 1 (
    echo [FAILED] compile or link error
    exit /b 1
)

echo [DONE] %~dp0native_guard.dll

echo.
echo To rebuild amsi_provider.dll separately:
echo   "%GXX%" -O2 -shared -o amsi_provider.dll amsi_provider.cpp -lole32 -loleaut32 -ladvapi32

endlocal
