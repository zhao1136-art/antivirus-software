@echo off
chcp 65001 >nul
REM ============================================================
REM  matcher.dll 构建脚本
REM
REM  注意：不能用 `gcc -shared` 一步到位。
REM  本机环境下 gcc 的驱动进程无法派生 as/ld（管道受限），
REM  表现为「零输出、exit 1」。但 cc1 / as / ld 单独调用都正常，
REM  所以这里手工驱动三步：gcc -S  ->  as  ->  ld -shared
REM ============================================================
setlocal

set MINGW=F:\winlibs_mingw-16.1.0posix-14.0.0-ucrt-r3\mingw64
set GCC=%MINGW%\bin\gcc.exe
set AS=%MINGW%\bin\as.exe
set LD=%MINGW%\bin\ld.exe
set LIBS=%MINGW%\x86_64-w64-mingw32\lib
set SRC=%~dp0matcher.c
set OUT=%~dp0matcher.dll

if not exist "%GCC%" (
    echo [错误] 未找到 gcc: %GCC%
    exit /b 1
)

echo [1/3] gcc -S ...
"%GCC%" -S -O2 -I "%MINGW%\include" -o "%~dp0matcher.s" "%SRC%"
if errorlevel 1 ( echo [失败] 编译阶段 & exit /b 1 )

echo [2/3] as ...
"%AS%" "%~dp0matcher.s" -o "%~dp0matcher.o"
if errorlevel 1 ( echo [失败] 汇编阶段 & exit /b 1 )

echo [3/3] ld -shared ...
"%LD%" -shared -o "%OUT%" "%~dp0matcher.o" "%LIBS%\libmsvcrt.a" "%LIBS%\libkernel32.a" "%LIBS%\libmingw32.a"
if errorlevel 1 ( echo [失败] 链接阶段 & exit /b 1 )

del "%~dp0matcher.s" "%~dp0matcher.o" 2>nul
echo [完成] %OUT%
endlocal
