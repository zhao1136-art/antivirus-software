@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo Andun Pack Script - Starting
echo ============================================================
echo.

echo --- Step 1: Set TMP and TEMP environment variables ---
set TMP=F:\tmp
set TEMP=F:\tmp
echo TMP  = %TMP%
echo TEMP = %TEMP%
if exist "%TMP%" (echo TMP dir exists: YES) else (echo TMP dir exists: NO)
echo.

echo --- Step 2: Change to work directory ---
cd /d "F:\杀毒\backend"
echo Current dir: %CD%
echo.

echo --- Step 3: Verify spec file ---
if exist "安盾.spec" (
    echo Spec exists: YES
    dir "安盾.spec" | findstr /R "安盾\.spec"
) else (
    echo Spec exists: NO
)
echo.

echo --- Step 4: Check Python and PyInstaller ---
echo Python path: F:\Python314\python.exe
if exist "F:\Python314\python.exe" (echo Python exists: YES) else (echo Python exists: NO)
F:\Python314\python.exe --version
echo.
echo PyInstaller version check:
F:\Python314\python.exe -m PyInstaller --version
echo.

echo --- Step 5: Run PyInstaller build ---
echo Start time: %date% %time%
echo Running PyInstaller...
echo ------------------------------------------------------------

F:\Python314\python.exe -m PyInstaller 安盾.spec --clean --noconfirm
set EXITCODE=%ERRORLEVEL%

echo ------------------------------------------------------------
echo End time: %date% %time%
echo PyInstaller exit code: %EXITCODE%
echo.

if "%EXITCODE%"=="0" (
    echo --- Step 6: List dist directory contents ---
    if exist "dist" (
        echo dist dir exists: YES
        echo dist dir path: %CD%\dist
        echo.
        echo dist directory recursive listing:
        echo ------------------------------------------------------------
        dir "dist" /s
        echo ------------------------------------------------------------
    ) else (
        echo dist dir exists: NO
    )
) else (
    echo Build FAILED with exit code: %EXITCODE%
)

echo.
echo ============================================================
echo Script finished
echo ============================================================

exit /b %EXITCODE%
