@echo off
setlocal enabledelayedexpansion
set LOG=H:\Caelire\backend\FULL_PACK_LOG.txt

echo ============================================================ > "%LOG%"
echo YUTIAN PACK EXECUTION LOG >> "%LOG%"
echo Started: %DATE% %TIME% >> "%LOG%"
echo ============================================================ >> "%LOG%"
echo. >> "%LOG%"

echo --- Step 1: Set TMP and TEMP --- >> "%LOG%"
set TMP=H:\Caelire\backend\_tmp
set TEMP=H:\Caelire\backend\_tmp
echo TMP=%TMP% >> "%LOG%"
echo TEMP=%TEMP% >> "%LOG%"
if exist "%TMP%" (echo TMP dir exists: YES >> "%LOG%") else (echo TMP dir exists: NO >> "%LOG%")
echo. >> "%LOG%"

echo --- Step 2: Change directory --- >> "%LOG%"
cd /d "H:\Caelire\backend"
echo Current dir: %CD% >> "%LOG%"
echo. >> "%LOG%"

echo --- Step 3: Check spec file --- >> "%LOG%"
if exist "御天.spec" (
    echo Spec exists: YES >> "%LOG%"
    dir "御天.spec" >> "%LOG%"
) else (
    echo Spec exists: NO >> "%LOG%"
)
echo. >> "%LOG%"

echo --- Step 4: Check Python --- >> "%LOG%"
F:\Python314\python.exe --version >> "%LOG%" 2>&1
echo. >> "%LOG%"
echo PyInstaller version: >> "%LOG%"
F:\Python314\python.exe -m PyInstaller --version >> "%LOG%" 2>&1
echo. >> "%LOG%"

echo --- Step 5: RUN PYINSTALLER --- >> "%LOG%"
echo Start: %DATE% %TIME% >> "%LOG%"
echo. >> "%LOG%"
echo ================ PyInstaller OUTPUT ================ >> "%LOG%"

F:\Python314\python.exe -m PyInstaller 御天.spec --clean --noconfirm >> "%LOG%" 2>&1
set EXITCODE=%ERRORLEVEL%

echo ================ END PyInstaller OUTPUT ================ >> "%LOG%"
echo. >> "%LOG%"
echo End: %DATE% %TIME% >> "%LOG%"
echo PyInstaller Exit Code: %EXITCODE% >> "%LOG%"
echo. >> "%LOG%"

if "%EXITCODE%"=="0" (
    echo --- Step 6: LIST DIST DIRECTORY --- >> "%LOG%"
    echo dist dir exists: >> "%LOG%"
    if exist "dist" (
        echo YES >> "%LOG%"
        echo. >> "%LOG%"
        dir "dist" /s >> "%LOG%"
    ) else (
        echo NO >> "%LOG%"
    )
) else (
    echo Build FAILED with code %EXITCODE% >> "%LOG%"
)

echo. >> "%LOG%"
echo ============================================================ >> "%LOG%"
echo FINISHED: %DATE% %TIME% >> "%LOG%"
echo ============================================================ >> "%LOG%"

exit /b %EXITCODE%
