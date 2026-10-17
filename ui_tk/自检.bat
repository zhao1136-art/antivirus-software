@echo off
setlocal
set "PY=F:\Python314\python.exe"
if exist "%PY%" goto :run

where python >nul 2>nul
if errorlevel 1 goto :nopython
set "PY=python"

:run
echo ==========================================
echo  Yutian Tkinter UI - self test (no window)
echo ==========================================
echo Python: %PY%
echo.

"%PY%" "%~dp0run_ui.py" --self-test
set "RC=%ERRORLEVEL%"

echo.
echo ==========================================
if "%RC%"=="0" echo  RESULT: PASS
if not "%RC%"=="0" echo  RESULT: FAIL  rc=%RC%
echo ==========================================
echo.
pause
exit /b %RC%

:nopython
echo.
echo [ERROR] Python not found.
echo         Expected: F:\Python314\python.exe
echo         Or put python.exe on PATH.
echo.
pause
exit /b 1
