@echo off
setlocal
set "PY=F:\Python314\python.exe"
if exist "%PY%" goto :run

rem Fall back to PATH if the project interpreter is missing
where python >nul 2>nul
if errorlevel 1 goto :nopython
set "PY=python"

:run
echo Python: %PY%
"%PY%" -c "import sys;print('Python',sys.version.split()[0])"
if errorlevel 1 goto :nopython

echo.
echo Starting Yutian Tkinter UI ...
echo.
"%PY%" "%~dp0run_ui.py" %*
set "RC=%ERRORLEVEL%"

echo.
echo Exit code: %RC%
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
