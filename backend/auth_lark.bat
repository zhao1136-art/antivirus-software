@echo off
lark-cli auth status --json --verify 2>&1
echo.
echo Exit code: %ERRORLEVEL%
pause
