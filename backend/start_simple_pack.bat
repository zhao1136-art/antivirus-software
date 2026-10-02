@echo off
set TMP=F:\tmp
set TEMP=F:\tmp
cd /d "F:\杀毒\backend"
echo %DATE% %TIME% - Starting pack > simple_pack_started.txt
start "AndunPack" /B /WAIT F:\Python314\python.exe simple_pack.py
echo %DATE% %TIME% - Finished pack, exit=%ERRORLEVEL% >> simple_pack_started.txt
exit /b %ERRORLEVEL%
