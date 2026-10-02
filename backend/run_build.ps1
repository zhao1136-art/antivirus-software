$ErrorActionPreference = "Continue"
$WorkingDir = "F:\杀毒\backend"
$LogFile = "F:\tmp\pyinstaller_full.log"

Set-Location $WorkingDir
$env:TMP = "F:\tmp"
$env:TEMP = "F:\tmp"

"=== 开始时间: $(Get-Date) ===" | Out-File -FilePath $LogFile -Encoding UTF8
"工作目录: $(Get-Location)" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"TMP=$env:TMP" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"TEMP=$env:TEMP" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"" | Out-File -FilePath $LogFile -Append -Encoding UTF8

"--- Python 版本检查 ---" | Out-File -FilePath $LogFile -Append -Encoding UTF8
& "F:\Python314\python.exe" --version 2>&1 | Out-File -FilePath $LogFile -Append -Encoding UTF8
"" | Out-File -FilePath $LogFile -Append -Encoding UTF8

"--- PyInstaller 版本检查 ---" | Out-File -FilePath $LogFile -Append -Encoding UTF8
& "F:\Python314\python.exe" -m PyInstaller --version 2>&1 | Out-File -FilePath $LogFile -Append -Encoding UTF8
"" | Out-File -FilePath $LogFile -Append -Encoding UTF8

"--- 开始 PyInstaller 打包 ---" | Out-File -FilePath $LogFile -Append -Encoding UTF8
& "F:\Python314\python.exe" -m PyInstaller 御天.spec --clean --noconfirm 2>&1 | Out-File -FilePath $LogFile -Append -Encoding UTF8
$ExitCode = $LASTEXITCODE
"" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"打包退出码: $ExitCode" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"=== 结束时间: $(Get-Date) ===" | Out-File -FilePath $LogFile -Append -Encoding UTF8

Exit $ExitCode
