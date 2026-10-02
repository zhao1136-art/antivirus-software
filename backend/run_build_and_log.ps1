$LogFile = "F:\tmp\build_output.txt"
$ErrorActionPreference = "Continue"
Set-Location "F:\Caelire\backend"
"Starting build at $(Get-Date)" | Out-File $LogFile -Encoding UTF8
$env:TMP = "F:\tmp"
$env:TEMP = "F:\tmp"
try {
    & "F:\Python314\python.exe" -m PyInstaller 御天.spec --clean --noconfirm 2>&1 | Out-File $LogFile -Append -Encoding UTF8
    $exitCode = $LASTEXITCODE
    "Exit code: $exitCode" | Out-File $LogFile -Append -Encoding UTF8
} catch {
    "Exception: $_" | Out-File $LogFile -Append -Encoding UTF8
}
"Build finished at $(Get-Date)" | Out-File $LogFile -Append -Encoding UTF8