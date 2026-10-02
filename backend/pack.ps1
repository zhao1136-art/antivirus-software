Set-Location "F:\杀毒\backend"
& F:\Python314\python.exe -m PyInstaller "御天.spec" --distpath "dist" --workpath "build" --noconfirm *>&1 | Tee-Object -FilePath "pack_log.txt"
Write-Output "Exit code: $LASTEXITCODE"
