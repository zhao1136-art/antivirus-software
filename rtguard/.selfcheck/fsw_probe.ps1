$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:TEMP ("fsw-probe-" + $PID)
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Write-Host "dir: $dir"

$script:fired = New-Object System.Collections.ArrayList
$fsw = New-Object System.IO.FileSystemWatcher
$fsw.Path = $dir
$fsw.IncludeSubdirectories = $true
$fsw.NotifyFilter = [System.IO.NotifyFilters]'FileName, DirectoryName, Attributes, Size, LastWrite, CreationTime, Security'
$fsw.InternalBufferSize = 65536
$fsw.EnableRaisingEvents = $true

foreach ($evt in @('Created','Changed','Deleted','Renamed')) {
    Register-ObjectEvent -InputObject $fsw -EventName $evt -Action {
        $null = $Event.MessageData.Add("$($Event.SourceEventArgs.ChangeType) $($Event.SourceEventArgs.FullPath)")
    } -MessageData $script:fired | Out-Null
}

Start-Sleep -Milliseconds 500
$a = Join-Path $dir 'a.txt'
$b = Join-Path $dir 'b.txt'
Set-Content -Path $a -Value 'hello'
Start-Sleep -Milliseconds 400
Add-Content -Path $a -Value 'more'
Start-Sleep -Milliseconds 400
Rename-Item -Path $a -NewName 'b.txt'
Start-Sleep -Milliseconds 400
Remove-Item -Path $b
Start-Sleep -Milliseconds 800

$fsw.EnableRaisingEvents = $false
Get-EventSubscriber | Unregister-Event
Start-Sleep -Milliseconds 300

Write-Host "=== events captured: $($script:fired.Count) ==="
$script:fired | ForEach-Object { Write-Host "  $_" }
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
