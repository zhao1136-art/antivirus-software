<#
    还原「御天」exe 的内置浏览器补丁
    ================================
    把 _internal 下的目录联接换回真实目录（数据从 %LOCALAPPDATA%\Andun\runtime\exe\ 拷回）。

    用法：
        powershell -ExecutionPolicy Bypass -File 还原御天exe补丁.ps1
        powershell -ExecutionPolicy Bypass -File 还原御天exe补丁.ps1 -DistDir 'D:\御天'
#>
param(
    [string]$DistDir = 'H:\Caelire\backend\dist\御天',
    [switch]$KeepStaging          # 保留暂存区副本（默认保留）
)

$ErrorActionPreference = 'Stop'

$internal = Join-Path $DistDir '_internal'
if (-not (Test-Path -LiteralPath $internal)) { throw "找不到 _internal：$internal" }
$good = Join-Path $env:LOCALAPPDATA 'Andun\runtime\exe'

$targets = @('pythonnet\runtime', 'webview\lib')

foreach ($rel in $targets) {
    $src = Join-Path $internal $rel
    $dst = Join-Path $good     $rel

    Write-Host "=== $rel ==="
    if (-not (Test-Path -LiteralPath $src)) { Write-Warning "  不存在，跳过"; continue }

    $it = Get-Item -LiteralPath $src -Force
    if (-not $it.LinkType) { Write-Host "  本来就不是联接，跳过（幂等）"; continue }

    if (-not (Test-Path -LiteralPath $dst)) {
        throw "暂存副本不见了，无法还原：$dst"
    }

    Remove-Item -LiteralPath $src -Recurse -Force      # 删联接（不会删到目标）
    Copy-Item -LiteralPath $dst -Destination $src -Recurse -Force

    $a = Get-ChildItem -LiteralPath $src -Recurse -File | Measure-Object Length -Sum
    Write-Host "  已还原 $($a.Count) 个文件，$($a.Sum) 字节"
}

if (-not $KeepStaging) {
    Write-Host "删除暂存区：$good"
    Remove-Item -LiteralPath $good -Recurse -Force
}

Write-Host ""
Write-Host "已还原为未打补丁状态（内置浏览器将再次回退到系统默认浏览器）。"
