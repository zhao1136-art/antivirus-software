<#
    给已打包的「御天」exe 打"内置浏览器"补丁 —— 免重新打包
    =====================================================

    问题现象
    --------
    双击 dist\御天\御天.exe 后，界面在**系统默认浏览器**里打开（外置），
    而不是内嵌 WebView2 窗口。startup_traceback.txt 里能看到：

        RuntimeError: Failed to resolve Python.Runtime.Loader.Initialize
            from ...\_internal\pythonnet\runtime\Python.Runtime.dll
        FileLoadException: 未能加载 ...\webview\lib\Microsoft.Web.WebView2.Core.dll
            (HRESULT: 0x80131515)

    根因
    ----
    pywebview 的 Windows 内嵌后端依赖两份托管程序集：
        <pythonnet>\runtime\Python.Runtime.dll        (pythonnet.load() 第 140 行定位)
        <webview>\lib\Microsoft.Web.WebView2.Core.dll (webview/util.py 第 489 行定位)
    两者的路径都由 `__file__` 推导。实测：**只要这两个 DLL 的物理路径位于
    H:\Caelire\ 之下，.NET 的 Assembly.LoadFrom 就会失败**；同一份字节放在
    H:\ 根、C:\ 或 %LOCALAPPDATA% 下均正常。（对照实验：用 junction 指向
    H:\Caelire 内部 → 失败；同一目录改成复制 → 成功。故与内容无关，只与物理路径有关。）
    而打包产物恰好位于 H:\Caelire\backend\dist\，所以 exe 必然回退。

    修复思路
    --------
    把这两个目录搬到 %LOCALAPPDATA%\Andun\runtime\exe\ 下（好路径），
    再在原位建立**目录联接（Junction）**。.NET 会解析联接的真实路径，
    于是物理位置落在好路径上，内置浏览器即可正常加载。

    本脚本幂等：已打过补丁会跳过。

    用法
    ----
        powershell -ExecutionPolicy Bypass -File 给御天exe打补丁.ps1
        powershell -ExecutionPolicy Bypass -File 给御天exe打补丁.ps1 -DistDir 'D:\御天'

    回滚见同目录 还原御天exe补丁.ps1
#>
param(
    [string]$DistDir = 'H:\Caelire\backend\dist\御天'
)

$ErrorActionPreference = 'Stop'

$internal = Join-Path $DistDir '_internal'
if (-not (Test-Path -LiteralPath $internal)) {
    throw "找不到 _internal 目录：$internal（确认这是 PyInstaller onedir 产物）"
}

$good = Join-Path $env:LOCALAPPDATA 'Andun\runtime\exe'
$targets = @(
    @{ rel = 'pythonnet\runtime'; label = 'pythonnet\runtime (Python.Runtime.dll)' },
    @{ rel = 'webview\lib';       label = 'webview\lib (Microsoft.Web.WebView2.*.dll)' }
)

Write-Host "dist    : $DistDir"
Write-Host "暂存区  : $good"
Write-Host ""

foreach ($t in $targets) {
    $src = Join-Path $internal $t.rel
    $dst = Join-Path $good     $t.rel

    Write-Host "=== $($t.label) ==="

    if (-not (Test-Path -LiteralPath $src)) {
        Write-Warning "  源目录不存在，跳过：$src"
        continue
    }

    $it = Get-Item -LiteralPath $src -Force
    if ($it.LinkType) {
        Write-Host "  已是联接 -> $($it.Target -join ';')，跳过（幂等）"
        continue
    }

    # 1) 复制到好路径
    if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Recurse -Force }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
    Copy-Item -LiteralPath $src -Destination $dst -Recurse -Force

    # 2) 校验复制完整
    $a = Get-ChildItem -LiteralPath $src -Recurse -File | Measure-Object Length -Sum
    $b = Get-ChildItem -LiteralPath $dst -Recurse -File | Measure-Object Length -Sum
    if ($a.Count -ne $b.Count -or $a.Sum -ne $b.Sum) {
        throw "复制不完整：源 $($a.Count) 文件/$($a.Sum) 字节，副本 $($b.Count) 文件/$($b.Sum) 字节"
    }
    Write-Host "  已复制 $($b.Count) 个文件，$($b.Sum) 字节 -> $dst"

    # 3) 原位置换成联接
    Remove-Item -LiteralPath $src -Recurse -Force
    New-Item -ItemType Junction -Path $src -Target $dst | Out-Null

    $chk = Get-Item -LiteralPath $src -Force
    Write-Host "  已建立联接：LinkType=$($chk.LinkType) -> $($chk.Target -join ';')"
}

Write-Host ""
Write-Host "校验关键文件仍可达："
foreach ($f in @(
        (Join-Path $internal 'pythonnet\runtime\Python.Runtime.dll'),
        (Join-Path $internal 'webview\lib\Microsoft.Web.WebView2.Core.dll'))) {
    Write-Host ("  exists={0}  {1}" -f (Test-Path -LiteralPath $f), $f)
}

Write-Host ""
Write-Host "完成。现在直接双击 $DistDir\御天.exe 即可 —— 应弹出内嵌 WebView2 窗口。"
Write-Host "验证方法：任务管理器里应出现 msedgewebview2.exe 进程。"
