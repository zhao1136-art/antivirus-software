"""
御天 启动项扫描模块
扫描注册表Run键、计划任务、启动文件夹、服务，排查持久化木马
"""
import os
try:
    import winreg
except ImportError:
    # 非 Windows 平台无 winreg 模块（如 Linux 部署）
    winreg = None
import subprocess
import csv
import io
from dataclasses import dataclass, field, asdict
from typing import Optional

@dataclass
class StartupEntry:
    source: str            # registry / scheduled_task / startup_folder / service
    name: str
    command: str
    location: str          # 具体路径
    publisher: str = ""    # 发布者/签名
    risk: str = "unknown"  # safe / suspicious / high
    risk_reason: str = ""

def _parse_schtasks_csv(text: str) -> list[dict]:
    """解析 schtasks /query /fo csv 输出"""
    reader = csv.DictReader(io.StringIO(text))
    return list(reader)

def _assess_risk(command: str, publisher: str, name: str) -> tuple[str, str]:
    """评估启动项风险等级"""
    # 有数字签名的通常是安全的
    if publisher and publisher != "N/A" and publisher != "未知":
        return "safe", ""
    
    cmd_lower = command.lower()
    name_lower = name.lower()
    
    # 高危特征
    high_keywords = [
        "powershell -enc", "powershell -e ", "powershell.exe -enc",
        "cmd.exe /c", "wscript", "cscript", "mshta", "rundll32",
        "regsvr32 /s", "certutil -decode", "bitsadmin",
        "schtasks /create", "sc\\ create", "sc \\create",
        "downloadstring", "frombase64string", "iex",
        "invoke-expression", "invoke-webrequest", "invoke-restmethod",
    ]
    for kw in high_keywords:
        if kw in cmd_lower:
            return "high", f"检测到高风险命令: {kw}"
    
    # 可疑特征
    suspicious_dirs = [
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
        "\\downloads\\", "\\public\\", "%temp%", "%tmp%",
        "\\users\\public\\",
    ]
    for d in suspicious_dirs:
        if d in cmd_lower:
            return "suspicious", f"程序位于可疑目录: {d}"
    
    suspicious_names = ["update", "helper", "service", "svc", "daemon", "agent"]
    # 无签名的 exe 在 Windows/System32 之外
    if cmd_lower.endswith(".exe") and "\\windows\\" not in cmd_lower and not publisher:
        return "suspicious", "无数字签名且位于非系统目录"
    
    return "unknown", ""


def scan_registry_run_keys() -> list[StartupEntry]:
    """扫描注册表 Run/RunOnce 键"""
    if winreg is None:
        # 非 Windows 平台无注册表，跳过
        return []
    entries = []
    hives = [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        (winreg.HKEY_CURRENT_USER, "HKCU"),
    ]
    subkeys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    
    for hive, hive_name in hives:
        for subkey in subkeys:
            try:
                key = winreg.OpenKey(hive, subkey)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        full_path = f"{hive_name}\\{subkey}\\{name}"
                        risk, reason = _assess_risk(value, "", name)
                        entries.append(StartupEntry(
                            source="registry",
                            name=name,
                            command=value,
                            location=full_path,
                            risk=risk,
                            risk_reason=reason,
                        ))
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                continue
    return entries


def scan_startup_folders() -> list[StartupEntry]:
    """扫描启动文件夹"""
    entries = []
    folders = [
        os.path.join(os.environ.get("APPDATA", ""),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.environ.get("PROGRAMDATA", ""),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.environ.get("ALLUSERSPROFILE", ""),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        try:
            for item in os.listdir(folder):
                full_path = os.path.join(folder, item)
                if item.endswith(".ini") or item == "desktop.ini":
                    continue
                target = full_path
                if item.endswith(".lnk"):
                    # 尝试解析 .lnk 快捷方式
                    target = _resolve_shortcut(full_path) or full_path
                risk, reason = _assess_risk(target, "", item)
                entries.append(StartupEntry(
                    source="startup_folder",
                    name=item,
                    command=target,
                    location=full_path,
                    risk=risk,
                    risk_reason=reason,
                ))
        except OSError:
            continue
    return entries


def _resolve_shortcut(lnk_path: str) -> Optional[str]:
    """解析 .lnk 快捷方式的目标路径"""
    try:
        import pythoncom
        from win32com.client import Dispatch
        pythoncom.CoInitialize()
        shell = Dispatch("WScript.Shell")
        shortcut = shell.CreateShortcut(lnk_path)
        return shortcut.TargetPath
    except Exception:
        # 简单手动解析
        try:
            with open(lnk_path, "rb") as f:
                data = f.read()
                if data[:4] == b"L\x00\x00\x00":
                    idx = data.find(b"\x00\x00\x00")
                    if idx > 0:
                        return data[4:idx].decode("utf-16-le", errors="ignore")
        except Exception:
            pass
    return None


def scan_scheduled_tasks() -> list[StartupEntry]:
    """扫描计划任务（开机自启类）"""
    entries = []
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/v", "/nh"],
            capture_output=True, text=True, encoding="gbk", errors="replace",
            timeout=30
        )
        if result.returncode != 0:
            return entries
        
        reader = csv.DictReader(io.StringIO(result.stdout.strip().replace('\x00', '')))
        for row in reader:
            task_name = row.get("TaskName", "").strip().strip('"').strip('\\')
            status = row.get("Status", "").strip()
            trigger = row.get("Scheduled Type", "").strip()
            command = row.get("Task To Run", "").strip()
            
            if not task_name or "\\" not in task_name:
                continue
            folder, name = task_name.rsplit("\\", 1)
            
            # 关注开机自启类任务
            boot_triggers = ["At startup", "At logon", "At system start", "One time"]
            is_boot = any(t.lower() in trigger.lower() for t in boot_triggers)
            
            if is_boot or status.lower() == "ready":
                location = f"Task Scheduler\\{task_name}"
                risk, reason = _assess_risk(command, "", name)
                entries.append(StartupEntry(
                    source="scheduled_task",
                    name=task_name,
                    command=command,
                    location=location,
                    risk=risk,
                    risk_reason=reason,
                ))
    except (subprocess.TimeoutExpired, Exception):
        pass
    return entries


def scan_services() -> list[StartupEntry]:
    """扫描自动启动的服务（非 Microsoft）"""
    entries = []
    try:
        result = subprocess.run(
            ["sc", "query", "state=", "all"],
            capture_output=True, text=True, encoding="gbk", errors="replace",
            timeout=20
        )
        lines = result.stdout.splitlines()
        service_names = []
        for line in lines:
            if "SERVICE_NAME" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    name = parts[1].strip().strip('"')
                    if name:
                        service_names.append(name)
    except Exception:
        return entries
    
    for svc_name in service_names:
        try:
            info = subprocess.run(
                ["sc", "qc", svc_name],
                capture_output=True, text=True, timeout=5, encoding="gbk", errors="replace"
            )
            out = info.stdout.lower()
            
            # 只关注自动启动的服务
            if "auto_start" not in out and "demand_start" not in out:
                continue
            
            # 提取 BINARY_PATH_NAME
            cmd = ""
            publisher = ""
            for line in info.stdout.splitlines():
                if "BINARY_PATH_NAME" in line.upper():
                    cmd = line.split(":", 1)[-1].strip().strip('"')
                    break
            
            if not cmd:
                continue
            
            risk, reason = _assess_risk(cmd, publisher, svc_name)
            entries.append(StartupEntry(
                source="service",
                name=svc_name,
                command=cmd,
                location=f"Service: {svc_name}",
                publisher=publisher,
                risk=risk,
                risk_reason=reason,
            ))
        except Exception:
            continue
    
    # 去重，只保留风险项和可疑项（减少噪声）
    return [e for e in entries if e.risk != "unknown"]


def scan_all() -> dict:
    """执行全部启动项扫描"""
    results = {
        "registry": [asdict(e) for e in scan_registry_run_keys()],
        "startup_folders": [asdict(e) for e in scan_startup_folders()],
        "scheduled_tasks": [asdict(e) for e in scan_scheduled_tasks()],
        "services": [asdict(e) for e in scan_services()],
    }
    
    # 统计
    total = sum(len(v) for v in results.values())
    high_risk = sum(1 for v in results.values() for e in v if e["risk"] == "high")
    suspicious = sum(1 for v in results.values() for e in v if e["risk"] == "suspicious")
    
    results["summary"] = {
        "total": total,
        "high_risk": high_risk,
        "suspicious": suspicious,
        "safe": total - high_risk - suspicious,
    }
    return results



