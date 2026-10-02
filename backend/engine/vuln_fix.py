"""
御天 系统漏洞修复模块（Vuln Fix）

对标 360 安全卫士 / 火绒 的漏洞扫描功能，本地最小实现：
  - scan():      枚举本机已安装的热修复补丁（注册表 HKLM-Hotfix），
                 与内置的“重大高危漏洞 CVE → 补丁 KB”清单比对，
                 输出缺失的高危补丁与当前补丁状态。
  - open_update():唤起 Windows 系统更新界面（usoclient / ms-settings），
                 不擅自下载安装补丁（补丁安装强依赖 Windows Update 服务与网络，
                 由系统正规渠道完成更安全可控）。
  - ignore/unignore: 对个别补丁“暂不提示”，避免反复告警，可持久化。

说明：修复采用“检测 + 引导系统更新”的安全路径，非内核、无需驱动。
"""
import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime

IS_WINDOWS = sys.platform == "win32"

DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
)
STATE_FILE = os.path.join(DATA_DIR, "vuln_fix.json")
LOG_FILE = os.path.join(DATA_DIR, "logs", "vuln_fix.log")

# 系统热修复注册表路径（不含末尾 key）
HOTFIX_ROOT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Hotfix"

# ─────────── 内置高危漏洞 → 补丁清单 ───────────
# kb 为 Windows 补丁编号；检测到缺失且未被忽略时列为风险项。
BUILTIN_KB = [
    {"kb": "KB4013389", "cve": "MS17-010", "desc": "远程代码执行（永恒之蓝/勒索蠕虫级）"},
    {"kb": "KB4012212", "cve": "MS17-010", "desc": "远程代码执行（永恒之蓝，Windows 8.1/2012 R2）"},
    {"kb": "KB3011780", "cve": "MS14-068", "desc": "Kerberos 权限提升（域控提权）"},
    {"kb": "KB4499175", "cve": "CVE-2019-0708", "desc": "远程桌面服务远程代码执行（蓝屏级 BlueKeep）"},
    {"kb": "KB5005399", "cve": "CVE-2021-40444", "desc": "MSHTML 远程代码执行（恶意 Office 文档）"},
    {"kb": "KB5014697", "cve": "CVE-2022-30190", "desc": "Microsoft 支持诊断工具 RCE（Follina）"},
    {"kb": "KB5023446", "cve": "CVE-2023-23397", "desc": "Outlook 权限提升（NTLM 中继）"},
    {"kb": "KB5004945", "cve": "CVE-2021-34527", "desc": "Windows 打印后台处理服务 RCE（PrintNightmare）"},
    {"kb": "KB5005033", "cve": "CVE-2021-36942", "desc": "AD DS 权限提升（PetitPotam NTLM 重放）"},
]


class VulnFix:
    """漏洞修复引擎（单实例，线程安全）"""

    def __init__(self):
        self._lock = threading.Lock()
        self._scan_time = None          # 最近一次扫描时间
        self._installed: set[str] = set()   # 本机已装 KB 集合
        self._missing: list[dict] = []      # 缺失风险项
        self._ignore: set[str] = set()      # 用户忽略的 KB
        self._last_report: dict = {}
        os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)
        self._load_state()

    # ── 基础工具 ─────────────────────────────────────────────
    def _log(self, msg: str):
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}\n")
        except Exception:
            pass

    def _load_state(self):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                st = json.load(f)
            self._ignore = set(st.get("ignore", []))
        except Exception:
            pass

    def _save_state(self):
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump({"ignore": sorted(self._ignore)}, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # ── 扫描 ─────────────────────────────────────────────────
    def _read_installed_hotfixes(self) -> set[str]:
        """从注册表枚举已安装热修复补丁的 KB 编号"""
        installed: set[str] = set()
        if not IS_WINDOWS:
            return installed
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, HOTFIX_ROOT) as key:
                count, _, _ = winreg.QueryInfoKey(key)
                for i in range(count):
                    name = winreg.EnumKey(key, i)
                    if name and name.lower().startswith("kb"):
                        installed.add(name.upper())
        except OSError:
            pass
        except Exception:
            pass
        return installed

    def _scan_builtin(self, installed: set[str], ignored: set[str]) -> list[dict]:
        """对比内置清单，返回缺失且未忽略的风险项"""
        missing = []
        for item in BUILTIN_KB:
            kb = item["kb"]  # 形如 KB4013389
            kb_raw = kb[2:]  # 4013389
            hit = (kb in installed or kb_raw in installed or
                   any(kb_raw in k for k in installed))
            if not hit and kb not in ignored:
                missing.append({
                    **item,
                    "installed": False,
                    "missing": True,
                })
        return missing

    def scan(self, force: bool = True) -> dict:
        """执行漏洞扫描，返回报告"""
        with self._lock:
            installed = self._read_installed_hotfixes()
            missing = self._scan_builtin(installed, self._ignore)

        self._installed = installed
        self._missing = missing
        self._scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report = {
            "scan_time": self._scan_time,
            "installed_count": len(installed),
            "checked_kb": len(BUILTIN_KB),
            "missing_count": len(missing),
            "ignored_count": len(self._ignore),
            "critical_missing": [m["kb"] for m in missing if m.get("cve")],
            "missing": missing,
            "all_patched": len(missing) == 0,
        }
        self._last_report = report
        self._log(f"漏洞扫描完成: 已装 {len(installed)} 个补丁, 缺失高危 {len(missing)} 项")
        return report

    # ── 修复/引导 ────────────────────────────────────────────
    def open_windows_update(self) -> dict:
        """
        唤起系统更新界面。不擅自下载安装补丁。
        返回启动结果（是否成功、提示信息）。
        """
        if not IS_WINDOWS:
            return {"ok": False, "msg": "非 Windows 环境"}
        # 优先用系统设置页命令（Win10/11 均支持 ms-settings:windowsupdate）
        try:
            subprocess.Popen(
                ["cmd", "/c", "start", "", "ms-settings:windowsupdate"],
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self._log("已唤起系统更新设置页")
            return {"ok": True, "msg": "已打开系统更新设置，请在窗口中检查并安装更新", "via": "settings"}
        except Exception as e:
            return {"ok": False, "msg": f"无法打开系统更新: {e}"}

    # ── 忽略管理 ─────────────────────────────────────────────
    def ignore(self, kb: str) -> bool:
        kb = kb.upper()
        with self._lock:
            self._ignore.add(kb)
            self._save_state()
        self._log(f"忽略补丁 {kb}")
        return True

    def unignore(self, kb: str) -> bool:
        kb = kb.upper()
        with self._lock:
            self._ignore.discard(kb)
            self._save_state()
        return True

    # ── 状态 ─────────────────────────────────────────────────
    def get_status(self) -> dict:
        with self._lock:
            report = dict(self._last_report)
            report.setdefault("missing", [])
            report["ignored"] = sorted(self._ignore)
        return report


# ── 单例 ─────────────────────────────────────────────────
_global: VulnFix | None = None


def get_vuln_fix() -> VulnFix:
    global _global
    if _global is None:
        _global = VulnFix()
    return _global