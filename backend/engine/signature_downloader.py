"""
病毒库下载器 - 从多个免费威胁情报平台下载恶意软件特征
支持: ESET IOC, URLhaus, PhishTank, Blocklist.de
"""
import os
import time
import json
import hashlib
import requests
from engine.signature_manager import SignatureManager

# ── 免费数据源（无需认证）─────────────────────
SOURCES = {
    "eset": {
        "name": "ESET malware-ioc",
        "url": "https://api.github.com/repos/eset/malware-ioc/contents/",
        "type": "sha256",
        "desc": "ESET 官方恶意软件 IOC 仓库，148+ 家族"
    },
    "blocklist": {
        "name": "Blocklist.de",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "type": "ip",
        "desc": "全球 fail2ban 服务器报告的恶意 IP（25,000+ 条）"
    },
}

UA = "AnDun-Antivirus/1.0"


class SignatureDownloader:
    """多源病毒特征库下载与导入"""

    def __init__(self, sig_mgr: SignatureManager = None):
        self.sig_mgr = sig_mgr or SignatureManager()
        self._status = {"downloading": False, "progress": 0, "total": 0,
                        "imported": 0, "errors": [], "current_source": ""}

    @property
    def status(self) -> dict:
        return dict(self._status)

    def download_and_import(self, source: str = "all", limit: int = 5000) -> dict:
        """
        下载并导入病毒特征库
        source: "all" | "eset" | "urlhaus" | "phishtank" | "blocklist"
        """
        self._status = {"downloading": True, "progress": 0, "total": 0,
                        "imported": 0, "errors": [], "current_source": ""}

        if source == "all":
            sources_to_run = list(SOURCES.keys())
        elif source in SOURCES:
            sources_to_run = [source]
        else:
            self._status["downloading"] = False
            self._status["errors"].append(f"未知数据源: {source}")
            return {"error": f"未知数据源: {source}"}

        total_imported = 0
        total_errors = []

        for src_key in sources_to_run:
            self._status["current_source"] = SOURCES[src_key]["name"]
            try:
                per_source_limit = max(100, limit // len(sources_to_run))
                result = self._download_source(src_key, per_source_limit)
                total_imported += result.get("imported", 0)
                if result.get("error"):
                    total_errors.append(f"{SOURCES[src_key]['name']}: {result['error']}")
            except Exception as e:
                total_errors.append(f"{SOURCES[src_key]['name']}: {str(e)}")

        self._status["downloading"] = False
        self._status["imported"] = total_imported
        self._status["errors"] = total_errors[:10]  # 最多保留10条错误
        self._status["current_source"] = "完成"

        return {
            "sources": len(sources_to_run),
            "imported": total_imported,
            "errors": len(total_errors),
            "error_details": total_errors[:5]
        }

    def _download_source(self, src_key: str, limit: int) -> dict:
        """下载单个数据源"""
        if src_key == "eset":
            return self._import_eset(limit)
        elif src_key == "blocklist":
            return self._import_blocklist(limit)
        return {"error": "未知源"}

    # ── ESET malware-ioc (GitHub) ──────────────────

    def _import_eset(self, limit: int) -> dict:
        """从 ESET GitHub 仓库导入 SHA256 哈希"""
        imported = 0
        try:
            resp = requests.get(SOURCES["eset"]["url"],
                              headers={"User-Agent": UA}, timeout=30)
            if resp.status_code != 200:
                return {"error": f"GitHub API 返回 {resp.status_code}"}

            dirs = [d["name"] for d in resp.json() if d.get("type") == "dir"]
            self._status["total"] = min(len(dirs), 30)

            for i, folder in enumerate(dirs[:30]):
                sha_url = f"https://raw.githubusercontent.com/eset/malware-ioc/master/{folder}/samples.sha256"
                try:
                    sr = requests.get(sha_url, headers={"User-Agent": UA}, timeout=15)
                    if sr.status_code != 200:
                        continue
                    for line in sr.text.split("\n"):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if parts and len(parts[0]) == 64:
                            self.sig_mgr.add_signature(
                                "sha256", parts[0].lower(), f"{folder}.malware",
                                threat_level="high", category="downloaded", source="eset-ioc")
                            imported += 1
                            if imported >= limit:
                                break
                except Exception:
                    pass
                self._status["progress"] = i + 1
                self._status["imported"] = imported
                if imported >= limit:
                    break

            return {"source": "ESET", "imported": imported}
        except Exception as e:
            return {"error": str(e), "imported": imported}

    # ── Blocklist.de ───────────────────────────────

    def _import_blocklist(self, limit: int) -> dict:
        """从 Blocklist.de 导入恶意 IP"""
        imported = 0
        try:
            resp = requests.get(SOURCES["blocklist"]["url"],
                              headers={"User-Agent": UA}, timeout=30)
            if resp.status_code != 200:
                return {"error": f"Blocklist.de 返回 {resp.status_code}"}

            lines = [l.strip() for l in resp.text.split("\n")
                    if l.strip() and not l.startswith("#")]
            self._status["total"] = min(len(lines), limit)

            for i, ip in enumerate(lines[:limit]):
                ip = ip.strip()
                if ip:
                    self.sig_mgr.add_signature(
                        "ip", ip, "Blocklist.MaliciousIP",
                        threat_level="medium", category="downloaded", source="blocklist.de")
                    imported += 1

                self._status["progress"] = i + 1
                self._status["imported"] = imported

            return {"source": "Blocklist.de", "imported": imported}
        except Exception as e:
            return {"error": str(e), "imported": imported}

    # ── 辅助 ───────────────────────────────────────

    def _guess_level(self, signature: str) -> str:
        sig = signature.lower()
        if any(kw in sig for kw in ["ransom", "wiper", "rootkit", "apt", "emotet"]):
            return "critical"
        if any(kw in sig for kw in ["trojan", "banker", "stealer", "backdoor", "rat",
                                      "agenttesla", "formbook", "lokibot"]):
            return "high"
        if any(kw in sig for kw in ["worm", "dropper", "downloader", "botnet", "adware"]):
            return "medium"
        return "low"

    def quick_update(self) -> dict:
        """快速更新 - 各源取少量数据"""
        return self.download_and_import("all", limit=500)
