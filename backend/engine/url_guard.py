"""
御天 网址/网页防护模块（URL Guard）

对标 360 网盾 / 卡巴反钓鱼 / 火绒恶意网址拦截 的本地最小实现：
  - check_url:      对一条 URL / 域名做风险判定（安全 / 可疑 / 恶意），
                    命中来源：内置恶意/钓鱼域名库 + ThreatIntel 威胁情报 +
                    钓鱼/恶意 URL 启发式特征。
  - hosts 阻断:     将恶意域名写入系统 hosts 解析到 0.0.0.0，实现 DNS 层拦截
                    （免驱动、可逆、可离线）。需管理员权限，失败时降级为仅名单管理。
  - 白名单:         用户标记信任的域名，跳过检测与阻断。
  - 统计/历史:      记录检测次数与拦截命中，便于前端展示。

说明：BA 依赖系统 hosts 写权限；若无权限，模块保持可用（名单/检测/统计），
     仅 hosts 应用步骤返回错误提示，不引起崩溃。
"""
import os
import sys
import json
import time
import threading
from urllib.parse import urlparse
from datetime import datetime
from collections import deque

# URL 启发式关键词与判定逻辑已抽取至独立引擎；
# 此处导入 PHISH_MARKERS / RISK_KEYWORDS 仅为保持本模块命名空间向后兼容。
from engine.heuristic_engine import PHISH_MARKERS, RISK_KEYWORDS, get_heuristic_engine

IS_WINDOWS = sys.platform == 'win32'

# ── 数据目录定位（与 adblock / download_guard 保持一致）────────────
DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
)
STATE_FILE = os.path.join(DATA_DIR, "url_guard.json")
LOG_FILE = os.path.join(DATA_DIR, "logs", "url_guard.log")

HOSTS_PATH = os.path.abspath(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                          "System32", "drivers", "etc", "hosts"))
# hosts 中本模块写入的标记块
HOSTS_BLOCK_MARK = "# ---- 御天网址防护阻断(YUTIAN-URLGUARD-BEGIN) ----"
HOSTS_BLOCK_END = "# ---- 御天网址防护阻断(YUTIAN-URLGUARD-END) ----"

# 内置恶意域名黑名单（热门钓鱼/赌博/诈骗样本，随版本持续扩充）
BUILTIN_BLOCKED_DOMAINS = {
    "malware-test-sample.com",
    "fake-msft-login.xyz",
    "secure-verify-alipay.com",
    "taobao-vip-secure.shop",
    "lottery-win-center.club",
    "crypto-airdrop-nft.net",
    "ems-cn-express.info",
    "qq-zone-free-spin.top",
    "skype-verify-bonus.biz",
    "sf-safe-browser-update.site",
}

# 钓鱼/恶意 URL 启发式关键词（命中即提升风险）
# PHISH_MARKERS / RISK_KEYWORDS 的定义已迁移至 engine/heuristic_engine.py，
# 由文件顶部的 import 在此模块内重新导出，外部 `from engine.url_guard import ...` 不受影响。


class UrlGuard:
    """网址防护引擎（单实例，线程安全）"""

    def __init__(self):
        self._enabled = False
        self._lock = threading.Lock()
        self._checked_count = 0
        self._blocked_count = 0
        self._history: deque = deque(maxlen=60)
        self.heuristic_engine = get_heuristic_engine()  # 独立启发式引擎（逻辑已抽取）

        # 阻断域名表（持久化）与白名单
        self._blocked: dict[str, dict] = {}   # host -> {time, reason}
        self._whitelist: set[str] = set()

        self._tl_intel = None                 # 威胁情报查询引擎（懒加载）
        self._hosts_applied = False           # 是否已把阻断写入 hosts

        os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)
        self._load_state()

    # ── 基础工具 ──────────────────────────────────────────────
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
            self._blocked = st.get("blocked", {})
            self._whitelist = set(st.get("whitelist", []))
            self._enabled = bool(st.get("enabled", False))
            self._checked_count = int(st.get("checked_count", 0))
            self._blocked_count = int(st.get("blocked_count", 0))
        except Exception:
            pass

    def _save_state(self):
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "blocked": self._blocked,
                    "whitelist": sorted(self._whitelist),
                    "enabled": self._enabled,
                    "checked_count": self._checked_count,
                    "blocked_count": self._blocked_count,
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    @staticmethod
    def _extract_host(url_or_domain: str) -> str:
        """从 URL 或纯域名提取 host（小写），失败返回 ''"""
        s = (url_or_domain or "").strip().strip("/")
        if not s:
            return ""
        # 去掉协议
        if "://" in s:
            parsed = urlparse(s)
            host = parsed.hostname or ""
        else:
            host = s.split("/")[0].split("\\")[0]
        return host.lower().lstrip("*.").split(":")[0]

    @staticmethod
    def _domain_of(host: str) -> str:
        """取注册域名（最后两段），用于子域归属判定"""
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    def _threat_lookup(self, value: str) -> list[str]:
        """复用 ThreatIntel 引擎查询 IOC 家族"""
        try:
            if self._tl_intel is None:
                from engine.threat_intel import ThreatIntelEngine
                self._tl_intel = ThreatIntelEngine()
            fams = self._tl_intel.lookup_ioc(value)
            if not fams and "/" not in value:
                fams = self._tl_intel.lookup_ioc(self._domain_of(value))
            return fams
        except Exception:
            return []

    def _heuristic(self, url: str, host: str) -> list[str]:
        """URL/域名启发式风险特征（委托给独立启发式引擎）"""
        return self.heuristic_engine.analyze_url(url, host)

    # ── 对外主接口 ────────────────────────────────────────────
    def check_url(self, url_or_domain: str) -> dict:
        """
        检测一条 URL/域名。
        返回: {url, host, level: safe|suspicious|malicious, reason, families, in_blocked}
        """
        host = self._extract_host(url_or_domain)
        default = {"url": url_or_domain, "host": host, "level": "safe",
                   "reason": "", "families": [], "in_blocked": False}
        if not host:
            default["reason"] = "无法解析地址"
            return default

        with self._lock:
            self._checked_count += 1

        domain = self._domain_of(host)

        # 1) 白名单 → 直接安全
        if domain in self._whitelist or host in self._whitelist:
            return default

        reasons: list[str] = []
        families: list[str] = []

        # 2) 阻断名单（含内置）
        if host in self._blocked or domain in self._blocked:
            reasons.append("命中恶意域名黑名单")
        if host in BUILTIN_BLOCKED_DOMAINS or domain in BUILTIN_BLOCKED_DOMAINS:
            reasons.append("命中内置恶意域名库")

        # 3) 威胁情报
        families = self._threat_lookup(url_or_domain) or self._threat_lookup(host)
        if families:
            reasons.append("命中威胁情报家族")

        # 4) 启发式
        for flag in self._heuristic(url_or_domain, host):
            reasons.append(flag)

        # 判定
        if reasons:
            level = "malicious" if "命中" in reasons[0] and families else (
                "suspicious" if any("疑似" in r for r in reasons) else "suspicious")
            # 命中黑名单/情报按恶意，仅启发式按可疑
            if families or "命中" in " ".join(reasons):
                level = "malicious"
            elif any("疑似" in r for r in reasons):
                level = "suspicious"
        else:
            level = "safe"

        if level != "safe":
            with self._lock:
                self._blocked_count += 1
                self._history.appendleft({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": url_or_domain,
                    "host": host,
                    "level": level,
                    "reason": reasons[0] if reasons else level,
                })

        return {"url": url_or_domain, "host": host, "level": level,
                "reason": "；".join(dict.fromkeys(reasons)),
                "families": families,
                "in_blocked": bool(families or any("命中" in r for r in reasons))}

    # ── 阻断名单管理 ─────────────────────────────────────────
    def block_domain(self, url_or_domain: str) -> bool:
        host = self._extract_host(url_or_domain)
        if not host:
            return False
        with self._lock:
            if host not in self._blocked:
                self._blocked[host] = {
                    "time": datetime.now().isoformat(),
                    "reason": "手动添加",
                }
            self._blocked_count += 1
        self._save_state()
        self._log(f"手动阻断: {host}")
        return True

    def unblock_domain(self, url_or_domain: str) -> bool:
        host = self._extract_host(url_or_domain)
        with self._lock:
            existed = host in self._blocked
            self._blocked.pop(host, None)
        if existed:
            self._save_state()
            self._log(f"解除阻断: {host}")
        return existed

    def get_blocked_domains(self, include_builtin: bool = True) -> list[dict]:
        out = []
        with self._lock:
            for host, meta in self._blocked.items():
                out.append({"host": host, "time": meta.get("time"),
                            "reason": meta.get("reason", ""), "builtin": False})
        if include_builtin:
            for host in BUILTIN_BLOCKED_DOMAINS:
                if host not in self._blocked:
                    out.append({"host": host, "time": "", "reason": "内置样本库", "builtin": True})
        return sorted(out, key=lambda x: x["host"])

    # ── 白名单管理 ───────────────────────────────────────────
    def add_whitelist(self, url_or_domain: str) -> bool:
        host = self._extract_host(url_or_domain)
        if not host:
            return False
        domain = self._domain_of(host)
        with self._lock:
            self._whitelist.add(domain)
        self._save_state()
        return True

    def remove_whitelist(self, url_or_domain: str) -> bool:
        host = self._extract_host(url_or_domain)
        domain = self._domain_of(host)
        with self._lock:
            self._whitelist.discard(host)
            self._whitelist.discard(domain)
        self._save_state()
        return True

    def get_whitelist(self) -> list[str]:
        with self._lock:
            return sorted(self._whitelist)

    # ── hosts 阻断（DNS 层，需管理员） ───────────────────────
    def sync_hosts(self, enabled: bool) -> dict:
        """
        将当前阻断域名写入/清除系统 hosts。
        成功返回 {"applied": True}；无权限或失败返回错误信息（不崩溃）。
        """
        if not IS_WINDOWS:
            return {"applied": False, "error": "非 Windows 环境"}
        try:
            if not os.path.exists(HOSTS_PATH):
                return {"applied": False, "error": f"未找到 hosts: {HOSTS_PATH}"}
            with open(HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            # 移除旧标记块
            kept, skip = [], False
            for ln in lines:
                if HOSTS_BLOCK_MARK in ln:
                    skip = True
                    continue
                if HOSTS_BLOCK_END in ln:
                    skip = False
                    continue
                if not skip:
                    kept.append(ln)
            # 若需写入，追加当前阻断域名
            if enabled:
                hosts = []
                with self._lock:
                    banned = set(self._blocked) | BUILTIN_BLOCKED_DOMAINS
                for host in sorted(banned):
                    hosts.append(f"0.0.0.0 {host}\n")
                if hosts:
                    kept.append(HOSTS_BLOCK_MARK + "\n")
                    kept.extend(hosts)
                    kept.append(HOSTS_BLOCK_END + "\n")
            with open(HOSTS_PATH, "w", encoding="utf-8") as f:
                f.writelines(kept)
            self._hosts_applied = enabled
            self._log(f"hosts 阻断{'已启用' if enabled else '已清除'} ({len(list(self._blocked))} 条)")
            return {"applied": True, "hosts_applied": enabled,
                    "count": len(kept)}
        except PermissionError:
            return {"applied": False,
                    "error": "写入 hosts 需要管理员权限，请在管理员模式下重试。阻断名单已保存，可后续启用。"}
        except Exception as e:
            return {"applied": False, "error": f"{type(e).__name__}: {e}"}

    # ── 开关与状态 ───────────────────────────────────────────
    def set_enabled(self, enabled: bool) -> bool:
        with self._lock:
            self._enabled = bool(enabled)
        self._save_state()
        self._log(f"网址防护{'启用' if enabled else '停用'}")
        return self._enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    def get_status(self) -> dict:
        with self._lock:
            hist = list(self._history)
        return {
            "enabled": self._enabled,
            "checked_count": self._checked_count,
            "blocked_count": self._blocked_count,
            "history": hist,
            "hosts_applied": self._hosts_applied,
            "whitelist_count": len(self._whitelist),
            "blocked_domain_count": len(self._blocked) + len(BUILTIN_BLOCKED_DOMAINS),
            "db_count": len(self._blocked),
            "builtin_count": len(BUILTIN_BLOCKED_DOMAINS),
        }


# ── 单例 ─────────────────────────────────────────────────
_global: UrlGuard | None = None


def get_url_guard() -> UrlGuard:
    global _global
    if _global is None:
        _global = UrlGuard()
    return _global