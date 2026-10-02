"""
御天 邮件防护（浅层集成）

轻量级邮件安全检测，不接管邮件客户端，仅提供内容级安检：
  - scan_text():   对传入的邮件正文/来源文本做启发式检测，
                   提取其中的 URL，逐个研判是否钓鱼/恶意。
  - scan_urls():   批量检测一组 URL。
  - 可挂接 url_guard 等外部检测器做加权研判（优先级高于本地启发式）。

启发式覆盖（浅层）：
  - 身份伪装：发件人显示名与域名不一致、声称银行/支付/中奖等。
  - 可疑链接：短链、IP 直连、仿冒域名（含同形字/易混淆字符）。
  - 附件风险：可执行/宏文档扩展名黑名单。

仅做提示与报告，不修改邮件、不阻断收发。
"""
import os
import re
import json
import time
import threading
from datetime import datetime

# 可执行/高危附件扩展名
RISKY_ATTACH_EXTS = {
    ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".msi", ".msp",
    ".docm", ".xlsm", ".pptm", ".jar", ".lnk", ".reg", ".ps1",
}

# 身份仿冒常用的“官方/安全话术”关键词
PHISH_KEYWORDS = [
    "账号异常", "登录验证", "密码过期", "您的账户已冻结", "即将停用",
    "中奖", "领取礼金", "banking", "verify your account", "payment method",
    "update your info", "security alert", "unusual sign-in",
]

# 提取 URL（http/https/mailto）
_URL_RE = re.compile(
    r"(?:https?://|www\.|mailto:)[^\s<>'\"]+", re.IGNORECASE
)

# 常见仿冒目标域名（用于相似度提示）
KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "alibaba", "taobao", "jd",
    "bank", "icbc", "ccb", "cmbchina",
]


def _extract_urls(text: str) -> list[str]:
    return [u.rstrip(".,;:!?)") for u in _URL_RE.findall(text or "")]


def _looks_spoof(display_name: str, domain: str) -> bool:
    """发件人显示名与域名相关性弱 → 疑似身份伪装"""
    if not display_name or not domain:
        return False
    name = display_name.split("@")[0].lower()
    # 提取域名主体（打包为示例）
    domain_base = re.sub(r"^(www\.|mail\.|email\.)", "", domain)
    domain_base = domain_base.split(".")[0] if "." in domain_base else domain_base
    return bool(name) and name != domain_base and name not in domain


class MailGuard:
    """邮件防护引擎（单实例，线程安全）"""

    def __init__(self, url_checker=None):
        """
        :param url_checker: 可选外部检测器，形如 func(url) -> level/hint，
                            返回值为 str（'safe'/'suspicious'/'malicious'）或 dict。
        """
        self._checker = url_checker
        self._lock = threading.Lock()
        self._scanned = 0
        self._flagged = 0
        self._history = []

    def set_url_checker(self, url_checker):
        self._checker = url_checker

    def _check_url(self, url: str) -> tuple[str, str]:
        """返回 (level, reason) 本地级联外部检测"""
        reason = ""
        # 1) 本地启发式
        low = url.lower()
        if low.startswith("mailto:"):
            return ("safe", "")
        if re.match(r"^https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?", low):
            return ("suspicious", "使用纯 IP 地址，缺少可信任域名")
        if "bit.ly/" in low or "tinyurl.com/" in low or "goo.gl/" in low:
            return ("suspicious", "疑似短链接跳转")
        for brand in KNOWN_BRANDS:
            if brand in low and "-" in low.split("//")[-1].split("/")[0]:
                return ("suspicious", f"域名含连字符，可能仿冒 {brand}")
        # 2) 外部检测器（有则覆盖）
        if self._checker:
            try:
                r = self._checker(url)
                if isinstance(r, dict):
                    lv = r.get("level")
                    rs = r.get("reason")
                    if lv in ("safe", "suspicious", "malicious"):
                        return (lv, rs or "")
                elif isinstance(r, str) and r in ("safe", "suspicious", "malicious"):
                    return (r, "")
            except Exception:
                pass
        return ("safe", "")

    # ── 对外接口 ────────────────────────────────────────────
    def scan_text(self, text: str, display_name: str = "", domain: str = "") -> dict:
        """检测邮件文本，返回结构化报告"""
        text = text or ""
        alerts: list[dict] = []
        flagged = False

        # 身份/话术启发式
        if _looks_spoof(display_name, domain):
            alerts.append({"type": "spoof", "level": "suspicious",
                           "detail": "发件人显示名与域名不匹配，疑似身份伪装"})
        for kw in PHISH_KEYWORDS:
            if kw.lower() in text.lower():
                alerts.append({"type": "keyword", "level": "suspicious",
                               "detail": f"命中钓鱼话术关键词：{kw}"})
                break

        # 链接检测
        urls = _extract_urls(text)
        for u in urls[:20]:
            lv, rs = self._check_url(u)
            if lv != "safe":
                flagged = True
                alerts.append({"type": "url", "level": lv,
                               "detail": f"{u}  {rs}".strip()})

        # 附件后缀
        att_names = re.findall(r"[^\s]+\.\w{2,5}", text)
        for a in att_names:
            ext = os.path.splitext(a)[1].lower()
            if ext in RISKY_ATTACH_EXTS:
                alerts.append({"type": "attach", "level": "suspicious",
                               "detail": f"可执行/高宏附件：{a} ({ext})"})

        risk = max([2 if a["level"] == "malicious" else
                    (1 if a["level"] == "suspicious" else 0) for a in alerts] or [0])

        with self._lock:
            self._scanned += 1
            if risk > 0:
                self._flagged += 1
                self._history.append({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "risk": ["safe", "suspicious", "malicious"][risk],
                    "alerts": list(alerts),
                })
                self._history = self._history[-50:]

        return {
            "risk": ["safe", "suspicious", "malicious"][risk],
            "flagged": risk > 0,
            "url_count": len(urls),
            "alerts": alerts,
            "urls": urls,
        }

    def scan_urls(self, urls: list[str]) -> dict:
        results = []
        for u in urls or []:
            lv, rs = self._check_url(u)
            results.append({"url": u, "level": lv, "reason": rs})
        return {"results": results,
                "flagged_count": sum(1 for r in results if r["level"] != "safe")}

    def get_status(self) -> dict:
        with self._lock:
            return {
                "scanned": self._scanned,
                "flagged": self._flagged,
                "history": list(reversed(self._history[-20:])),
            }


# 单例
_global: MailGuard | None = None


def get_mail_guard(url_checker=None) -> MailGuard:
    global _global
    if _global is None:
        _global = MailGuard(url_checker)
    return _global