"""
AlienVault OTX (Open Threat Exchange)  — 客户端 SDK

官方 API 文档: https://otx.alienvault.com/api
提供: 文件哈希查询、IP/域名/URL IOC 情报、Pulse 订阅、用户统计等。
"""
import time
import requests
from typing import Optional


class OTXClient:
    """AlienVault OTX 开放威胁情报 API 客户端"""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str, timeout: int = 15):
        """
        初始化客户端

        Args:
            api_key: OTX API Key (在 https://otx.alienvault.com/settings 申请)
            timeout: 请求超时秒数
        """
        self.api_key = api_key.strip() if api_key else ""
        self.timeout = timeout
        self._available = bool(self.api_key)
        self._last_error = None
        self.session = requests.Session()
        self.session.headers.update({
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
            "User-Agent": "Yutian-Security-Engine/1.0",
        })

    # ── 属性 ──

    @property
    def available(self) -> bool:
        return self._available

    @property
    def last_error(self) -> str | None:
        return self._last_error

    # ── 基础请求封装 ──

    def _get(self, path: str, params: Optional[dict] = None) -> Optional[dict]:
        """统一 GET 请求封装"""
        if not self._available:
            self._last_error = "OTX API Key 未配置"
            return None
        url = f"{self.BASE_URL}{path}"
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            if resp.status_code == 403:
                self._last_error = "OTX API Key 无效或权限不足"
                self._available = False
                return None
            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                self._last_error = "OTX 请求频率超限 (Rate Limited)"
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.Timeout:
            self._last_error = "OTX 请求超时"
            return None
        except requests.exceptions.ConnectionError:
            self._last_error = "无法连接到 OTX 服务器"
            return None
        except Exception as e:
            self._last_error = f"OTX 请求异常: {str(e)[:80]}"
            return None

    # ── 认证 & 用户信息 ──

    def verify_key(self) -> dict:
        """验证 API Key 是否有效，并获取用户统计信息"""
        return self._get("/user/me") or {}

    def get_user_stats(self) -> dict:
        """获取用户统计（订阅数、Pulse 数等）"""
        return self._get("/user/messages") or {}

    # ── 文件哈希查询 ──

    def lookup_file_hash(self, file_hash: str) -> Optional[dict]:
        """
        查询文件哈希情报 (支持 MD5/SHA1/SHA256)

        返回的 general 信息含:
          - hash, malware, pulse_count, analysis, detections 等
        """
        h = file_hash.strip().lower()
        if not h:
            return None
        return self._get(f"/indicators/file/{h}/general")

    def lookup_file_analysis(self, file_hash: str) -> Optional[dict]:
        """查询文件哈希的沙箱分析结果"""
        h = file_hash.strip().lower()
        if not h:
            return None
        return self._get(f"/indicators/file/{h}/analysis")

    # ── IP 查询 ──

    def lookup_ip(self, ip: str) -> Optional[dict]:
        """查询 IPv4 地址情报"""
        ip = ip.strip()
        if not ip:
            return None
        return self._get(f"/indicators/IPv4/{ip}/general")

    def lookup_ip_malware(self, ip: str) -> Optional[dict]:
        """查询 IP 关联的恶意软件样本"""
        ip = ip.strip()
        if not ip:
            return None
        return self._get(f"/indicators/IPv4/{ip}/malware")

    def lookup_ip_passive_dns(self, ip: str) -> Optional[dict]:
        """查询 IP 的被动 DNS 记录"""
        ip = ip.strip()
        if not ip:
            return None
        return self._get(f"/indicators/IPv4/{ip}/passive_dns")

    def lookup_ip_url_list(self, ip: str, page: int = 1, limit: int = 50) -> Optional[dict]:
        """查询 IP 关联的 URL 列表"""
        ip = ip.strip()
        if not ip:
            return None
        return self._get(
            f"/indicators/IPv4/{ip}/url_list",
            params={"page": page, "limit": limit},
        )

    # ── 域名查询 ──

    def lookup_domain(self, domain: str) -> Optional[dict]:
        """查询域名情报"""
        domain = domain.strip().lower()
        if not domain:
            return None
        return self._get(f"/indicators/domain/{domain}/general")

    def lookup_domain_malware(self, domain: str) -> Optional[dict]:
        """查询域名关联的恶意软件"""
        domain = domain.strip().lower()
        if not domain:
            return None
        return self._get(f"/indicators/domain/{domain}/malware")

    def lookup_domain_passive_dns(self, domain: str) -> Optional[dict]:
        """查询域名被动 DNS"""
        domain = domain.strip().lower()
        if not domain:
            return None
        return self._get(f"/indicators/domain/{domain}/passive_dns")

    def lookup_domain_url_list(self, domain: str, page: int = 1, limit: int = 50) -> Optional[dict]:
        """查询域名关联 URL 列表"""
        domain = domain.strip().lower()
        if not domain:
            return None
        return self._get(
            f"/indicators/domain/{domain}/url_list",
            params={"page": page, "limit": limit},
        )

    # ── URL 查询 ──

    def lookup_url(self, url: str) -> Optional[dict]:
        """查询 URL 情报"""
        if not url:
            return None
        import urllib.parse
        encoded = urllib.parse.quote(url, safe="")
        return self._get(f"/indicators/url/{encoded}/general")

    # ── 主机名 / CVE ──

    def lookup_hostname(self, hostname: str) -> Optional[dict]:
        """查询主机名情报"""
        hostname = hostname.strip().lower()
        if not hostname:
            return None
        return self._get(f"/indicators/hostname/{hostname}/general")

    def lookup_cve(self, cve_id: str) -> Optional[dict]:
        """查询 CVE 漏洞情报"""
        cve_id = cve_id.strip().upper()
        if not cve_id:
            return None
        return self._get(f"/indicators/cve/{cve_id}/general")

    # ── Pulse 订阅 (威胁事件集合) ──

    def list_subscribed_pulses(self, page: int = 1, limit: int = 20,
                                modified_since: Optional[str] = None) -> Optional[dict]:
        """
        列出已订阅的 Pulse

        Args:
            page: 页码
            limit: 每页数量 (最大 500)
            modified_since: ISO 格式时间字符串，只返回此时间后修改的 Pulse
        """
        params = {"page": page, "limit": min(limit, 500)}
        if modified_since:
            params["modified_since"] = modified_since
        return self._get("/pulses/subscribed", params=params)

    def get_pulse(self, pulse_id: str) -> Optional[dict]:
        """获取单个 Pulse 详情"""
        pulse_id = pulse_id.strip()
        if not pulse_id:
            return None
        return self._get(f"/pulses/{pulse_id}")

    def search_pulses(self, query: str, page: int = 1, limit: int = 20) -> Optional[dict]:
        """搜索 Pulse"""
        if not query:
            return None
        return self._get(
            "/search/pulses",
            params={"q": query, "page": page, "limit": min(limit, 500)},
        )

    def list_indicator_related_pulses(self, indicator_type: str, indicator: str,
                                       page: int = 1, limit: int = 20) -> Optional[dict]:
        """查询与指定 IOC 相关的 Pulse 列表"""
        if not indicator_type or not indicator:
            return None
        indicator_type = indicator_type.strip()
        indicator = indicator.strip()
        return self._get(
            f"/indicators/{indicator_type}/{indicator}/related",
            params={"page": page, "limit": min(limit, 500)},
        )

    # ── 高级: 扫描文件 (封装哈希查询 + 威胁解析) ──

    def scan_file(self, file_hash: str) -> dict:
        """
        一站式文件云查杀: 查询哈希 + 解析威胁级别

        返回格式与 CloudScanner 统一:
        {
            "found": bool,
            "classification": "malicious" | "suspicious" | "safe" | "unknown",
            "threat_name": str,
            "family": str,
            "pulse_count": int,
            "detections": dict,
            "hit_count": int,
            "raw": dict
        }
        """
        general = self.lookup_file_hash(file_hash)
        if general is None:
            return {
                "found": False,
                "classification": "unknown",
                "threat_name": "",
                "family": "",
                "pulse_count": 0,
                "detections": {},
                "hit_count": 0,
                "raw": {},
            }

        pulse_count = general.get("pulse_count", 0) or 0
        malware_info = general.get("malware", {}) or {}
        detections = general.get("detections", []) or []

        # 分类判断
        hit_count = len(detections) if isinstance(detections, list) else 0
        detection_map = {}
        if isinstance(detections, list):
            for d in detections:
                if isinstance(d, dict):
                    name = d.get("name") or d.get("engine") or "unknown"
                    if name:
                        detection_map[name] = d.get("result") or d.get("detection") or "malicious"
        elif isinstance(detections, dict):
            detection_map = {k: v for k, v in detections.items() if v}
            hit_count = len(detection_map)

        # 威胁名称提取
        threat_name = malware_info.get("hash", "") or malware_info.get("name", "")
        family = ""
        for key in ("family", "malware_family", "family_name"):
            if malware_info.get(key):
                family = malware_info[key]
                break
        if not family and general.get("type_title"):
            family = general["type_title"]

        # 分类级别
        if pulse_count > 0 and hit_count >= 10:
            classification = "malicious"
        elif pulse_count > 0 or hit_count >= 3:
            classification = "malicious"
        elif pulse_count == 0 and hit_count >= 1:
            classification = "suspicious"
        elif pulse_count == 0 and hit_count == 0:
            classification = "safe"
        else:
            classification = "unknown"

        # 从 pulse 名字提取恶意家族名
        if not family and general.get("pulse_info", {}).get("pulses"):
            for p in general["pulse_info"]["pulses"][:3]:
                pname = p.get("name", "")
                if pname:
                    family = pname
                    break

        return {
            "found": pulse_count > 0 or hit_count > 0,
            "classification": classification,
            "threat_name": threat_name or (f"OTX.{classification}.{pulse_count}pulses" if classification in ("malicious", "suspicious") else ""),
            "family": family,
            "pulse_count": pulse_count,
            "detections": detection_map,
            "hit_count": hit_count,
            "raw": general,
        }
