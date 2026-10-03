"""
天听引擎 - 多源云端威胁情报引擎

主引擎:   AVIC 情报中心 (社区联合云安全情报)
第二引擎: 微步在线 ThreatBook API
第三引擎: AlienVault OTX (开放威胁情报交换社区)
策略:     引擎优先级可配置（默认 AVIC 优先），逐一降级补充
缓存:     本地 SQLite 缓存，各引擎 7天TTL
"""
import os
import time
import json
import hashlib
import threading
import requests
import sqlite3
from config import SIGNATURES_DB
from engine.avic_client import AVICClient
from engine.otx_client import OTXClient

# ── 缓存 TTL ──
CACHE_TTL_AVIC = 604800       # AVIC 7天
CACHE_TTL_THREATBOOK = 604800 # 微步 7天
CACHE_TTL_OTX = 604800        # OTX 7天
CACHE_TTL_UNKNOWN = 3600      # 未知结果 1小时（避免频繁查无结果）
CACHE_TTL_ERROR = 300         # 错误缓存 5分钟

# ── 默认配置 ──
DEFAULT_AVIC_URL = "https://avic.xiguastudio.top"
# AVIC API Key 不内置明文，避免随源码发布泄露：
# 优先由 config.AVIC_API_KEY（可被 data/config_save.json 的 cloud.avic_api_key 覆盖）提供，
# 其次读环境变量 AVIC_API_KEY，都没有时为空串（该引擎降级为「未配置」）。
DEFAULT_AVIC_KEY = os.environ.get("AVIC_API_KEY", "")

# 默认引擎优先级（可按用户选择调整）
# 查询优先走可用的 AVIC, 再按需补充 ThreatBook / OTX。
DEFAULT_ENGINE_ORDER = ["avic", "threatbook", "otx"]


class CloudScanner:
    """天听引擎 - 多源云查杀"""

    THREATBOOK_URL = "https://x.threatbook.cn/api/v1"

    def __init__(self, api_key: str = "", avic_key: str = "", otx_key: str = "",
                 engine_order: list[str] | None = None):
        # ── AVIC 客户端 ──
        self._avic_key = avic_key or os.environ.get("AVIC_API_KEY", DEFAULT_AVIC_KEY)
        self._avic = AVICClient(
            base_url=DEFAULT_AVIC_URL,
            api_key=self._avic_key,
            timeout=5
        )
        self._avic_available = False
        self._avic_checked = False  # 是否已尝试过连接验证

        # ── 微步客户端（降级） ──
        self._tb_key = api_key or os.environ.get("THREATBOOK_API_KEY", "")
        self._tb_available = bool(self._tb_key)

        # ── AlienVault OTX 客户端（第三引擎） ──
        self._otx_key = otx_key or os.environ.get("OTX_API_KEY", "")
        self._otx = OTXClient(api_key=self._otx_key, timeout=15)
        self._otx_available = bool(self._otx_key)

        # ── 引擎优先级（用户可配置，默认 AVIC 优先） ──
        # 经 set_engine_order 归一化：过滤掉已下线/未知引擎并补全缺失引擎
        self._engine_order = []
        self.set_engine_order(engine_order)

        # ── 状态 ──
        self._last_error = None
        self._lock = threading.Lock()
        self._stats = {
            "avic_queries": 0,
            "avic_hits": 0,
            "tb_queries": 0,
            "tb_hits": 0,
            "otx_queries": 0,
            "otx_hits": 0,
            "cache_hits": 0,
        }
        # 云缓存库与签名库共用 SQLite 连接。若磁盘/锁异常导致缓存不可用，
        # 绝不能阻断启动（否则会触发自保护无限重启循环），统一降级为无缓存。
        self._cache_enabled = True
        self._init_cache_db()

        # ── 后台异步验证 AVIC 连接 ──
        if self._avic_key:
            threading.Thread(target=self._async_verify_avic, daemon=True).start()

    # ── 属性 ──

    @property
    def available(self) -> bool:
        """任一引擎可用即返回 True"""
        return (self._avic_available
                or self._tb_available or self._otx_available)

    @property
    def avic_available(self) -> bool:
        return self._avic_available

    @property
    def tb_available(self) -> bool:
        return self._tb_available

    @property
    def otx_available(self) -> bool:
        return self._otx_available

    @property
    def engine_order(self) -> list[str]:
        return list(self._engine_order)

    @property
    def last_error(self) -> str | None:
        return self._last_error

    # ── 数据库初始化 ──

    def _cache_conn(self) -> "sqlite3.Connection | None":
        """打开云缓存库连接；不可用（磁盘/锁异常）时关闭缓存并返回 None"""
        if not self._cache_enabled:
            return None
        try:
            return sqlite3.connect(SIGNATURES_DB, timeout=10.0)
        except sqlite3.Error as _e:
            self._cache_enabled = False
            try:
                print(f"[云查] 缓存库不可用，本次运行停用云缓存: {_e}")
            except Exception:
                pass
            return None

    def _init_cache_db(self):
        """初始化缓存表（按 provider 区分）。任何 DB 异常只停用缓存，不崩溃。"""
        conn = self._cache_conn()
        if conn is None:
            return
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cloud_cache (
                        resource TEXT PRIMARY KEY,
                        response TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        provider TEXT DEFAULT 'threatbook',
                        ttl REAL DEFAULT 604800
                    )
                """)
                # 兼容旧表无 provider/ttl 列
                try:
                    conn.execute("SELECT provider FROM cloud_cache LIMIT 1")
                except sqlite3.OperationalError:
                    conn.execute("ALTER TABLE cloud_cache ADD COLUMN provider TEXT DEFAULT 'threatbook'")
                try:
                    conn.execute("SELECT ttl FROM cloud_cache LIMIT 1")
                except sqlite3.OperationalError:
                    conn.execute("ALTER TABLE cloud_cache ADD COLUMN ttl REAL DEFAULT 604800")
        except sqlite3.Error as _e:
            self._cache_enabled = False
            try:
                print(f"[云查] 缓存初始化失败，本次运行停用云缓存: {_e}")
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ── 公开 API ──

    def set_api_key(self, key: str):
        """动态设置密钥（优先设置为 AVIC，长度>32且AVIC-开头视为 AVIC，长度64视为 OTX，其余视为微步）"""
        if key.startswith("AVIC-"):
            self._avic_key = key
            self._avic = AVICClient(base_url=DEFAULT_AVIC_URL, api_key=key, timeout=8)
            self._avic_available = False
        elif len(key) == 64 or key.startswith("OTX-"):
            self._otx_key = key
            self._otx = OTXClient(api_key=key, timeout=15)
            self._otx_available = bool(key)
        else:
            self._tb_key = key
            self._tb_available = bool(key)

    def set_avic_key(self, key: str):
        self._avic_key = key
        self._avic = AVICClient(base_url=DEFAULT_AVIC_URL, api_key=key, timeout=8)
        self._avic_available = False

    def set_engine_order(self, order: list[str] | None):
        """设置引擎查询优先级（如 ['avic','threatbook','otx']）"""
        allowed = {"avic", "threatbook", "otx"}
        valid = [o for o in (order or []) if o in allowed]
        # 补全未指定的引擎
        for o in DEFAULT_ENGINE_ORDER:
            if o not in valid:
                valid.append(o)
        self._engine_order = valid

    def set_otx_key(self, key: str):
        """设置 OTX API Key"""
        self._otx_key = key
        self._otx = OTXClient(api_key=key, timeout=15)
        self._otx_available = bool(key)

    def get_status(self) -> dict:
        """获取引擎状态（不阻塞，返回当前已知状态）"""
        missing = {
            "avic": not bool(self._avic_key),
            "threatbook": not bool(self._tb_key),
            "otx": not bool(self._otx_key),
        }
        any_degraded = not (
            self._avic_available
            and self._tb_available and self._otx_available
        )
        hint = None
        if any_degraded:
            keys = [name for name, miss in missing.items() if miss]
            if keys:
                hint = f"云端引擎未配置 API Key（{', '.join(keys)}），相关云查功能暂不可用，可到「引擎启动」页配置。"
            else:
                hint = "云端引擎已配置但当前不可用，请检查网络或平台连通性。"
        return {
            "available": self.available,
            "engine_order": self._engine_order,
            "avic": {
                "available": self._avic_available,
                "configured": bool(self._avic_key),
                "verifying": not self._avic_checked,
                "url": DEFAULT_AVIC_URL,
            },
            "threatbook": {
                "available": self._tb_available,
                "configured": bool(self._tb_key),
            },
            "otx": {
                "available": self._otx_available,
                "configured": bool(self._otx_key),
                "base_url": OTXClient.BASE_URL,
            },
            "provider": "AVIC + ThreatBook + AlienVault OTX",
            "degraded": any_degraded,
            "missing_keys": missing,
            "hint": hint,
            "last_error": self._last_error,
            "stats": self._stats,
        }

    def verify_connection(self) -> bool:
        """主动验证 AVIC 连接（供前端手动触发，同步阻塞）"""
        return self._verify_avic()

    def _async_verify_avic(self):
        """后台异步验证 AVIC 连接（不阻塞主线程）"""
        try:
            self._verify_avic()
        except Exception:
            pass  # 已在 _verify_avic 内部处理

    def _verify_avic(self) -> bool:
        """验证 AVIC API 连接"""
        if self._avic_checked and self._avic_available:
            return True
        if not self._avic_key:
            self._avic_checked = True
            self._avic_available = False
            return False

        try:
            status = self._avic.status()
            if status.get("status") == "online":
                self._avic_available = True
                self._last_error = None
            else:
                self._avic_available = False
                self._last_error = "AVIC 服务异常"
        except requests.exceptions.Timeout:
            self._avic_available = False
            self._last_error = "AVIC 连接超时"
        except requests.exceptions.ConnectionError:
            self._avic_available = False
            self._last_error = "无法连接到 AVIC 情报中心"
        except Exception as e:
            self._avic_available = False
            self._last_error = f"AVIC: {str(e)[:60]}"

        self._avic_checked = True
        return self._avic_available

    def lookup_hash(self, md5: str = "", sha1: str = "", sha256: str = "") -> dict | None:
        """
        云端哈希查询（按用户配置的引擎优先级逐一查询，命中即返回）
        返回: 威胁信息 dict 或 None
        """
        resource = sha256 or sha1 or md5
        if not resource:
            return None

        # 1. 查本地缓存
        cached = self._cache_get(resource)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return cached

        # 2. 按引擎优先级查询
        for engine in self._engine_order:
            if engine == "avic" and self._avic_key:
                result = self._lookup_avic(resource)
                if result is not None:
                    return result
            elif engine == "threatbook" and self._tb_available and self._tb_key:
                result = self._lookup_threatbook(resource)
                if result is not None:
                    return result
            elif engine == "otx" and self._otx_available and self._otx_key:
                result = self._lookup_otx(resource)
                if result is not None:
                    return result

        return None

    def lookup_hashes_batch(self, hashes: list[str]) -> dict[str, dict | None]:
        """
        批量查询（走 AVIC batch API，一次请求查多个；OTX 逐个查）
        返回: {hash: threat_info | None}
        """
        if not hashes:
            return {}

        # 先查缓存
        results = {}
        uncached = []
        for h in hashes:
            cached = self._cache_get(h)
            if cached is not None:
                results[h] = cached
                self._stats["cache_hits"] += 1
            else:
                uncached.append(h)

        if not uncached:
            return results

        # AVIC 批量查询
        if self._avic_key and self._avic_available:
            try:
                batch = self._avic.batch_query(uncached)
                self._stats["avic_queries"] += 1

                still_uncached = []
                for item in batch.get("results", []):
                    h = item.get("hash", "").lower()
                    if item.get("found") and item.get("classification") == "malicious":
                        threat = self._parse_avic_result(item)
                        self._cache_set(h, threat, ttl=CACHE_TTL_AVIC, provider="avic")
                        results[h] = threat
                        self._stats["avic_hits"] += 1
                    else:
                        still_uncached.append(h)
                        self._cache_set(h, None, ttl=CACHE_TTL_UNKNOWN, provider="avic")
                        results[h] = None

                # 未返回的哈希标记为未知
                for h in uncached:
                    if h not in results:
                        still_uncached.append(h)
                        self._cache_set(h, None, ttl=CACHE_TTL_UNKNOWN, provider="avic")
                        results[h] = None

                uncached = still_uncached
            except Exception as e:
                self._last_error = f"AVIC batch: {e}"
                self._avic_available = False

        # 逐个查微步 + OTX
        for h in uncached:
            if h in results and results[h] is not None:
                continue
            if self._tb_available:
                result = self._lookup_threatbook(h)
                if result is not None:
                    results[h] = result
                    continue
            if self._otx_available:
                result = self._lookup_otx(h)
                if result is not None:
                    results[h] = result
                    continue
            # 都没命中，确保有值
            if h not in results:
                results[h] = None

        return results

    def submit_hash(self, filepath: str, threat_name: str = "", family: str = "",
                    classification: str = "malicious") -> dict | None:
        """向 AVIC 提交新发现的恶意哈希"""
        if not self._avic_key:
            return None
        try:
            sha256_hash = self._sha256_file(filepath) if os.path.isfile(filepath) else filepath
            return self._avic.submit(
                hash_value=sha256_hash,
                threat_name=threat_name,
                family=family,
                classification=classification,
            )
        except Exception as e:
            self._last_error = f"AVIC submit: {e}"
            return None

    def upload_file(self, file_path: str) -> dict | None:
        """上传文件到云端沙箱分析（微步）"""
        if not self._tb_available or not os.path.isfile(file_path):
            return None
        try:
            with open(file_path, "rb") as f:
                resp = requests.post(
                    f"{self.THREATBOOK_URL}/file/scan",
                    data={"apikey": self._tb_key},
                    files={"file": (os.path.basename(file_path), f)},
                    timeout=60
                )
            data = resp.json()
            if data.get("response_code") == 1:
                return {
                    "scan_id": data.get("scan_id"),
                    "permalink": data.get("permalink"),
                    "sha256": data.get("sha256"),
                }
            return None
        except Exception as e:
            self._last_error = str(e)
            return None

    # ── AVIC 查询 ──

    def _lookup_avic(self, resource: str) -> dict | None:
        """AVIC 单哈希查询"""
        try:
            result = self._avic.query(resource)
            self._stats["avic_queries"] += 1

            if not self._avic_available:
                self._avic_available = True

            if result.get("found") and result.get("classification") == "malicious":
                threat = self._parse_avic_result(result)
                self._cache_set(resource, threat, ttl=CACHE_TTL_AVIC, provider="avic")
                self._stats["avic_hits"] += 1
                return threat
            else:
                self._cache_set(resource, None, ttl=CACHE_TTL_UNKNOWN, provider="avic")
                return None
        except requests.exceptions.Timeout:
            self._last_error = "AVIC 请求超时"
            self._cache_set(resource, None, ttl=CACHE_TTL_ERROR, provider="avic")
            return None
        except requests.exceptions.ConnectionError:
            self._last_error = "无法连接到 AVIC 情报中心"
            self._avic_available = False
            return None
        except Exception as e:
            self._last_error = f"AVIC: {e}"
            return None

    def _parse_avic_result(self, data: dict) -> dict:
        """解析 AVIC 返回为引擎统一格式"""
        classification = data.get("classification", "unknown")
        level_map = {"malicious": "high", "suspicious": "medium", "safe": "clean"}
        threat_level = level_map.get(classification, "low")

        return {
            "path": data.get("path", ""),
            "md5": data.get("hash", "") if len(data.get("hash", "")) == 32 else "",
            "sha256": data.get("hash", "") if len(data.get("hash", "")) == 64 else "",
            "threat_level": threat_level,
            "engine": "cloud_avic",
            "signature": data.get("threat_name", f"AVIC.{classification}"),
            "category": "cloud_detected",
            "details": {
                "threat_name": data.get("threat_name", ""),
                "family": data.get("family", ""),
                "hit_count": data.get("hit_count", 0),
                "source": "avic",
            },
            "action": "quarantine" if threat_level in ("high", "critical") else "prompt"
        }

    # ── 微步查询 ──

    def _lookup_threatbook(self, resource: str) -> dict | None:
        """微步哈希查询"""
        try:
            resp = requests.post(
                f"{self.THREATBOOK_URL}/file/report",
                data={"apikey": self._tb_key, "resource": resource},
                timeout=15
            )
            data = resp.json()

            if data.get("response_code") != 1:
                self._last_error = data.get("verbose_msg", "未知错误")
                self._cache_set(resource, None, ttl=CACHE_TTL_UNKNOWN, provider="threatbook")
                return None

            threat = self._parse_tb_report(data)
            self._stats["tb_queries"] += 1
            if threat:
                self._stats["tb_hits"] += 1
            self._cache_set(resource, threat, ttl=CACHE_TTL_THREATBOOK, provider="threatbook")
            return threat

        except requests.exceptions.Timeout:
            self._last_error = "ThreatBook 请求超时"
            return None
        except requests.exceptions.ConnectionError:
            self._last_error = "无法连接到 ThreatBook"
            return None
        except Exception as e:
            self._last_error = str(e)
            return None

    def _parse_tb_report(self, data: dict) -> dict | None:
        """解析微步 API 返回结果"""
        positives = data.get("positives", 0)
        total = data.get("total", 0)
        scans = data.get("scans", {})

        if positives == 0:
            return None

        detected_engines = []
        for engine_name, result in scans.items():
            if result and isinstance(result, dict) and result.get("detected"):
                detected_engines.append({
                    "engine": engine_name,
                    "result": result.get("result", "unknown"),
                })

        threat_level = "low"
        if positives >= total * 0.5:
            threat_level = "critical"
        elif positives >= total * 0.2:
            threat_level = "high"
        elif positives >= 3:
            threat_level = "medium"

        return {
            "path": "",
            "md5": data.get("md5", ""),
            "sha256": data.get("sha256", ""),
            "threat_level": threat_level,
            "engine": "cloud_tb",
            "signature": f"Cloud.MultiEngine.{positives}of{total}",
            "category": "cloud_detected",
            "details": {
                "positives": positives,
                "total_engines": total,
                "detected_engines": [e["engine"] for e in detected_engines],
                "permalink": data.get("permalink", ""),
                "scan_date": data.get("scan_date", ""),
                "source": "threatbook",
            },
            "action": "quarantine" if threat_level in ("high", "critical") else "prompt"
        }

    # ── OTX 查询 ──

    def _lookup_otx(self, resource: str) -> dict | None:
        """AlienVault OTX 哈希查询（第三补充源）"""
        try:
            result = self._otx.scan_file(resource)
            self._stats["otx_queries"] += 1

            if not self._otx_available:
                self._otx_available = True

            if result.get("found") and result.get("classification") in ("malicious", "suspicious"):
                threat = self._parse_otx_result(resource, result)
                self._cache_set(resource, threat, ttl=CACHE_TTL_OTX, provider="otx")
                self._stats["otx_hits"] += 1
                return threat
            else:
                self._cache_set(resource, None, ttl=CACHE_TTL_UNKNOWN, provider="otx")
                return None
        except requests.exceptions.Timeout:
            self._last_error = "OTX 请求超时"
            self._cache_set(resource, None, ttl=CACHE_TTL_ERROR, provider="otx")
            return None
        except requests.exceptions.ConnectionError:
            self._last_error = "无法连接到 OTX 情报中心"
            self._otx_available = False
            return None
        except Exception as e:
            self._last_error = f"OTX: {e}"
            return None

    def _parse_otx_result(self, resource: str, data: dict) -> dict:
        """解析 OTX 返回为引擎统一格式"""
        classification = data.get("classification", "unknown")
        level_map = {"malicious": "high", "suspicious": "medium", "safe": "clean"}
        threat_level = level_map.get(classification, "low")
        detections = data.get("detections", {}) or {}
        hit_count = data.get("hit_count", 0)
        pulse_count = data.get("pulse_count", 0)

        raw = data.get("raw", {}) or {}
        md5 = raw.get("md5", "")
        sha256 = raw.get("sha256", "")
        hash_val = raw.get("hash", "") or ""

        if not md5 and len(hash_val) == 32:
            md5 = hash_val
        if not sha256 and len(hash_val) == 64:
            sha256 = hash_val
        if not md5 and len(resource) == 32:
            md5 = resource
        if not sha256 and len(resource) == 64:
            sha256 = resource

        return {
            "path": "",
            "md5": md5,
            "sha256": sha256,
            "threat_level": threat_level,
            "engine": "cloud_otx",
            "signature": data.get("threat_name") or f"OTX.{classification}.P{pulse_count}H{hit_count}",
            "category": "cloud_detected",
            "details": {
                "threat_name": data.get("threat_name", ""),
                "family": data.get("family", ""),
                "pulse_count": pulse_count,
                "hit_count": hit_count,
                "detected_engines": list(detections.keys()),
                "detections": detections,
                "source": "otx",
            },
            "action": "quarantine" if threat_level in ("high", "critical") else "prompt"
        }

    # ── OTX IOC 查询（IP/域名/URL/CVE） ──

    def otx_lookup_ip(self, ip: str) -> dict:
        """OTX IP 情报查询（返回通用情报格式）"""
        if not self._otx_available:
            return {"error": "OTX 未配置", "success": False}
        result = self._otx.lookup_ip(ip) or {}
        return {
            "success": bool(result),
            "ip": ip,
            "pulse_count": result.get("pulse_count", 0) or 0,
            "reputation": result.get("reputation", 0) or 0,
            "country": result.get("country_code", ""),
            "city": result.get("city", ""),
            "asn": result.get("asn", ""),
            "malware_samples": len(result.get("malware_samples", []) or []),
            "related_pulses": (result.get("pulse_info") or {}).get("count", 0),
            "raw": result,
            "source": "otx",
        }

    def otx_lookup_domain(self, domain: str) -> dict:
        """OTX 域名情报查询"""
        if not self._otx_available:
            return {"error": "OTX 未配置", "success": False}
        result = self._otx.lookup_domain(domain) or {}
        return {
            "success": bool(result),
            "domain": domain,
            "pulse_count": result.get("pulse_count", 0) or 0,
            "malware_samples": len(result.get("malware_samples", []) or []),
            "whois": result.get("whois", ""),
            "related_pulses": (result.get("pulse_info") or {}).get("count", 0),
            "raw": result,
            "source": "otx",
        }

    def otx_lookup_url(self, url: str) -> dict:
        """OTX URL 情报查询"""
        if not self._otx_available:
            return {"error": "OTX 未配置", "success": False}
        result = self._otx.lookup_url(url) or {}
        return {
            "success": bool(result),
            "url": url,
            "pulse_count": result.get("pulse_count", 0) or 0,
            "hostname": result.get("hostname", ""),
            "domain": result.get("domain", ""),
            "related_pulses": (result.get("pulse_info") or {}).get("count", 0),
            "raw": result,
            "source": "otx",
        }

    def otx_lookup_cve(self, cve_id: str) -> dict:
        """OTX CVE 漏洞情报查询"""
        if not self._otx_available:
            return {"error": "OTX 未配置", "success": False}
        result = self._otx.lookup_cve(cve_id) or {}
        return {
            "success": bool(result),
            "cve_id": cve_id,
            "description": result.get("description", ""),
            "cvss": result.get("cvss", ""),
            "pulse_count": result.get("pulse_count", 0) or 0,
            "raw": result,
            "source": "otx",
        }

    def otx_verify_key(self) -> dict:
        """验证 OTX API Key 有效性"""
        if not self._otx_key:
            return {"success": False, "error": "未配置 OTX API Key"}
        info = self._otx.verify_key()
        if not info:
            return {
                "success": False,
                "error": self._otx.last_error or "验证失败",
            }
        return {
            "success": True,
            "user_id": info.get("id"),
            "username": info.get("username"),
            "email": info.get("email"),
            "subscribed_pulses": info.get("subscribed_pulse_count"),
            "api_key_used": f"{self._otx_key[:8]}...",
        }

    # ── 缓存操作 ──

    def _cache_get(self, resource: str) -> dict | None:
        """读取缓存（自动检查 TTL）。缓存不可用时返回 None，不抛异常。"""
        conn = self._cache_conn()
        if conn is None:
            return None
        try:
            with conn:
                row = conn.execute(
                    "SELECT response, created_at, ttl FROM cloud_cache WHERE resource=?",
                    (resource,)
                ).fetchone()
        except sqlite3.Error:
            return None
        finally:
            try:
                conn.close()
            except Exception:
                pass
        if not row:
            return None
        response_str, created_at, ttl = row
        if ttl and time.time() - created_at > ttl:
            return None
        try:
            return json.loads(response_str) if response_str and response_str != "null" else None
        except Exception:
            return None

    def _cache_set(self, resource: str, data: dict | None, ttl: int = 604800,
                   provider: str = "unknown"):
        """写入缓存。失败静默忽略，不抛异常。"""
        conn = self._cache_conn()
        if conn is None:
            return
        try:
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO cloud_cache (resource, response, created_at, provider, ttl) "
                    "VALUES (?,?,?,?,?)",
                    (resource, json.dumps(data, ensure_ascii=False) if data else "null",
                     time.time(), provider, ttl)
                )
        except sqlite3.Error:
            self._cache_enabled = False
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def clear_cache(self, older_than_days: int = 0):
        """清理过期缓存。失败静默忽略，不抛异常。"""
        conn = self._cache_conn()
        if conn is None:
            return
        try:
            with conn:
                if older_than_days > 0:
                    cutoff = time.time() - older_than_days * 86400
                    conn.execute("DELETE FROM cloud_cache WHERE created_at < ?", (cutoff,))
                else:
                    conn.execute("DELETE FROM cloud_cache")
        except sqlite3.Error:
            self._cache_enabled = False
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ── 工具 ──

    def _sha256_file(self, path: str) -> str:
        try:
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha.update(chunk)
            return sha.hexdigest()
        except Exception:
            return ""