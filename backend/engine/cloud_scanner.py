"""
联网查杀引擎 - 微步在线 ThreatBook API 集成
支持：哈希信誉查询、文件上传沙箱、URL/IP 信誉
缓存：本地 SQLite 缓存（7天TTL），降级策略
"""
import os
import time
import json
import hashlib
import requests
from config import SIGNATURES_DB
import sqlite3


class CloudScanner:
    """联网查杀引擎 - 微步在线 API"""

    BASE_URL = "https://x.threatbook.cn/api/v1"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._init_cache_db()
        # 从环境变量或配置读取 API Key
        if not self.api_key:
            self.api_key = os.environ.get("THREATBOOK_API_KEY", "")
        self._available = bool(self.api_key)
        self._last_error = None

    def _init_cache_db(self):
        """初始化云端查询缓存表"""
        with sqlite3.connect(SIGNATURES_DB) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cloud_cache (
                    resource TEXT PRIMARY KEY,
                    response TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            conn.commit()

    @property
    def available(self) -> bool:
        return self._available

    def set_api_key(self, key: str):
        """动态设置 API Key"""
        self.api_key = key
        self._available = bool(key)

    def get_status(self) -> dict:
        return {
            "available": self._available,
            "configured": bool(self.api_key),
            "last_error": self._last_error,
            "provider": "ThreatBook (微步在线)"
        }

    def lookup_hash(self, md5: str = "", sha1: str = "", sha256: str = "") -> dict | None:
        """
        通过哈希查询云端信誉
        返回: 威胁信息 dict 或 None
        """
        resource = sha256 or sha1 or md5
        if not resource or not self._available:
            return None

        # 先查本地缓存
        cached = self._cache_get(resource)
        if cached is not None:
            return cached

        # 调用微步 API
        try:
            resp = requests.post(
                f"{self.BASE_URL}/file/report",
                data={
                    "apikey": self.api_key,
                    "resource": resource
                },
                timeout=15
            )
            data = resp.json()

            if data.get("response_code") != 1:
                self._last_error = data.get("verbose_msg", "未知错误")
                # 缓存空结果（短期 TTL 避免重复请求）
                self._cache_set(resource, None, ttl=3600)
                return None

            # 解析结果
            threat = self._parse_report(data, md5, sha1, sha256)
            self._cache_set(resource, threat, ttl=604800)  # 7天
            return threat

        except requests.exceptions.Timeout:
            self._last_error = "API 请求超时"
            return None
        except requests.exceptions.ConnectionError:
            self._last_error = "无法连接到威胁情报服务"
            return None
        except Exception as e:
            self._last_error = str(e)
            return None

    def upload_file(self, file_path: str) -> dict | None:
        """
        上传文件到云端沙箱分析（仅通过本地引擎后仍未知的可疑文件）
        """
        if not self._available or not os.path.isfile(file_path):
            return None

        try:
            with open(file_path, "rb") as f:
                resp = requests.post(
                    f"{self.BASE_URL}/file/scan",
                    data={"apikey": self.api_key},
                    files={"file": (os.path.basename(file_path), f)},
                    timeout=60
                )
            data = resp.json()
            if data.get("response_code") == 1:
                return {
                    "scan_id": data.get("scan_id"),
                    "permalink": data.get("permalink"),
                    "sha256": data.get("sha256"),
                    "sha1": data.get("sha1"),
                    "md5": data.get("md5")
                }
            return None
        except Exception as e:
            self._last_error = str(e)
            return None

    def lookup_ip(self, ip: str) -> dict | None:
        """查询 IP 信誉（预留）"""
        # 微步公开 API 以文件分析为主，IP 查询需私有 API Key
        return None

    def lookup_domain(self, domain: str) -> dict | None:
        """查询域名信誉（预留）"""
        return None

    # ---------- 内部方法 ----------

    def _parse_report(self, data: dict, md5: str, sha1: str, sha256: str) -> dict | None:
        """解析微步 API 返回结果"""
        positives = data.get("positives", 0)
        total = data.get("total", 0)
        scans = data.get("scans", {})

        if positives == 0:
            return None  # 无毒

        # 收集检出引擎
        detected_engines = []
        for engine_name, result in scans.items():
            if result and isinstance(result, dict) and result.get("detected"):
                detected_engines.append({
                    "engine": engine_name,
                    "result": result.get("result", "unknown"),
                    "version": result.get("version", "")
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
            "md5": data.get("md5", md5),
            "sha256": data.get("sha256", sha256),
            "threat_level": threat_level,
            "engine": "cloud_hash",
            "signature": f"Cloud.MultiEngine.{positives}of{total}",
            "category": "cloud_detected",
            "details": {
                "positives": positives,
                "total_engines": total,
                "detected_engines": [e["engine"] for e in detected_engines],
                "permalink": data.get("permalink", ""),
                "scan_date": data.get("scan_date", ""),
                "source": "threatbook"
            },
            "action": "quarantine" if threat_level in ("high", "critical") else "prompt"
        }

    def _cache_get(self, resource: str) -> dict | None:
        """读取缓存"""
        with sqlite3.connect(SIGNATURES_DB) as conn:
            row = conn.execute(
                "SELECT response, created_at FROM cloud_cache WHERE resource=?",
                (resource,)
            ).fetchone()
        if not row:
            return None
        response_str, created_at = row
        if time.time() - created_at > 604800:  # 7天过期
            return None
        try:
            return json.loads(response_str) if response_str != "null" else None
        except Exception:
            return None

    def _cache_set(self, resource: str, data: dict | None, ttl: int = 604800):
        """写入缓存"""
        with sqlite3.connect(SIGNATURES_DB) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cloud_cache (resource, response, created_at) VALUES (?,?,?)",
                (resource, json.dumps(data, ensure_ascii=False) if data else "null", time.time())
            )
            conn.commit()
