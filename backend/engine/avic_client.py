"""
AVIC 情报中心 — 客户端 SDK

供自制杀毒软件集成的 Python 客户端。
支持: 单哈希查询、批量查询、提交哈希、API 状态检查、文件扫描。
"""
import hashlib
import requests
from typing import Optional


class AVICClient:
    """AVIC 情报中心 API 客户端"""

    def __init__(self, base_url: str, api_key: str, timeout: int = 10):
        """
        初始化客户端

        Args:
            base_url: 情报中心地址,例如 https://avic.xiguastudio.top
            api_key: API 密钥 (AVIC-XXXX 格式)
            timeout: 请求超时(秒)
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._available = bool(api_key and api_key.startswith("AVIC-"))
        self._last_error = None
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        })

    @property
    def available(self) -> bool:
        return self._available

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def query(self, hash_value: str) -> dict:
        """查询单个哈希"""
        resp = self.session.post(
            f"{self.base_url}/api/v1/query",
            json={"hash": hash_value.lower().strip()},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def batch_query(self, hashes: list) -> dict:
        """批量查询哈希 (最多 1000 个)"""
        resp = self.session.post(
            f"{self.base_url}/api/v1/batch",
            json={"hashes": [h.lower().strip() for h in hashes]},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def submit(self, hash_value: str,
               threat_name: Optional[str] = None,
               family: Optional[str] = None,
               description: Optional[str] = None,
               tags: Optional[str] = None,
               classification: Optional[str] = None) -> dict:
        """提交新发现的哈希"""
        payload = {"hash": hash_value.lower().strip()}
        if threat_name:
            payload["threat_name"] = threat_name
        if family:
            payload["family"] = family
        if description:
            payload["description"] = description
        if tags:
            payload["tags"] = tags
        if classification:
            payload["classification"] = classification

        resp = self.session.post(
            f"{self.base_url}/api/v1/submit",
            json=payload,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def status(self) -> dict:
        """检查 API 状态"""
        resp = self.session.get(
            f"{self.base_url}/api/v1/status",
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def compute_hash(filepath: str, algo: str = "sha256") -> str:
        """计算文件的哈希值"""
        h = hashlib.new(algo)
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def scan_file(self, filepath: str, algo: str = "sha256") -> dict:
        """扫描文件: 计算哈希并查询情报中心"""
        file_hash = self.compute_hash(filepath, algo)
        result = self.query(file_hash)
        result["file"] = filepath
        return result