"""
AndunAI 云查杀平台 — 客户端 SDK

御天客户端对接自建云查杀平台 (AndunAI)。
支持: 哈希查询、文件上传扫描、样本上报、平台状态。
"""
import os
import time
import requests
from typing import Optional


class AndunClient:
    """AndunAI 云查杀平台 API 客户端"""

    def __init__(self, base_url: str = "http://shadu.zh.kg",
                 api_key: str = "", timeout: int = 10):
        """
        初始化客户端

        Args:
            base_url: 平台地址, 例如 http://shadu.zh.kg
            api_key: 可选平台 API 密钥 (若平台启用鉴权)
            timeout: 请求超时(秒)
        """
        self.base_url = (base_url or "http://shadu.zh.kg").rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._last_error = None
        self._last_status = None
        self.session = requests.Session()
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

    @property
    def available(self) -> bool:
        return bool(self.base_url)

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def _post(self, path: str, json_body: dict | None = None,
              files: dict | None = None, timeout: int | None = None) -> dict:
        """发送 POST 请求并解析 JSON"""
        self._last_error = None
        resp = self.session.post(
            f"{self.base_url}{path}",
            json=json_body,
            files=files,
            timeout=timeout or self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def _get(self, path: str, timeout: int | None = None) -> dict:
        self._last_error = None
        resp = self.session.get(
            f"{self.base_url}{path}",
            timeout=timeout or self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ── 哈希查询 ──

    def query_hash(self, hash_value: str) -> dict:
        """按哈希查询（本地库 + 在线情报），返回平台原始结果"""
        return self._post("/api/scan/hash", {"hash_value": hash_value.strip().lower()})

    # ── 文件上传扫描 ──

    def scan_file(self, file_path: str) -> dict:
        """上传文件做多层比对扫描（本地 → YARA → 启发式 → 在线）"""
        if not os.path.isfile(file_path):
            self._last_error = "文件不存在"
            return {"found": False, "error": "文件不存在"}
        with open(file_path, "rb") as f:
            return self._post(
                "/api/scan",
                files={"file": (os.path.basename(file_path), f)},
                timeout=max(self.timeout, 30),
            )

    # ── 样本上报 ──

    def submit_file(self, file_path: str, threat_name: str = "",
                    threat_type: str = "", reporter: str = "yutian",
                    description: str = "", source: str = "",
                    tags: Optional[list] = None) -> dict:
        """上传文件上报样本（平台自动比对后入库）"""
        if not os.path.isfile(file_path):
            self._last_error = "文件不存在"
            return {"success": False, "error": "文件不存在"}
        data = {"reporter": reporter or "yutian"}
        if threat_name:
            data["threat_name"] = threat_name
        if threat_type:
            data["threat_type"] = threat_type
        if description:
            data["description"] = description
        if source:
            data["source"] = source
        if tags:
            data["tags"] = tags
        with open(file_path, "rb") as f:
            return self._post(
                "/api/submit",
                files={"file": (os.path.basename(file_path), f)},
                timeout=max(self.timeout, 30),
            )

    def submit_hash(self, sha256: str, threat_name: str = "",
                    threat_type: str = "", reporter: str = "yutian",
                    description: str = "", source: str = "",
                    tags: Optional[list] = None) -> dict:
        """上报哈希（不含文件），仅记录威胁情报"""
        data = {"reporter": reporter or "yutian"}
        if sha256:
            data["sha256"] = sha256.strip().lower()
        if threat_name:
            data["threat_name"] = threat_name
        if threat_type:
            data["threat_type"] = threat_type
        if description:
            data["description"] = description
        if source:
            data["source"] = source
        if tags:
            data["tags"] = tags
        return self._post("/api/submit/hash", data)

    # ── 平台状态 ──

    def status(self) -> dict:
        """查询平台运行状态与统计"""
        try:
            stats = self._get("/api/stats", timeout=8)
            self._last_status = stats
            return {"ok": True, "stats": stats}
        except requests.exceptions.RequestException as e:
            self._last_error = str(e)
            return {"ok": False, "error": str(e)}

    def check_health(self) -> bool:
        """快速健康检查"""
        try:
            self._get("/health", timeout=5)
            return True
        except Exception:
            return False
