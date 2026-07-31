"""
漏洞数据库下载器 - 从 CNNVD、NVD/CVE 下载漏洞数据
"""
import os
import time
import json
import threading
import gzip
import tarfile
import lzma
import requests
import zipfile
import io
from engine.vuln_database import VulnerabilityDatabase

# NVD CVE API 2.0
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CNNVD XML 下载页面（免费公开）
CNNVD_BASE = "https://www.cnnvd.org.cn"


class VulnerabilityDownloader:
    """漏洞数据库下载器"""

    def __init__(self, db: VulnerabilityDatabase = None):
        self.db = db or VulnerabilityDatabase()
        self._status = {"downloading": False, "progress": 0, "total": 0, "imported": 0,
                         "current_source": "", "errors": []}

    @property
    def status(self) -> dict:
        return dict(self._status)

    def download_from_nvd(self, limit: int = 2000, start_index: int = 0) -> dict:
        """
        从 NVD (美国国家漏洞数据库) 下载 CVE 数据
        NVD API 无需认证即可使用（但建议加 API Key 提高限速）
        """
        self._status = {"downloading": True, "progress": 0, "total": limit,
                         "imported": 0, "current_source": "NVD (nist.gov)", "errors": []}

        imported = 0
        page_size = min(limit, 100)
        current = start_index

        try:
            while current < start_index + limit:
                params = {
                    "resultsPerPage": page_size,
                    "startIndex": current,
                    "noRejected": None
                }
                resp = requests.get(NVD_API, params=params, timeout=30, headers={
                    "User-Agent": "AnDun-Antivirus/1.0"
                })

                if resp.status_code != 200:
                    self._status["errors"].append(f"NVD API {resp.status_code}")
                    break

                data = resp.json()
                count = self.db.import_from_nvd_json(data)
                imported += count
                current += page_size

                self._status["progress"] = min(current - start_index, limit)
                self._status["imported"] = imported

                if count == 0 or current >= data.get("totalResults", 0):
                    break

                time.sleep(0.6)  # NVD API 限速

        except Exception as e:
            self._status["errors"].append(str(e))

        self._status["downloading"] = False
        return {"source": "NVD (nist.gov)", "imported": imported, "errors": len(self._status["errors"])}

    def download_community_feed(self, limit: int = 5000) -> dict:
        """
        从 fkie-cad 社区镜像下载 NVD JSON feed（GitHub Releases，更快速）
        约 36万条 CVE 数据，支持 .zip / .json.xz / .tar.gz / .gz 格式
        
        社区镜像最新格式为 .json.xz（单文件 lzma 压缩），逐个年份文件下载
        """
        self._status = {"downloading": True, "progress": 0, "total": limit,
                         "imported": 0, "current_source": "NVD Community Feed", "errors": []}

        imported = 0
        try:
            # 获取最新 release 下载链接
            api_url = "https://api.github.com/repos/fkie-cad/nvd-json-data-feeds/releases/latest"
            resp = requests.get(api_url, timeout=15, headers={
                "User-Agent": "AnDun-Antivirus/1.0"
            })

            if resp.status_code != 200:
                self._status["errors"].append(f"GitHub API {resp.status_code}")
                self._status["downloading"] = False
                return {"source": "Community Feed", "imported": 0, "errors": 1}

            release = resp.json()
            assets = release.get("assets", [])
            download_url = None
            file_type = None  # "zip" / "tar" / "gz" / "xz_bundle"

            # 检查是否有 .json.xz 格式（新版社区镜像格式）
            xz_files = [a for a in assets if a.get("name", "").endswith(".json.xz")]
            if xz_files:
                file_type = "xz_bundle"
                # 下载多个 .json.xz 文件，但只取前N个年份的
                self._status["current_source"] = "NVD Community Feed (xz)"
                self._status["total"] = min(len(xz_files), 30)
                
                for i, a in enumerate(xz_files[:30]):
                    if imported >= limit:
                        break
                    fname = a["name"]
                    # 重试最多3次
                    for retry in range(3):
                        try:
                            dl_resp = requests.get(a["browser_download_url"], timeout=120,
                                                   headers={"User-Agent": "AnDun-Antivirus/1.0"})
                            if dl_resp.status_code != 200:
                                if retry < 2:
                                    time.sleep(2)
                                    continue
                                self._status["errors"].append(f"{fname}: HTTP {dl_resp.status_code}")
                                break
                            
                            raw = lzma.decompress(dl_resp.content)
                            content_str = raw.decode("utf-8")
                            data = json.loads(content_str)
                            
                            # 处理格式差异
                            data = self._normalize_json_feed(data)
                            count = self.db.import_from_nvd_json(data)
                            imported += count
                            break  # 成功，跳出重试
                        except Exception as e:
                            if retry < 2:
                                time.sleep(2)
                                continue
                            self._status["errors"].append(f"{fname}: {str(e)}")
                    
                    self._status["progress"] = i + 1
                    self._status["imported"] = imported
                    self._status["total"] = min(len(xz_files), 30)
                
                self._status["downloading"] = False
                return {"source": "NVD Community Feed (xz)", "imported": imported, 
                        "errors": len(self._status["errors"])}

            # 旧格式：找 .zip / .tar.gz / .gz
            for a in assets:
                name = a.get("name", "")
                if name.endswith(".zip"):
                    download_url = a["browser_download_url"]
                    file_type = "zip"
                    break
                elif name.endswith(".tar.gz") or name.endswith(".tgz"):
                    download_url = a["browser_download_url"]
                    file_type = "tar"
                    break
                elif name.endswith(".gz"):
                    download_url = a["browser_download_url"]
                    file_type = "gz"
                    break

            if not download_url:
                # GitHub API 可能被限流或没有 assets，回退到 NVD API
                self._status["current_source"] = "NVD (nist.gov) - 回退"
                self._status["errors"].append("未找到下载文件，回退到 NVD API")
                return self.download_from_nvd(limit=limit)

            # 下载文件
            dl_resp = requests.get(download_url, timeout=300, stream=True)
            if dl_resp.status_code != 200:
                self._status["errors"].append(f"下载失败 {dl_resp.status_code}")
                self._status["downloading"] = False
                return {"source": "Community Feed", "imported": 0, "errors": 1}

            # 根据文件类型解压
            content = io.BytesIO(dl_resp.content)
            file_list = []

            if file_type == "zip":
                with zipfile.ZipFile(content) as zf:
                    file_list = [(f, zf.read(f)) for f in zf.namelist() if f.endswith(".json")]
            elif file_type == "tar":
                with tarfile.open(fileobj=content, mode="r:gz") as tf:
                    for member in tf.getmembers():
                        if member.name.endswith(".json") and member.isfile():
                            f = tf.extractfile(member)
                            if f:
                                file_list.append((member.name, f.read()))
            elif file_type == "gz":
                raw = gzip.decompress(content.read())
                file_list = [("feed.json", raw)]

            self._status["total"] = len(file_list)

            for i, (fname, raw_content) in enumerate(file_list):
                if imported >= limit:
                    break
                try:
                    content_str = raw_content.decode("utf-8")
                    data = json.loads(content_str)
                    data = self._normalize_json_feed(data)
                    count = self.db.import_from_nvd_json(data)
                    imported += count
                except Exception as e:
                    self._status["errors"].append(f"{fname}: {str(e)}")

                self._status["progress"] = i + 1
                self._status["imported"] = imported

        except Exception as e:
            self._status["errors"].append(str(e))

        self._status["downloading"] = False
        return {"source": "NVD Community Feed", "imported": imported, "errors": len(self._status["errors"])}

    @staticmethod
    def _normalize_json_feed(data) -> dict:
        """将不同格式的 NVD JSON 标准化为 { vulnerabilities: [...] } 格式"""
        if isinstance(data, dict) and "vulnerabilities" in data:
            return data
        if isinstance(data, dict) and "cve" in data:
            return {"vulnerabilities": [data]}
        if isinstance(data, list):
            wrapped = []
            for item in data:
                if isinstance(item, dict) and "cve" in item:
                    wrapped.append(item)
                elif isinstance(item, dict) and "id" in item:
                    wrapped.append({"cve": item})
                else:
                    wrapped.append({"cve": item})
            return {"vulnerabilities": wrapped}
        if isinstance(data, dict) and "cve_items" in data:
            # 旧版 NVD 格式
            return {"vulnerabilities": [{"cve": item} for item in data["cve_items"]]}
        return {"vulnerabilities": []}

    def download_from_cnnvd(self) -> dict:
        """
        从 CNNVD (国家信息安全漏洞库) 下载漏洞数据
        
        CNNVD 官方网站需要登录才能下载，公开的 static/download 路径可能返回 HTML 页面。
        回退方案：通过 NVD API 搜索 Chinese 相关的 CVE，或使用 CNNVD 编号关联。
        """
        self._status = {"downloading": True, "progress": 0, "total": 1,
                         "imported": 0, "current_source": "CNNVD (cnnvd.org.cn)", "errors": []}

        imported = 0
        success = False
        
        # 尝试多个可能的 URL
        import datetime
        now = datetime.datetime.now()
        
        urls_to_try = [
            # CNNVD 按月发布的 ZIP
            (f"https://www.cnnvd.org.cn/static/download/CNNVD_{now.strftime('%Y%m')}.zip", "zip"),
            (f"https://www.cnnvd.org.cn/static/download/CNNVD_{now.strftime('%Y%m')}.xml", "xml"),
            # 上月
            (f"https://www.cnnvd.org.cn/static/download/CNNVD_{(now - datetime.timedelta(days=30)).strftime('%Y%m')}.zip", "zip"),
            (f"https://www.cnnvd.org.cn/static/download/CNNVD_{(now - datetime.timedelta(days=30)).strftime('%Y%m')}.xml", "xml"),
        ]
        
        for cnnvd_url, expected_type in urls_to_try:
            try:
                resp = requests.get(cnnvd_url, timeout=60, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Referer": "https://www.cnnvd.org.cn/home/dataDownLoad",
                    "Accept": "application/xml,application/zip,text/xml,*/*"
                })
                
                if resp.status_code != 200:
                    continue
                
                # 检查是否返回了 HTML 页面而非数据
                content_type = resp.headers.get("Content-Type", "")
                text = resp.text[:200] if resp.text else ""
                if "text/html" in content_type or text.strip().startswith("<!DOCTYPE") or text.strip().startswith("<html"):
                    continue  # 是 HTML 页面，跳过
                
                # 尝试解压 ZIP 或直接解析 XML
                if expected_type == "zip" or "zip" in content_type:
                    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                        for fname in zf.namelist():
                            if fname.endswith(".xml"):
                                xml_text = zf.read(fname).decode("utf-8", errors="ignore")
                                count = self.db.import_cnnvd_xml(xml_text)
                                imported += count
                                success = True
                else:
                    xml_text = resp.content.decode("utf-8", errors="ignore")
                    if xml_text.strip().startswith("<"):
                        count = self.db.import_cnnvd_xml(xml_text)
                        imported += count
                        success = True
                
                if success:
                    break
                    
            except Exception as e:
                continue
        
        if not success:
            # CNNVD 直接下载不可用，通过 NVD 补充中国相关 CVE
            self._status["current_source"] = "CNNVD (通过 NVD 关联)"
            self._status["errors"].append("CNNVD 直接下载不可用（需登录），尝试通过 NVD 获取中国相关漏洞")
            try:
                # 通过 NVD 搜索中文关键词相关的 CVE
                params = {
                    "keywordSearch": "China OR Chinese OR 中国",
                    "resultsPerPage": 50,
                }
                resp = requests.get(NVD_API, params=params, timeout=30, headers={
                    "User-Agent": "AnDun-Antivirus/1.0"
                })
                if resp.status_code == 200:
                    data = resp.json()
                    count = self.db.import_from_nvd_json(data)
                    imported += count
                    # 标记为 CNNVD 关联源
                    with __import__('sqlite3').connect(self.db.db_path) as conn:
                        conn.execute(
                            "UPDATE vulnerabilities SET source='cnnvd' WHERE source='nvd' AND imported_at > ?",
                            (time.time() - 10,)
                        )
                        conn.commit()
            except Exception as e:
                self._status["errors"].append(f"NVD 回退: {str(e)}")
        
        self._status["progress"] = 1
        self._status["imported"] = imported
        self._status["downloading"] = False
        return {"source": "CNNVD (cnnvd.org.cn)", "imported": imported, "errors": len(self._status["errors"])}

    def download_all(self) -> dict:
        """依次从所有数据源下载漏洞数据"""
        results = {}

        # 1. NVD 社区镜像（数据量大）
        results["nvd_community"] = self.download_community_feed(limit=5000)

        # 2. CNNVD
        results["cnnvd"] = self.download_from_cnnvd()

        return results
