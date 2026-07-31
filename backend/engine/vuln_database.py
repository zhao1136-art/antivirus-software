"""
漏洞数据库管理 - 存储和查询 CNNVD/NVD/CVE 漏洞信息
"""
import sqlite3
import os
import json
import time
import xml.etree.ElementTree as ET
from config import VULN_DB


class VulnerabilityDatabase:
    """漏洞数据库管理器"""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or VULN_DB
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT,
                    cnnvd_id TEXT,
                    title TEXT,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_version TEXT,
                    affected_product TEXT,
                    affected_vendor TEXT,
                    cwe_id TEXT,
                    published_date TEXT,
                    modified_date TEXT,
                    reference_urls TEXT,
                    source TEXT DEFAULT 'unknown',
                    imported_at REAL NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cve ON vulnerabilities(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cnnvd ON vulnerabilities(cnnvd_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_product ON vulnerabilities(affected_product)")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vuln_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.commit()

    def get_count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]

    def import_from_nvd_json(self, data: dict) -> int:
        """从 NVD CVE API v2 响应导入"""
        imported = 0
        vulnerabilities = data.get("vulnerabilities", [])
        with sqlite3.connect(self.db_path) as conn:
            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                # 描述
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                # CVSS 评分
                severity, score, cvss_ver = "", 0.0, ""
                metrics = cve.get("metrics", {})
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    arr = metrics.get(key, [])
                    if arr:
                        cvss_data = arr[0].get("cvssData", {}) if isinstance(arr[0], dict) else {}
                        score = cvss_data.get("baseScore", 0)
                        severity = cvss_data.get("baseSeverity", "")
                        cvss_ver = cvss_data.get("version", "")
                        break

                # 受影响产品
                products, vendors = [], []
                for node in cve.get("configurations", []):
                    for match in node.get("nodes", []):
                        for m in match.get("cpeMatch", []):
                            criteria = m.get("criteria", "")
                            if criteria:
                                parts = criteria.split(":")
                                if len(parts) > 4:
                                    vendors.append(parts[3])
                                    products.append(parts[4])

                # CWE
                cwe = ""
                for w in cve.get("weaknesses", []):
                    for d in w.get("description", []):
                        cwe = d.get("value", "")
                        break

                # 日期
                published = cve.get("published", "")
                modified = cve.get("lastModified", "")

                # 参考链接
                refs = json.dumps([r.get("url", "") for r in cve.get("references", [])[:5]], ensure_ascii=False)

                try:
                    conn.execute("""
                        INSERT OR REPLACE INTO vulnerabilities
                        (cve_id, title, description, severity, cvss_score, cvss_version,
                         affected_product, affected_vendor, cwe_id, published_date,
                         modified_date, reference_urls, source, imported_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        cve_id, desc[:200], desc, severity, score, cvss_ver,
                        ",".join(set(products))[:500], ",".join(set(vendors))[:500],
                        cwe, published, modified, refs, "nvd", time.time()
                    ))
                    imported += 1
                except Exception:
                    continue
            conn.commit()
        return imported

    def search(self, keyword: str = "", severity: str = "", limit: int = 100,
               offset: int = 0, source: str = "") -> list[dict]:
        """搜索漏洞"""
        conditions = []
        params = []

        if keyword:
            conditions.append("(title LIKE ? OR description LIKE ? OR cve_id LIKE ? OR affected_product LIKE ? OR affected_vendor LIKE ?)")
            kw = f"%{keyword}%"
            params.extend([kw, kw, kw, kw, kw])

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())

        if source:
            conditions.append("source = ?")
            params.append(source)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        query = f"SELECT * FROM vulnerabilities{where} ORDER BY published_date DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    def search_count(self, keyword: str = "", severity: str = "", source: str = "") -> int:
        """搜索漏洞计数"""
        conditions = []
        params = []

        if keyword:
            conditions.append("(title LIKE ? OR description LIKE ? OR cve_id LIKE ? OR affected_product LIKE ?)")
            kw = f"%{keyword}%"
            params.extend([kw, kw, kw, kw])

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())

        if source:
            conditions.append("source = ?")
            params.append(source)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(f"SELECT COUNT(*) FROM vulnerabilities{where}", params).fetchone()[0]

    def get_stats(self) -> dict:
        """获取统计信息"""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            by_severity = dict(conn.execute(
                "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"
            ).fetchall())
            by_source = dict(conn.execute(
                "SELECT source, COUNT(*) FROM vulnerabilities GROUP BY source"
            ).fetchall())
            return {
                "total": total,
                "by_severity": by_severity,
                "by_source": by_source
            }

    def get_recent(self, limit: int = 20) -> list[dict]:
        """获取最近漏洞"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM vulnerabilities ORDER BY published_date DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def import_cnnvd_xml(self, xml_text: str) -> int:
        """从 CNNVD XML 格式导入漏洞"""
        imported = 0
        try:
            root = ET.fromstring(xml_text)
            with sqlite3.connect(self.db_path) as conn:
                for entry in root.findall(".//entry") if root.tag != "entry" else [root]:
                    cnnvd_id = self._xml_text(entry, "cnnvd_id") or self._xml_text(entry, "vuln-id")
                    cve_id = self._xml_text(entry, "cve-id")
                    title = self._xml_text(entry, "vuln-title") or self._xml_text(entry, "title")
                    desc = self._xml_text(entry, "vuln-descript") or self._xml_text(entry, "description")
                    severity = self._xml_text(entry, "hazard_level") or self._xml_text(entry, "severity")
                    score_str = self._xml_text(entry, "cvss_score") or "0"
                    try:
                        score = float(score_str)
                    except ValueError:
                        score = 0.0
                    product = self._xml_text(entry, "product") or self._xml_text(entry, "affected-software")
                    vendor = self._xml_text(entry, "vendor") or ""
                    cwe = self._xml_text(entry, "cwe-id") or ""
                    published = self._xml_text(entry, "create-time") or self._xml_text(entry, "published")
                    modified = self._xml_text(entry, "update-time") or self._xml_text(entry, "modified")

                    if not cnnvd_id and not cve_id:
                        continue

                    try:
                        conn.execute("""
                            INSERT OR IGNORE INTO vulnerabilities
                            (cve_id, cnnvd_id, title, description, severity, cvss_score,
                             affected_product, affected_vendor, cwe_id, published_date,
                             modified_date, reference_urls, source, imported_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            cve_id, cnnvd_id, (title or "")[:200], (desc or ""),
                            severity, score, (product or "")[:500], (vendor or "")[:200],
                            cwe, published, modified, "[]", "cnnvd", time.time()
                        ))
                        imported += 1
                    except Exception:
                        continue
                conn.commit()
        except ET.ParseError as e:
            return -1
        return imported

    @staticmethod
    def _xml_text(element, tag):
        child = element.find(tag) if hasattr(element, 'find') else None
        return child.text.strip() if child is not None and child.text else ""
