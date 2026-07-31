"""
特征库管理器 - 哈希黑名单与规则管理
"""
import sqlite3
import os
import time
from config import SIGNATURES_DB

# 内建哈希种子：重建容器后依然生效（不依赖运行时插入）
# 来源：theZoo 样本库已知恶意样本哈希
SEED_SIGNATURES = [
    # Flame / Skywiper 32位内核驱动 (boot32drv.sys)，1300字节原始blob，无MZ头无可读字符串
    {"hash_type": "sha256",
     "hash_value": "029bcd72dc2ca4b31778cf4ee086038d8bd6c59ed2ed485e247aed56f909f881",
     "threat_name": "Win32/Flame (boot32drv.sys)",
     "threat_level": "high", "category": "rootkit", "source": "seed"},
    {"hash_type": "md5",
     "hash_value": "c81d037b723adc43e3ee17b1eee9d6cc",
     "threat_name": "Win32/Flame (boot32drv.sys)",
     "threat_level": "high", "category": "rootkit", "source": "seed"},
]


class SignatureManager:
    """管理本地特征库：哈希黑名单、威胁名称、版本控制"""

    def __init__(self, db_path: str = SIGNATURES_DB):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash_type TEXT NOT NULL CHECK(hash_type IN ('md5','sha1','sha256')),
                    hash_value TEXT NOT NULL UNIQUE,
                    threat_name TEXT NOT NULL,
                    threat_level TEXT NOT NULL CHECK(threat_level IN ('low','medium','high','critical')),
                    category TEXT DEFAULT 'unknown',
                    added_at REAL NOT NULL,
                    source TEXT DEFAULT 'local'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS signature_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.execute("""
                INSERT OR IGNORE INTO signature_meta (key, value)
                VALUES ('version', '1.0.0'), ('updated_at', ?)
            """, (str(time.time()),))
            # 播种内建哈希特征（幂等，重建容器不丢）
            for s in SEED_SIGNATURES:
                conn.execute(
                    "INSERT OR IGNORE INTO signatures "
                    "(hash_type, hash_value, threat_name, threat_level, category, added_at, source) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (s["hash_type"], s["hash_value"], s["threat_name"],
                     s["threat_level"], s["category"], time.time(), s["source"])
                )
            conn.commit()

    def lookup(self, md5: str = "", sha1: str = "", sha256: str = "") -> dict | None:
        """查找哈希是否在特征库中"""
        with sqlite3.connect(self.db_path) as conn:
            for hash_type, hash_val in [("md5", md5), ("sha1", sha1), ("sha256", sha256)]:
                if not hash_val:
                    continue
                row = conn.execute(
                    "SELECT threat_name, threat_level, category, source FROM signatures WHERE hash_type=? AND hash_value=?",
                    (hash_type, hash_val)
                ).fetchone()
                if row:
                    return {
                        "threat_name": row[0],
                        "threat_level": row[1],
                        "category": row[2],
                        "source": row[3],
                        "matched_hash": hash_type
                    }
        return None

    def add_signature(self, hash_type: str, hash_value: str, threat_name: str,
                      threat_level: str = "medium", category: str = "unknown", source: str = "manual"):
        """添加一条特征"""
        with sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute(
                    "INSERT INTO signatures (hash_type, hash_value, threat_name, threat_level, category, added_at, source) VALUES (?,?,?,?,?,?,?)",
                    (hash_type, hash_value, threat_name, threat_level, category, time.time(), source)
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def get_stats(self) -> dict:
        """获取特征库统计"""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
            by_level = conn.execute(
                "SELECT threat_level, COUNT(*) FROM signatures GROUP BY threat_level"
            ).fetchall()
            version = conn.execute(
                "SELECT value FROM signature_meta WHERE key='version'"
            ).fetchone()
            return {
                "total_signatures": total,
                "by_level": dict(by_level),
                "version": version[0] if version else "1.0.0"
            }

    def export_signatures(self, hash_type: str = "all") -> list[dict]:
        """导出特征列表"""
        with sqlite3.connect(self.db_path) as conn:
            if hash_type == "all":
                rows = conn.execute(
                    "SELECT hash_type, hash_value, threat_name, threat_level, category FROM signatures"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT hash_type, hash_value, threat_name, threat_level, category FROM signatures WHERE hash_type=?",
                    (hash_type,)
                ).fetchall()
            return [
                {"hash_type": r[0], "hash_value": r[1], "threat_name": r[2],
                 "threat_level": r[3], "category": r[4]}
                for r in rows
            ]
