"""
隔离区管理器 - 样本隔离、还原、删除
"""
import os
import shutil
import time
import sqlite3
import hashlib
from datetime import datetime
from config import QUARANTINE_DIR, SIGNATURES_DB


class QuarantineManager:
    """管理隔离区：隔离样本、还原、删除"""

    def __init__(self):
        try:
            os.makedirs(QUARANTINE_DIR, exist_ok=True)
        except Exception:
            pass
        self._db_ok = True
        self._init_db()

    def _init_db(self):
        # 磁盘I/O/锁不可用时降级为空库, 不阻塞启动(与 SignatureManager 容错一致)
        try:
            with sqlite3.connect(SIGNATURES_DB) as conn:
                conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_name TEXT NOT NULL UNIQUE,
                    file_hash_type TEXT,
                    file_hash TEXT,
                    threat_name TEXT,
                    threat_level TEXT,
                    file_size INTEGER,
                    quarantined_at REAL NOT NULL,
                    original_mtime REAL
                )
            """)
                conn.commit()
        except Exception:
            self._db_ok = False
            import logging
            logging.getLogger("yutian").warning("隔离区数据库不可用, 降级为空库运行", exc_info=True)

    def quarantine_file(self, file_path: str, threat_name: str = "Unknown",
                        threat_level: str = "medium", file_hash: str = "",
                        hash_type: str = "sha256") -> dict:
        """将文件移入隔离区"""
        if not os.path.isfile(file_path):
            return {"success": False, "error": "文件不存在"}

        # 计算哈希
        if not file_hash:
            file_hash = self._hash_file(file_path)
            hash_type = "sha256"

        # 生成隔离文件名（时间戳+哈希前缀）
        ts = int(time.time() * 1000)
        hash_prefix = file_hash[:12] if file_hash else "no_hash"
        quarantine_name = f"{ts}_{hash_prefix}.qfile"
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)

        try:
            file_size = os.path.getsize(file_path)
            original_mtime = os.path.getmtime(file_path)
            shutil.move(file_path, quarantine_path)

            # 写入数据库
            with sqlite3.connect(SIGNATURES_DB) as conn:
                conn.execute(
                    """INSERT INTO quarantine 
                    (original_path, quarantine_name, file_hash_type, file_hash, threat_name, threat_level, file_size, quarantined_at, original_mtime)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (os.path.abspath(file_path), quarantine_name, hash_type, file_hash,
                     threat_name, threat_level, file_size, time.time(), original_mtime)
                )
                conn.commit()

            return {
                "success": True,
                "id": quarantine_name,
                "original_path": os.path.abspath(file_path),
                "quarantine_path": quarantine_path,
                "threat_name": threat_name,
                "threat_level": threat_level,
                "file_hash": file_hash
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def restore_file(self, quarantine_id: str) -> dict:
        """还原隔离文件"""
        with sqlite3.connect(SIGNATURES_DB) as conn:
            row = conn.execute(
                "SELECT id, original_path, quarantine_name FROM quarantine WHERE id=? OR quarantine_name=?",
                (quarantine_id, quarantine_id)
            ).fetchone()

        if not row:
            return {"success": False, "error": "隔离记录不存在"}

        _, original_path, quarantine_name = row
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)

        if not os.path.isfile(quarantine_path):
            return {"success": False, "error": "隔离文件丢失"}

        try:
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            shutil.move(quarantine_path, original_path)

            with sqlite3.connect(SIGNATURES_DB) as conn:
                conn.execute("DELETE FROM quarantine WHERE quarantine_name=?", (quarantine_name,))
                conn.commit()

            return {"success": True, "original_path": original_path}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def delete_quarantined(self, quarantine_id: str) -> dict:
        """永久删除隔离文件"""
        with sqlite3.connect(SIGNATURES_DB) as conn:
            row = conn.execute(
                "SELECT id, quarantine_name FROM quarantine WHERE id=? OR quarantine_name=?",
                (quarantine_id, quarantine_id)
            ).fetchone()

        if not row:
            return {"success": False, "error": "隔离记录不存在"}

        quarantine_name = row[1]
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)

        try:
            if os.path.isfile(quarantine_path):
                os.remove(quarantine_path)

            with sqlite3.connect(SIGNATURES_DB) as conn:
                conn.execute("DELETE FROM quarantine WHERE quarantine_name=?", (quarantine_name,))
                conn.commit()

            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_quarantined(self) -> list[dict]:
        """列出所有隔离文件"""
        with sqlite3.connect(SIGNATURES_DB) as conn:
            rows = conn.execute(
                """SELECT id, original_path, quarantine_name, threat_name, threat_level, 
                   file_hash, file_size, quarantined_at FROM quarantine ORDER BY quarantined_at DESC"""
            ).fetchall()

        result = []
        for r in rows:
            quarantine_path = os.path.join(QUARANTINE_DIR, r[2])
            file_exists = os.path.isfile(quarantine_path)
            result.append({
                "id": r[0],
                "original_path": r[1],
                "quarantine_name": r[2],
                "threat_name": r[3],
                "threat_level": r[4],
                "file_hash": r[5],
                "file_size": r[6],
                "quarantined_at": datetime.fromtimestamp(r[7]).isoformat(),
                "file_exists": file_exists
            })
        return result

    def _hash_file(self, file_path: str) -> str:
        """计算文件 SHA256"""
        sha = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha.update(chunk)
        except Exception:
            return ""
        return sha.hexdigest()
