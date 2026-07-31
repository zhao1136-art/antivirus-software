"""
病毒记忆管理模块
使用 SQLite 持久化记录每次扫描检出的病毒类型信息，
支持按病毒类型统计、搜索和去重。
"""
import os
import sqlite3
import threading
from datetime import datetime
from config import DATABASE_DIR


class VirusMemory:
    """管理病毒检出记录的记忆库"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(DATABASE_DIR, "virus_memory.db")
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _schema_path(self) -> str:
        """获取 schema.sql 路径（兼容开发模式和 PyInstaller 模式）"""
        # 优先与数据库同目录
        local = os.path.join(os.path.dirname(self.db_path), "schema.sql")
        if os.path.isfile(local):
            return local
        # 其次使用 DATABASE_DIR
        default = os.path.join(DATABASE_DIR, "schema.sql")
        if os.path.isfile(default):
            return default
        # 回退到源码目录
        src = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database", "schema.sql")
        if os.path.isfile(src):
            return src
        return default

    def _init_db(self):
        """初始化数据库：建表、建索引"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        schema_file = self._schema_path()
        if not os.path.isfile(schema_file):
            # schema 文件不存在时自动创建最小表结构
            self._create_minimal_schema()
            return
        with open(schema_file, "r", encoding="utf-8") as f:
            sql = f.read()
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        try:
            conn.executescript(sql)
            conn.commit()
        finally:
            conn.close()

    def _create_minimal_schema(self):
        """schema.sql 缺失时的兜底建表语句"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS virus_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    virus_type TEXT NOT NULL,
                    scan_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    sha256 TEXT NOT NULL,
                    md5 TEXT,
                    signature TEXT,
                    threat_level TEXT,
                    engine TEXT,
                    task_id TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_virus_sha256 ON virus_memory(sha256);
                CREATE INDEX IF NOT EXISTS idx_virus_type ON virus_memory(virus_type);
                CREATE INDEX IF NOT EXISTS idx_scan_time ON virus_memory(scan_time);
            """)
            conn.commit()
        finally:
            conn.close()

    def _connect(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def add_virus_record(self, file_path: str, virus_type: str, sha256: str,
                         md5: str = "", signature: str = "",
                         threat_level: str = "", engine: str = "",
                         task_id: str = "") -> bool:
        """添加或更新一条病毒记录（按 sha256 去重）"""
        if not sha256:
            return False
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("""
                    INSERT INTO virus_memory
                        (file_path, virus_type, sha256, md5, signature,
                         threat_level, engine, task_id, scan_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(sha256) DO UPDATE SET
                        file_path=excluded.file_path,
                        virus_type=excluded.virus_type,
                        md5=excluded.md5,
                        signature=excluded.signature,
                        threat_level=excluded.threat_level,
                        engine=excluded.engine,
                        task_id=excluded.task_id,
                        scan_time=excluded.scan_time
                """, (file_path, virus_type, sha256, md5 or "",
                      signature or "", threat_level or "", engine or "",
                      task_id or "", datetime.now().isoformat()))
                conn.commit()
                return True
            except Exception as e:
                print(f"[VirusMemory] 添加记录失败: {e}")
                return False
            finally:
                conn.close()

    def add_threat(self, threat: dict, task_id: str = "") -> bool:
        """从扫描器返回的威胁字典中自动提取信息并记录"""
        path = threat.get("path", "")
        sha256 = threat.get("sha256", "")
        if not sha256:
            return False
        # 病毒类型优先使用 category，其次 signature，最后 unknown
        virus_type = threat.get("category") or threat.get("signature") or "unknown"
        return self.add_virus_record(
            file_path=path,
            virus_type=virus_type,
            sha256=sha256,
            md5=threat.get("md5", ""),
            signature=threat.get("signature", ""),
            threat_level=threat.get("threat_level", ""),
            engine=threat.get("engine", ""),
            task_id=task_id
        )

    def get_recent_viruses(self, limit: int = 100,
                           keyword: str = "",
                           virus_type: str = "",
                           engine: str = "") -> list[dict]:
        """获取最近的病毒记录，支持按关键词、类型、引擎过滤"""
        conditions = []
        params = []
        if keyword:
            conditions.append("(file_path LIKE ? OR virus_type LIKE ? OR signature LIKE ?)")
            params.extend([f"%{keyword}%"] * 3)
        if virus_type:
            conditions.append("virus_type = ?")
            params.append(virus_type)
        if engine:
            conditions.append("engine = ?")
            params.append(engine)

        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        sql = f"""
            SELECT virus_type, file_path, scan_time, sha256, md5,
                   signature, threat_level, engine, task_id
            FROM virus_memory
            {where_clause}
            ORDER BY scan_time DESC
            LIMIT ?
        """
        params.append(limit)

        conn = self._connect()
        try:
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
            return [
                {
                    "virus_type": r[0],
                    "file_path": r[1],
                    "scan_time": r[2],
                    "sha256": r[3],
                    "md5": r[4],
                    "signature": r[5],
                    "threat_level": r[6],
                    "engine": r[7],
                    "task_id": r[8]
                }
                for r in rows
            ]
        finally:
            conn.close()

    def get_virus_count(self) -> dict:
        """统计各病毒类型出现次数"""
        conn = self._connect()
        try:
            cursor = conn.execute("""
                SELECT virus_type, COUNT(*) as count
                FROM virus_memory
                GROUP BY virus_type
                ORDER BY count DESC
            """)
            return {r[0]: r[1] for r in cursor.fetchall()}
        finally:
            conn.close()

    def get_engine_stats(self) -> dict:
        """统计各检测引擎检出数量"""
        conn = self._connect()
        try:
            cursor = conn.execute("""
                SELECT engine, COUNT(*) as count
                FROM virus_memory
                GROUP BY engine
                ORDER BY count DESC
            """)
            return {r[0] or "unknown": r[1] for r in cursor.fetchall()}
        finally:
            conn.close()

    def get_unique_virus_types(self) -> list[str]:
        """获取所有出现过的病毒类型列表"""
        conn = self._connect()
        try:
            cursor = conn.execute("""
                SELECT DISTINCT virus_type FROM virus_memory
                WHERE virus_type IS NOT NULL AND virus_type != ''
                ORDER BY virus_type
            """)
            return [r[0] for r in cursor.fetchall()]
        finally:
            conn.close()

    def clear_memory(self) -> bool:
        """清空所有病毒记忆记录"""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM virus_memory")
                conn.execute("DELETE FROM sqlite_sequence WHERE name='virus_memory'")
                conn.commit()
                return True
            except Exception as e:
                print(f"[VirusMemory] 清空记录失败: {e}")
                return False
            finally:
                conn.close()

    def get_total_count(self) -> int:
        """获取记忆库中病毒记录总数"""
        conn = self._connect()
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM virus_memory")
            return cursor.fetchone()[0]
        finally:
            conn.close()


# 全局单例
_virus_memory_instance: VirusMemory | None = None
_virus_memory_lock = threading.Lock()


def get_virus_memory() -> VirusMemory:
    """获取 VirusMemory 全局单例"""
    global _virus_memory_instance
    if _virus_memory_instance is None:
        with _virus_memory_lock:
            if _virus_memory_instance is None:
                _virus_memory_instance = VirusMemory()
    return _virus_memory_instance
