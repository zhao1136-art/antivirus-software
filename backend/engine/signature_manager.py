"""
特征库管理器 - 哈希黑名单与规则管理

P0 优化（单连接 + WAL + 内存索引 + 重试锁）:
  1. 全局复用一个 SQLite 连接（check_same_thread=False + threading.RLock 串行化），
     避免频繁 open/close、锁库与额外资源开销
  2. 启用 WAL + NORMAL 同步 + 64MB 缓存 + 内存临时表，提升读写性能
  3. 启动时把 MD5/SHA1/SHA256 全量载入内存字典，lookup 达到 O(1)
  4. 写操作带重试逻辑（指数退避，最多 4 次），应对极端锁冲突
"""
import sqlite3
import os
import time
import threading
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

# 写操作重试参数
_RETRY_TIMES = 4
_RETRY_BASE_DELAY = 0.05


# ── 全局单例：所有模块共享同一连接 + 同一内存索引 ──
_global_sig_mgr: "SignatureManager | None" = None
_global_lock = threading.Lock()


def get_signature_manager() -> "SignatureManager":
    """获取全局共享的特征库管理器实例（线程安全懒加载）"""
    global _global_sig_mgr
    if _global_sig_mgr is None:
        with _global_lock:
            if _global_sig_mgr is None:
                _global_sig_mgr = SignatureManager()
    return _global_sig_mgr


class SignatureManager:
    """管理本地特征库：哈希黑名单、威胁名称、版本控制"""

    def __init__(self, db_path: str = SIGNATURES_DB):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._lock = threading.RLock()  # 统一读写锁（RLock 允许重入）
        self._md5_idx: dict[str, tuple] = {}      # md5   -> (threat_name, level, cat, src)
        self._sha1_idx: dict[str, tuple] = {}     # sha1  -> ...
        self._sha256_idx: dict[str, tuple] = {}   # sha256 -> ...

        # 全局单连接复用（check_same_thread=False + 锁串行化）
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10.0)
        # 尝试启用 WAL。WAL 仅是性能优化，若文件系统/目录不支持（常见于受限目录、
        # 只读卷或安全软件拦截，报 disk I/O error），必须降级为默认 DELETE 日志模式，
        # 否则整个杀软在启动阶段直接崩溃。
        # 以下 PRAGMA 均为性能/健壮性优化。若目录受限、文件被锁定或安全软件拦截，
        # SQLite 会抛 disk I/O error，此时绝不能中断启动，需逐个安全降级。
        try:
            self._conn.execute("PRAGMA journal_mode=WAL;")  # 失败则保持默认 DELETE 日志模式
        except sqlite3.OperationalError as _wal_e:
            self._log(f"[签名库] WAL 启用失败，已回退默认日志模式: {_wal_e}")
        try:
            self._conn.execute("PRAGMA synchronous=NORMAL;")  # 失败则保持默认 FULL
        except sqlite3.OperationalError as _sync_e:
            self._log(f"[签名库] synchronous=NORMAL 失败，已回退默认模式: {_sync_e}")
        for _pragma, _desc in (
            ("PRAGMA cache_size=-65536;", "64MB 缓存"),
            ("PRAGMA temp_store=MEMORY;", "内存临时表"),
            ("PRAGMA busy_timeout=5000;", "锁等待 5 秒"),
        ):
            try:
                self._conn.execute(_pragma)
            except sqlite3.OperationalError as _e:
                self._log(f"[签名库] {_desc} 设置失败，已忽略: {_e}")

        # 建表/载入索引若因磁盘不可用（disk I/O error）失败，绝不能阻断杀软启动。
        # 已有表结构时下次启动可恢复；此处仅记录日志，交由上层按空库降级处理。
        try:
            self._init_db()
        except sqlite3.OperationalError as _e:
            self._log(f"[签名库] 初始化建表失败，已降级为空库继续启动: {_e}")
        try:
            self._load_index_to_memory()
        except sqlite3.OperationalError as _e:
            self._log(f"[签名库] 内存索引载入失败，已降级为按需查询: {_e}")

    def _log(self, msg: str):
        """安全日志输出：任何异常都不能阻断启动流程"""
        try:
            print(msg)
        except Exception:
            pass

    def close(self):
        """关闭共享连接（退出时调用）"""
        try:
            with self._lock:
                self._conn.close()
        except Exception:
            pass

    # ── 数据库初始化 ──
    def _init_db(self):
        with self._lock:
            self._conn.execute("""
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
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS signature_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            self._conn.execute("""
                INSERT OR IGNORE INTO signature_meta (key, value)
                VALUES ('version', '1.0.0'), ('updated_at', ?)
            """, (str(time.time()),))
            # 播种内建哈希特征（幂等，重建容器不丢）
            for s in SEED_SIGNATURES:
                self._conn.execute(
                    "INSERT OR IGNORE INTO signatures "
                    "(hash_type, hash_value, threat_name, threat_level, category, added_at, source) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (s["hash_type"], s["hash_value"], s["threat_name"],
                     s["threat_level"], s["category"], time.time(), s["source"])
                )
            self._conn.commit()

    # ── 内存索引（O(1) 查询）──
    def _load_index_to_memory(self):
        """把特征表全量载入内存字典（启动/批量导入后调用）"""
        with self._lock:
            self._md5_idx.clear()
            self._sha1_idx.clear()
            self._sha256_idx.clear()
            try:
                rows = self._conn.execute(
                    "SELECT hash_type, hash_value, threat_name, threat_level, category, source "
                    "FROM signatures"
                ).fetchall()
                for ht, hv, name, lvl, cat, src in rows:
                    tup = (name, lvl, cat, src)
                    if ht == "md5":
                        self._md5_idx[hv] = tup
                    elif ht == "sha1":
                        self._sha1_idx[hv] = tup
                    else:
                        self._sha256_idx[hv] = tup
            except Exception:
                pass

    # ── 写操作重试（指数退避）──
    def _execute_retry(self, fn):
        """执行写操作并带重试（最多 _RETRY_TIMES 次，指数退避）"""
        delay = _RETRY_BASE_DELAY
        for attempt in range(_RETRY_TIMES):
            try:
                return fn()
            except sqlite3.OperationalError as e:
                if "locked" not in str(e).lower() or attempt == _RETRY_TIMES - 1:
                    raise
                time.sleep(delay)
                delay *= 2

    # ── 查询 ──
    def lookup(self, md5: str = "", sha1: str = "", sha256: str = "") -> dict | None:
        """查找哈希是否在特征库中（内存索引 O(1)）"""
        with self._lock:
            if md5:
                t = self._md5_idx.get(md5.lower())
                if t:
                    return self._build_result(t, "md5")
            if sha1:
                t = self._sha1_idx.get(sha1.lower())
                if t:
                    return self._build_result(t, "sha1")
            if sha256:
                t = self._sha256_idx.get(sha256.lower())
                if t:
                    return self._build_result(t, "sha256")
        return None

    @staticmethod
    def _build_result(tup: tuple, hash_type: str) -> dict:
        return {
            "threat_name": tup[0],
            "threat_level": tup[1],
            "category": tup[2],
            "source": tup[3],
            "matched_hash": hash_type
        }

    # ── 写入 ──
    def add_signature(self, hash_type: str, hash_value: str, threat_name: str,
                      threat_level: str = "medium", category: str = "unknown",
                      source: str = "manual") -> bool:
        """添加一条特征（同步更新内存索引）"""
        hv = hash_value.lower()
        with self._lock:
            try:
                self._execute_retry(lambda: self._conn.execute(
                    "INSERT INTO signatures (hash_type, hash_value, threat_name, threat_level, category, added_at, source) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (hash_type, hv, threat_name, threat_level, category, time.time(), source)
                ))
                self._conn.commit()
            except sqlite3.IntegrityError:
                return False
            except sqlite3.OperationalError:
                return False
            # 同步内存索引
            tup = (threat_name, threat_level, category, source)
            idx = {"md5": self._md5_idx, "sha1": self._sha1_idx, "sha256": self._sha256_idx}.get(hash_type)
            if idx is not None:
                idx[hv] = tup
            return True

    # ── 元数据 ──
    def get_meta(self, key: str) -> str | None:
        with self._lock:
            try:
                row = self._conn.execute(
                    "SELECT value FROM signature_meta WHERE key=?", (key,)
                ).fetchone()
                return row[0] if row else None
            except Exception:
                return None

    def set_meta(self, key: str, value: str):
        with self._lock:
            try:
                self._execute_retry(lambda: self._conn.execute(
                    "INSERT OR REPLACE INTO signature_meta (key, value) VALUES (?, ?)",
                    (key, str(value))
                ))
                self._conn.commit()
            except Exception:
                pass

    def delete_meta(self, key: str):
        with self._lock:
            try:
                self._execute_retry(lambda: self._conn.execute(
                    "DELETE FROM signature_meta WHERE key=?", (key,)
                ))
                self._conn.commit()
            except Exception:
                pass

    # ── 统计 / 导出 ──
    def get_stats(self) -> dict:
        """获取特征库统计"""
        with self._lock:
            try:
                total = self._conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
                by_level = dict(self._conn.execute(
                    "SELECT threat_level, COUNT(*) FROM signatures GROUP BY threat_level"
                ).fetchall())
                version = self._conn.execute(
                    "SELECT value FROM signature_meta WHERE key='version'"
                ).fetchone()
                return {
                    "total_signatures": total,
                    "by_level": by_level,
                    "version": version[0] if version else "1.0.0"
                }
            except Exception:
                return {"total_signatures": 0, "by_level": {}, "version": "1.0.0"}

    def export_signatures(self, hash_type: str = "all") -> list[dict]:
        """导出特征列表"""
        with self._lock:
            try:
                if hash_type == "all":
                    rows = self._conn.execute(
                        "SELECT hash_type, hash_value, threat_name, threat_level, category FROM signatures"
                    ).fetchall()
                else:
                    rows = self._conn.execute(
                        "SELECT hash_type, hash_value, threat_name, threat_level, category FROM signatures WHERE hash_type=?",
                        (hash_type,)
                    ).fetchall()
                return [
                    {"hash_type": r[0], "hash_value": r[1], "threat_name": r[2],
                     "threat_level": r[3], "category": r[4]}
                    for r in rows
                ]
            except Exception:
                return []

    # ── 病毒库批量导入 ──
    def import_md5_text(self, txt_path: str, batch_size: int = 20000,
                        default_threat_name: str = "Trojan.Generic.Bingduku",
                        default_threat_level: str = "medium",
                        default_category: str = "trojan",
                        source: str = "bingduku_20260419") -> dict:
        """
        批量导入纯 MD5 哈希特征库文本文件（每行一个 32 位 MD5）。
        使用独立连接 + executemany + 事务（2 万条/批），36 万条约数秒内完成。
        导入完成后刷新内存索引，保证 lookup 立即可见。
        返回: {imported, skipped, total_lines, duration_ms, source_file, source}
        """
        import re
        t0 = time.time()
        if not txt_path or not os.path.isfile(txt_path):
            return {"imported": 0, "skipped": 0, "total_lines": 0,
                    "duration_ms": 0, "source_file": txt_path,
                    "error": "file not found"}

        md5_re = re.compile(r'^[a-fA-F0-9]{32}$')
        imported = 0
        skipped = 0
        total_lines = 0
        valid_md5 = 0
        batch = []
        added_ts = time.time()

        # 独立连接执行批量导入（不阻塞共享连接；MEMORY 日志 + 64MB 缓存提速）
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
            try:
                conn.execute("PRAGMA journal_mode = MEMORY")
            except Exception:
                pass
            conn.execute("PRAGMA synchronous = OFF")
            conn.execute("PRAGMA cache_size = -65536")  # 64MB 缓存
            conn.execute("PRAGMA temp_store = MEMORY")
            before = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]

            def _flush(buf):
                nonlocal imported, valid_md5
                if not buf:
                    return
                conn.executemany(
                    "INSERT OR IGNORE INTO signatures "
                    "(hash_type, hash_value, threat_name, threat_level, category, added_at, source) "
                    "VALUES (?,?,?,?,?,?,?)",
                    buf
                )
                conn.commit()  # 每批一个事务
                imported += len(buf)
                valid_md5 += len(buf)

            with open(txt_path, "r", encoding="utf-8", errors="ignore") as f:
                for raw in f:
                    s = raw.strip()
                    if not s:
                        continue
                    total_lines += 1
                    if not md5_re.match(s):
                        skipped += 1
                        continue
                    batch.append(("md5", s.lower(), default_threat_name,
                                  default_threat_level, default_category,
                                  added_ts, source))
                    if len(batch) >= batch_size:
                        _flush(batch)
                        batch = []
                _flush(batch)

            after = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
            # 实际新增 = 库增长量（INSERT OR IGNORE 去重后）
            real_imported = after - before
            duplicates = valid_md5 - real_imported
            if duplicates > 0:
                skipped += duplicates
                imported = real_imported

            conn.execute(
                "INSERT OR REPLACE INTO signature_meta (key, value) VALUES (?, ?)",
                ("updated_at", str(time.time()))
            )
            conn.commit()
        finally:
            conn.close()

        # 刷新内存索引（导入立即可查）
        self._load_index_to_memory()

        return {
            "imported": imported,
            "skipped": skipped,
            "total_lines": total_lines,
            "duration_ms": int((time.time() - t0) * 1000),
            "source_file": txt_path,
            "source": source,
        }

    # ── 签名库增量更新 ──
    def get_bingduku_version(self) -> str | None:
        """获取当前已导入的病毒库版本号"""
        return self.get_meta("bingduku_version")

    def set_bingduku_version(self, version: str):
        """设置当前病毒库版本号"""
        self.set_meta("bingduku_version", version)
        # 同时保留旧版标志以兼容
        self.set_meta(f"bingduku_{version}_imported", "1")

    def import_md5_incremental(self, txt_path: str, version: str,
                                batch_size: int = 20000,
                                default_threat_name: str = "Trojan.Generic.Bingduku",
                                default_threat_level: str = "medium",
                                default_category: str = "trojan") -> dict:
        """
        增量导入 MD5 病毒库（仅导入新版本相对于当前版本的新增签名）。
        
        策略：
        1. 读取当前已导入的版本号
        2. 如果版本号相同 → 跳过，返回 {incremental: true, skipped: "already up to date"}
        3. 如果无当前版本 → 回退到全量导入
        4. 如果有旧版本 → 将新版本文件逐行导入（INSERT OR IGNORE 自动去重）
        
        注意：增量导入依赖 INSERT OR IGNORE 去重机制，不依赖差异文件。
        适合场景：新版本文件中包含旧版本全部签名 + 新增签名的累积格式。
        
        返回: {incremental, imported, skipped, version, previous_version, duration_ms}
        """
        t0 = time.time()
        import re

        previous = self.get_bingduku_version()
        if previous == version:
            return {
                "incremental": True,
                "imported": 0,
                "skipped": 0,
                "version": version,
                "previous_version": previous,
                "status": "already_up_to_date",
                "duration_ms": int((time.time() - t0) * 1000),
            }

        if not txt_path or not os.path.isfile(txt_path):
            return {"incremental": True, "imported": 0, "skipped": 0,
                    "version": version, "previous_version": previous,
                    "error": "file not found"}

        md5_re = re.compile(r'^[a-fA-F0-9]{32}$')
        imported = 0
        skipped = 0
        total_lines = 0
        batch = []
        added_ts = time.time()
        source_tag = f"bingduku_{version}"

        # 通过独立连接 + MEMORY journal 执行批量导入
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
            try:
                conn.execute("PRAGMA journal_mode = MEMORY")
            except Exception:
                pass
            conn.execute("PRAGMA synchronous = OFF")
            conn.execute("PRAGMA cache_size = -65536")
            conn.execute("PRAGMA temp_store = MEMORY")
            before = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]

            def _flush(buf):
                nonlocal imported
                if not buf:
                    return
                conn.executemany(
                    "INSERT OR IGNORE INTO signatures "
                    "(hash_type, hash_value, threat_name, threat_level, category, added_at, source) "
                    "VALUES (?,?,?,?,?,?,?)",
                    buf
                )
                conn.commit()
                imported += len(buf)

            with open(txt_path, "r", encoding="utf-8", errors="ignore") as f:
                for raw in f:
                    s = raw.strip()
                    if not s:
                        continue
                    total_lines += 1
                    if not md5_re.match(s):
                        skipped += 1
                        continue
                    batch.append(("md5", s.lower(), default_threat_name,
                                  default_threat_level, default_category,
                                  added_ts, source_tag))
                    if len(batch) >= batch_size:
                        _flush(batch)
                        batch = []
                _flush(batch)

            after = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
            real_imported = after - before
            duplicates = imported - real_imported
            if duplicates > 0:
                skipped += duplicates
            imported = real_imported

            # 更新版本号
            conn.execute(
                "INSERT OR REPLACE INTO signature_meta (key, value) VALUES (?, ?)",
                ("bingduku_version", version)
            )
            conn.execute(
                "INSERT OR REPLACE INTO signature_meta (key, value) VALUES (?, ?)",
                (f"bingduku_{version}_imported", "1")
            )
            conn.execute(
                "INSERT OR REPLACE INTO signature_meta (key, value) VALUES (?, ?)",
                ("updated_at", str(time.time()))
            )
            conn.commit()
        finally:
            conn.close()

        # 刷新内存索引
        self._load_index_to_memory()

        return {
            "incremental": True,
            "imported": imported,
            "skipped": skipped,
            "total_lines": total_lines,
            "version": version,
            "previous_version": previous or "none",
            "status": "updated" if imported > 0 else "no_new_entries",
            "duration_ms": int((time.time() - t0) * 1000),
            "source_file": txt_path,
        }
