"""
隔离区管理器 - 样本隔离、还原、删除

本版修复的四个问题
------------------
1) **隔离样本不加密**（原实现只做 shutil.move + 改后缀：样本以原样躺在磁盘上，
   仍可执行、会被其它杀软反复扫到告警、改回扩展名就能跑）。
   现在隔离时立即用每文件独立的 32 字节随机密钥做异或混淆，密钥 hex 存库。
   为兼容本次改动之前已隔离的明文样本，xor_key 为空时按明文处理（不强行解密）。

2) **搬移与入库不是原子的**：原来 shutil.move 成功而 INSERT 失败时，
   文件已离开原位、数据库却没记录 —— 变成用户看不到也还原不了的孤儿。
   现在任一步失败都会回滚（把文件搬回原位 / 删掉隔离副本），绝不留下半成品。

3) **还原会静默覆盖**：原实现直接 shutil.move 回原路径，若该位置已有新文件
   就被无声覆盖，是真实的数据丢失路径。现在原路径被占用时改写为
   `原名 (已还原 N).扩展名`，并在返回值里告知实际落盘路径。

4) **_db_ok 标记了却没人检查**：restore/delete/list 三个方法没有异常兜底，
   数据库锁竞争或损坏时直接把异常抛给调用方（500）。
   现在全部捕获并返回结构化错误。

已知未做（如实记录）
--------------------
* 隔离表仍与签名库共用 SIGNATURES_DB，隔离操作会与签名读写争锁；
  并发扫描时仍可能遇到 database is locked（现在至少不会 500 了）。
* 跨盘时 shutil.move 会退化为 copy+delete，大文件没有进度、失败可能留下半个文件。
"""
import os
import shutil
import time
import sqlite3
import hashlib
import logging
import secrets
from datetime import datetime
from config import QUARANTINE_DIR, SIGNATURES_DB

log = logging.getLogger("yutian")

_XOR_KEY_BYTES = 32
_XOR_CHUNK = 1024 * 1024  # 1 MiB


def _xor_chunk(data: bytes, key: bytes, offset: int) -> bytes:
    """对 data 做异或，offset 保证跨块的密钥周期连续。

    用大整数异或而不是逐字节的 bytes(a ^ b for ...)：后者是 Python 级循环，
    1 MiB 要零点几秒，大文件会卡死；大整数异或是 C 层，快两个数量级。
    """
    klen = len(key)
    if klen == 0 or not data:
        return data
    reps = (len(data) + klen - 1) // klen + 1
    stream = (key * reps)[offset % klen: offset % klen + len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(len(data), "big")


def _xor_file(src: str, dst: str, key: bytes) -> None:
    """把 src 异或写入 dst（分块，跨块密钥连续）"""
    offset = 0
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while True:
            chunk = fi.read(_XOR_CHUNK)
            if not chunk:
                break
            fo.write(_xor_chunk(chunk, key, offset))
            offset += len(chunk)


class QuarantineManager:
    """管理隔离区：隔离样本、还原、删除"""

    def __init__(self):
        # 静默失败审计 P1：原来 makedirs 失败直接 pass —— 隔离区不可用却无人知晓，
        # 直到真正要隔离样本时才炸。现在如实记录，并把状态暴露出去。
        self._dir_ok = True
        try:
            os.makedirs(QUARANTINE_DIR, exist_ok=True)
        except Exception as e:
            self._dir_ok = False
            log.error("隔离目录不可用（%s）: %s —— 隔离功能将失败", QUARANTINE_DIR, e)
        self._db_ok = True
        self._init_db()

    # ── 数据库 ──
    def _connect(self):
        return sqlite3.connect(SIGNATURES_DB, timeout=10)

    def _init_db(self):
        # 磁盘I/O/锁不可用时降级为空库, 不阻塞启动(与 SignatureManager 容错一致)
        try:
            with self._connect() as conn:
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
                # 迁移：老库补 xor_key 列（旧记录为空 => 明文，按明文还原）
                cols = {r[1] for r in conn.execute("PRAGMA table_info(quarantine)")}
                if "xor_key" not in cols:
                    conn.execute("ALTER TABLE quarantine ADD COLUMN xor_key TEXT")
                conn.commit()
            self._db_ok = True
        except Exception:
            self._db_ok = False
            log.warning("隔离区数据库不可用, 降级为空库运行", exc_info=True)

    # ── 隔离 ──
    def quarantine_file(self, file_path: str, threat_name: str = "Unknown",
                        threat_level: str = "medium", file_hash: str = "",
                        hash_type: str = "sha256") -> dict:
        """将文件移入隔离区（搬移后立即异或混淆；任一步失败都回滚）"""
        if not os.path.isfile(file_path):
            return {"success": False, "error": "文件不存在"}

        moved = False
        encrypted = False
        quarantine_name = None
        quarantine_path = None
        key = None

        try:
            # 计算哈希
            if not file_hash:
                file_hash = self._hash_file(file_path)
                hash_type = "sha256"

            ts = int(time.time() * 1000)
            hash_prefix = file_hash[:12] if file_hash else "no_hash"
            # 唯一性：毫秒时间戳可能撞（同毫秒隔离同哈希的两个文件会违反 UNIQUE 约束），
            # 加随机后缀兜底，避免 INSERT 失败把文件留在中间态。
            quarantine_name = f"{ts}_{hash_prefix}_{secrets.token_hex(4)}.qfile"
            quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)

            file_size = os.path.getsize(file_path)
            original_mtime = os.path.getmtime(file_path)

            shutil.move(file_path, quarantine_path)
            moved = True

            # 立即混淆：隔离区里绝不留明文样本
            key = secrets.token_bytes(_XOR_KEY_BYTES)
            tmp_path = quarantine_path + ".tmp"
            try:
                _xor_file(quarantine_path, tmp_path, key)
                os.replace(tmp_path, quarantine_path)
                encrypted = True
            except Exception:
                # 混淆失败：删掉半成品，把文件搬回原位，保证不留明文在隔离区
                try:
                    if os.path.isfile(tmp_path):
                        os.remove(tmp_path)
                except Exception as _ce:
                    # 清理失败不影响主流程（下面会 raise 真正的错误），但要留痕
                    log.debug("清理隔离半成品失败 %s: %s", tmp_path, _ce)
                try:
                    shutil.move(quarantine_path, file_path)
                    moved = False
                except Exception:
                    log.error("混淆失败且无法回滚 %s", file_path, exc_info=True)
                raise

            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO quarantine
                    (original_path, quarantine_name, file_hash_type, file_hash, threat_name,
                     threat_level, file_size, quarantined_at, original_mtime, xor_key)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (os.path.abspath(file_path), quarantine_name, hash_type, file_hash,
                     threat_name, threat_level, file_size, time.time(), original_mtime,
                     key.hex())
                )
                conn.commit()

            return {
                "success": True,
                "id": quarantine_name,
                "original_path": os.path.abspath(file_path),
                "quarantine_path": quarantine_path,
                "threat_name": threat_name,
                "threat_level": threat_level,
                "file_hash": file_hash,
                "encrypted": True,
            }
        except Exception as e:
            # 入库失败：把已经搬走（并可能已混淆）的文件还原回原位，否则它就是孤儿
            # —— 用户既看不到也还原不了，而样本还以原样躺在隔离区里。
            if moved and quarantine_path and os.path.isfile(quarantine_path):
                try:
                    if os.path.exists(file_path):
                        # 原位已被占用，不覆盖；保留隔离副本，记日志让用户能手动找回
                        log.error("回滚时原路径已被占用，隔离副本保留在 %s", quarantine_path)
                    elif encrypted and key:
                        # 异或是对合运算：再异或同一个 key 就还原
                        _xor_file(quarantine_path, file_path, key)
                        os.remove(quarantine_path)
                        moved = False
                    else:
                        shutil.move(quarantine_path, file_path)
                        moved = False
                except Exception:
                    log.error("回滚失败，样本仍留在隔离区: %s -> %s",
                              file_path, quarantine_path, exc_info=True)
            return {"success": False, "error": str(e)}

    # ── 还原 ──
    def restore_file(self, quarantine_id) -> dict:
        """还原隔离文件。原路径被占用时改名放置，绝不覆盖。"""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT id, original_path, quarantine_name, xor_key, original_mtime "
                    "FROM quarantine WHERE id=? OR quarantine_name=?",
                    (quarantine_id, quarantine_id)
                ).fetchone()
        except Exception as e:
            return {"success": False, "error": f"数据库不可用: {e}"}

        if not row:
            return {"success": False, "error": "隔离记录不存在"}

        _, original_path, quarantine_name, xor_key, original_mtime = row
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)

        if not os.path.isfile(quarantine_path):
            return {"success": False, "error": "隔离文件丢失"}

        dest = original_path
        try:
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            # 不覆盖：原位置已有文件时改名
            if os.path.exists(dest):
                base, ext = os.path.splitext(dest)
                n = 1
                while os.path.exists(f"{base} (已还原 {n}){ext}"):
                    n += 1
                    if n > 999:
                        return {"success": False, "error": "原目录同名文件过多，请手动指定路径"}
                dest = f"{base} (已还原 {n}){ext}"

            if xor_key:
                key = bytes.fromhex(xor_key)
                tmp_path = dest + ".restoring"
                _xor_file(quarantine_path, tmp_path, key)
                os.replace(tmp_path, dest)
                os.remove(quarantine_path)
            else:
                # 本版之前隔离的明文样本
                shutil.move(quarantine_path, dest)

            if original_mtime:
                try:
                    os.utime(dest, (time.time(), float(original_mtime)))
                except Exception as _ue:
                    # 恢复原修改时间失败只影响取证价值，不影响还原成功 —— 但留痕
                    log.debug("还原后恢复 mtime 失败 %s: %s", dest, _ue)

            with self._connect() as conn:
                conn.execute("DELETE FROM quarantine WHERE quarantine_name=?", (quarantine_name,))
                conn.commit()

            return {"success": True, "original_path": dest,
                    "renamed": dest != original_path}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── 删除 ──
    def delete_quarantined(self, quarantine_id) -> dict:
        """永久删除隔离文件"""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT id, quarantine_name FROM quarantine WHERE id=? OR quarantine_name=?",
                    (quarantine_id, quarantine_id)
                ).fetchone()
        except Exception as e:
            return {"success": False, "error": f"数据库不可用: {e}"}

        if not row:
            return {"success": False, "error": "隔离记录不存在"}

        quarantine_name = row[1]
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)

        try:
            if os.path.isfile(quarantine_path):
                os.remove(quarantine_path)
            with self._connect() as conn:
                conn.execute("DELETE FROM quarantine WHERE quarantine_name=?", (quarantine_name,))
                conn.commit()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── 列表 ──
    def list_quarantined(self) -> list:
        """列出所有隔离文件"""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """SELECT id, original_path, quarantine_name, threat_name, threat_level,
                       file_hash, file_size, quarantined_at, xor_key FROM quarantine
                       ORDER BY quarantined_at DESC"""
                ).fetchall()
        except Exception:
            log.warning("读取隔离区列表失败", exc_info=True)
            return []

        result = []
        for r in rows:
            quarantine_path = os.path.join(QUARANTINE_DIR, r[2])
            result.append({
                "id": r[0],
                "original_path": r[1],
                "quarantine_name": r[2],
                "threat_name": r[3],
                "threat_level": r[4],
                "file_hash": r[5],
                "file_size": r[6],
                # 用带时区的本地时间，避免前端解析时偏几个钟头
                "quarantined_at": datetime.fromtimestamp(r[7]).astimezone().isoformat(),
                "file_exists": os.path.isfile(quarantine_path),
                "encrypted": bool(r[8]),
            })
        return result

    # ── 工具 ──
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
