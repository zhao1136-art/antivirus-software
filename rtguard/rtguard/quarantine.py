"""隔离区（Quarantine）。

样本以「每文件独立密钥 XOR 混淆」的形式落盘，避免被其它杀软按原样再次报毒，
同时保证 100% 可逆还原（XOR 的逆运算就是它自己）。

存储布局::

    <qdir>\\<id>.qfile   混淆后的样本内容
    <qdir>\\index.json   元数据索引（原子写：先写 .tmp 再 os.replace）

仅依赖标准库。
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import threading
import time
import uuid

__all__ = ["Quarantine"]

_INDEX_NAME = "index.json"
_QFILE_SUFFIX = ".qfile"
_CHUNK = 1024 * 1024  # 1 MiB，分块处理，避免大文件一次性读入内存
_INDEX_VERSION = 1


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """按 key 循环异或 data；key 为空时原样返回。自逆运算。"""
    if not key:
        return data
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def _xor_stream(src, dst, key: bytes, offset: int = 0) -> None:
    """从 src 流式读出、异或后写入 dst。

    offset 是 src 起点在「密钥周期」中的位置，保证分块时密钥下标连续，
    因此分块加解密与整体加解密结果完全一致。
    """
    klen = len(key)
    pos = offset
    while True:
        chunk = src.read(_CHUNK)
        if not chunk:
            break
        if klen:
            dst.write(bytes(b ^ key[(pos + i) % klen] for i, b in enumerate(chunk)))
        else:
            dst.write(chunk)
        pos += len(chunk)


class Quarantine:
    """一个目录即一个隔离区。线程内加锁，避免索引互相覆盖。"""

    def __init__(self, qdir: str):
        self.qdir = os.path.abspath(os.fspath(qdir))
        self._lock = threading.RLock()
        os.makedirs(self.qdir, exist_ok=True)
        # 启动时尝试载入索引：损坏则备份并重建，绝不因此让模块不可用。
        try:
            self._load_index()
        except Exception:
            pass

    # ------------------------------------------------------------------ 路径

    @property
    def index_path(self) -> str:
        return os.path.join(self.qdir, _INDEX_NAME)

    def _qfile_path(self, qid: str) -> str:
        return os.path.join(self.qdir, f"{qid}{_QFILE_SUFFIX}")

    # ------------------------------------------------------------ 索引读写

    def _load_index(self) -> dict:
        """读取索引；损坏时把原文件改名备份并以空索引继续。"""
        path = self.index_path
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except Exception:
            self._backup_broken_index(path)
            return {}
        if not isinstance(raw, dict):
            self._backup_broken_index(path)
            return {}
        entries = raw.get("entries")
        if not isinstance(entries, dict):
            self._backup_broken_index(path)
            return {}
        clean: dict = {}
        for qid, meta in entries.items():
            if isinstance(qid, str) and isinstance(meta, dict):
                clean[qid] = meta
        return clean

    def _backup_broken_index(self, path: str) -> str | None:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        broken = f"{path}.broken-{stamp}-{uuid.uuid4().hex[:8]}"
        try:
            os.replace(path, broken)
            return broken
        except Exception:
            try:
                os.remove(path)
            except Exception:
                pass
            return None

    def _save_index(self, entries: dict) -> None:
        """原子写：先写 .tmp（并 fsync），再 os.replace 覆盖正式索引。"""
        payload = {"version": _INDEX_VERSION, "entries": entries}
        tmp = f"{self.index_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.index_path)

    # ---------------------------------------------------------------- 工具

    def _sha256_of(self, path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def _new_id(self, entries: dict) -> str:
        for _ in range(128):
            qid = uuid.uuid4().hex
            if qid in entries or os.path.exists(self._qfile_path(qid)):
                continue  # 极端碰撞：换一个，绝不覆盖已有条目
            return qid
        raise OSError("无法生成未占用的隔离条目标识")

    def _move_into_quarantine(self, path: str, target: str) -> None:
        """移动；跨盘等失败时退化为「复制 + 删除源文件」。"""
        try:
            os.replace(path, target)
            return
        except OSError:
            pass
        shutil.copy2(path, target)
        try:
            os.remove(path)
        except OSError:
            try:
                os.remove(target)
            except OSError:
                pass
            raise

    def _entry(self, qid: str) -> dict | None:
        entries = self._load_index()
        meta = entries.get(qid)
        if meta is None:
            # 索引丢失但样本仍在：退化为按文件名推断的最小元数据
            qfile = self._qfile_path(qid)
            if os.path.exists(qfile):
                return {
                    "id": qid,
                    "name": "",
                    "original_path": "",
                    "size": os.path.getsize(qfile),
                    "sha256": "",
                    "time": os.path.getmtime(qfile),
                    "key": "",
                }
            return None
        out = dict(meta)
        out["id"] = qid
        out.setdefault("name", os.path.basename(out.get("original_path", "") or ""))
        return out

    # ---------------------------------------------------------------- 接口

    def add(self, path: str, meta: dict | None = None) -> dict:
        """把 path 指向的文件移入隔离区，返回条目摘要。

        返回 ``{"id", "size", "sha256", "original_path", "time"}``。
        同一个路径重复隔离会得到不同的 id，不会覆盖已有条目。
        """
        src = os.path.abspath(os.fspath(path))
        if not os.path.isfile(src):
            raise FileNotFoundError(src)

        size = os.path.getsize(src)
        sha256 = self._sha256_of(src)

        with self._lock:
            entries = self._load_index()
            qid = self._new_id(entries)
            qfile = self._qfile_path(qid)
            key = secrets.token_bytes(32)  # 每文件独立密钥

            # 1) 先把原文件搬进隔离区（跨盘时退化为复制 + 删除）。
            self._move_into_quarantine(src, qfile)
            # 2) 再就地分块混淆，保证最终落盘内容不是原样。
            #    此步失败要回滚，绝不能让明文样本留在隔离区目录里。
            tmp = f"{qfile}.tmp"
            try:
                with open(qfile, "rb") as fin, open(tmp, "wb") as fout:
                    _xor_stream(fin, fout, key, 0)
                os.replace(tmp, qfile)
            except Exception:
                try:
                    if not os.path.exists(src):
                        os.replace(qfile, src)  # 原路径仍空着：放回去
                    else:
                        os.remove(qfile)
                except OSError:
                    pass
                raise
            finally:
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

            now = time.time()
            entry = {
                "id": qid,
                "name": os.path.basename(src),
                "original_path": src,
                "size": int(size),
                "sha256": sha256,
                "time": float(now),
                "key": key.hex(),
            }
            if isinstance(meta, dict):
                for k, v in meta.items():
                    if k not in entry:
                        entry[k] = v
            entries[qid] = entry
            self._save_index(entries)

        return {
            "id": qid,
            "size": int(size),
            "sha256": sha256,
            "original_path": src,
            "time": float(now),
        }

    def list(self) -> list:
        """返回全部条目（时间倒序）。每项至少含 id/size/sha256/original_path/time/name。"""
        with self._lock:
            entries = self._load_index()
        items = []
        for qid, meta in entries.items():
            if not isinstance(meta, dict):
                continue
            item = dict(meta)
            item["id"] = qid
            item.setdefault("size", 0)
            item.setdefault("sha256", "")
            item.setdefault("original_path", "")
            item.setdefault("time", 0.0)
            item.setdefault("name", os.path.basename(item.get("original_path", "") or ""))
            items.append(item)

        def _key(it):
            try:
                return float(it.get("time", 0.0))
            except (TypeError, ValueError):
                return 0.0

        items.sort(key=_key, reverse=True)
        return items

    def get(self, qid: str) -> dict | None:
        """取单个条目；不存在返回 None。"""
        with self._lock:
            return self._entry(qid)

    def restore(self, qid: str, dest: str | None = None) -> str:
        """还原到 dest 或原路径，返回实际写入路径。条目不存在抛 KeyError。"""
        with self._lock:
            entry = self._entry(qid)
            if entry is None:
                raise KeyError(qid)
            qfile = self._qfile_path(qid)
            if not os.path.exists(qfile):
                raise KeyError(qid)

            target = dest if dest else (entry.get("original_path") or "")
            if not target:
                raise KeyError(qid)
            target = os.path.abspath(os.fspath(target))

            parent = os.path.dirname(target)
            if parent:
                os.makedirs(parent, exist_ok=True)

            key = bytes.fromhex(entry.get("key") or "")
            tmp = f"{target}.rtguard-restore.tmp"
            try:
                with open(qfile, "rb") as fin, open(tmp, "wb") as fout:
                    _xor_stream(fin, fout, key, 0)
                os.replace(tmp, target)
            except Exception:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                raise
            return target

    def delete(self, qid: str) -> bool:
        """彻底删除条目（样本 + 元数据）。条目存在返回 True。"""
        with self._lock:
            entries = self._load_index()
            if qid not in entries:
                return False
            qfile = self._qfile_path(qid)
            # 先删样本再落索引：中途异常只会留下「索引指向已删文件」，
            # 而不会留下无法追溯的孤儿 .qfile。
            try:
                os.remove(qfile)
            except FileNotFoundError:
                pass
            except OSError:
                return False
            entries.pop(qid, None)
            self._save_index(entries)
            return True

    # ---------------------------------------------------------------- 兼容

    def __len__(self) -> int:
        return len(self._load_index())

    def __contains__(self, qid: object) -> bool:
        try:
            return self._entry(str(qid)) is not None
        except Exception:
            return False

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"<Quarantine {self.qdir!r} entries={len(self)}>"
