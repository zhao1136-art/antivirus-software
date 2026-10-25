"""
报告与日志模块

⚠️ 日志写入**绝不能抛异常**。
2026-10-25 实测事故：打包版点"快速扫描"直接返回
`{"error":"internal_error","type":"PermissionError"}`，扫描根本没开始 ——
根因是 `open(SCAN_LOG_FILE, "a")` 撞上瞬时共享冲突（当时火绒 HipsDaemon
正在扫这个日志文件），而这里没有任何异常保护，异常一路冒到 FastAPI
变成 500，整个扫描任务就此失败。

日志是**旁路功能**：写不进去顶多丢一条记录，绝不该让核心业务失败。
所以这里改成"有限重试 + 最终静默放弃"。
"""
import os
import time
import json
from datetime import datetime
from config import LOGS_DIR, SCAN_LOG_FILE, THREAT_LOG_FILE

# 写日志失败时的重试次数与间隔（共享冲突通常是毫秒级瞬时的）
_LOG_RETRIES = 3
_LOG_RETRY_SLEEP = 0.05


def _append_line(path: str, line: str) -> bool:
    """向日志文件追加一行；失败重试，最终失败返回 False（**不抛异常**）。

    只捕获 OSError/PermissionError 一类 IO 问题；其他异常（如 json 序列化
    错误）也应被隔离，因为日志不能影响主流程。
    """
    for attempt in range(_LOG_RETRIES):
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
            return True
        except OSError:
            if attempt + 1 < _LOG_RETRIES:
                time.sleep(_LOG_RETRY_SLEEP)
    return False


class ReportLogger:
    """扫描日志与威胁报告"""

    def __init__(self):
        try:
            os.makedirs(LOGS_DIR, exist_ok=True)
        except OSError:
            pass

    def log_scan_start(self, task_id: str, scan_type: str):
        self._write_scan_log({
            "event": "scan_start",
            "task_id": task_id,
            "scan_type": scan_type,
            "timestamp": datetime.now().isoformat()
        })

    def log_scan_progress(self, task_id: str, current: int, total: int, current_file: str):
        pass  # 进度通过 WebSocket 实时推送，不写磁盘

    def log_scan_complete(self, task_id: str, stats: dict):
        self._write_scan_log({
            "event": "scan_complete",
            "task_id": task_id,
            "stats": stats,
            "timestamp": datetime.now().isoformat()
        })

    def log_threat(self, task_id: str, threat: dict):
        """记录威胁检出"""
        entry = {
            "task_id": task_id,
            "timestamp": datetime.now().isoformat(),
            "path": threat.get("path", ""),
            "threat_level": threat.get("threat_level", "unknown"),
            "engine": threat.get("engine", "unknown"),
            "signature": threat.get("signature", ""),
            "action": threat.get("action", "ignore"),
            "details": threat.get("details", {})
        }
        self._write_threat_log(entry)

    def get_scan_logs(self, limit: int = 50) -> list[dict]:
        """读取最近扫描日志"""
        return self._read_log(SCAN_LOG_FILE, limit)

    def get_threat_logs(self, limit: int = 100) -> list[dict]:
        """读取最近威胁日志"""
        return self._read_log(THREAT_LOG_FILE, limit)

    def get_stats(self) -> dict:
        """统计概览"""
        threats = self._read_log(THREAT_LOG_FILE, 10000)
        scans = self._read_log(SCAN_LOG_FILE, 1000)

        today = datetime.now().strftime("%Y-%m-%d")
        today_threats = [t for t in threats if t.get("timestamp", "").startswith(today)]

        total_scanned = 0
        for s in scans:
            if s.get("event") == "scan_complete" and "stats" in s:
                total_scanned += s["stats"].get("files_scanned", 0)

        return {
            "total_scanned": total_scanned,
            "today_blocked": len(today_threats),
            "total_threats": len(threats),
            "protection_days": self._calc_protection_days(scans)
        }

    def clear_logs(self):
        for f in [SCAN_LOG_FILE, THREAT_LOG_FILE]:
            try:
                if os.path.isfile(f):
                    open(f, "w").close()
            except OSError:
                # 清日志失败同样不该影响调用方
                pass

    # ---------- 内部方法 ----------

    def _write_scan_log(self, entry: dict):
        try:
            line = json.dumps(entry, ensure_ascii=False) + "\n"
        except (TypeError, ValueError):
            return
        _append_line(SCAN_LOG_FILE, line)

    def _write_threat_log(self, entry: dict):
        try:
            line = json.dumps(entry, ensure_ascii=False) + "\n"
        except (TypeError, ValueError):
            return
        _append_line(THREAT_LOG_FILE, line)

    def _read_log(self, path: str, limit: int) -> list[dict]:
        if not os.path.isfile(path):
            return []
        lines = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        lines.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        # 倒序取最近
        return list(reversed(lines))[:limit]

    def _calc_protection_days(self, scans: list[dict]) -> int:
        if not scans:
            return 1
        first_ts = None
        for s in scans:
            ts = s.get("timestamp", "")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts)
                    if first_ts is None or dt < first_ts:
                        first_ts = dt
                except Exception:
                    pass
        if first_ts:
            return max(1, (datetime.now() - first_ts).days)
        return 1
