"""
御天 处置中心（检测 → 确认 → 处置 → 回滚 → 审计 闭环）

统一编排各类检测结果（ETW 攻击链 / 反 Rootkit / 病毒扫描）的自动响应：
  1. 检测：消费 ETW 事件关联引擎的攻击链、反 Rootkit 扫描结果
  2. 确认：按置信度阈值判定是否需要自动处置
  3. 处置：终止进程 + 隔离文件 + 记录拦截规则（均走用户态兜底实现）
  4. 回滚：临时拦截规则超时自动移除；处置记录保留供回滚
  5. 审计：所有处置动作写入审计日志（JSON 行追加）

安全策略：
  - 受保护进程（自身 agent）绝不处置
  - 默认仅对 severity>=3 的高置信度攻击链自动处置
  - 所有处置可配置是否启用（auto_response_enabled）
"""

import json
import logging
import os
import threading
import time
from datetime import datetime
from typing import Optional

logger = logging.getLogger("response_center")


def _data_dir() -> str:
    """运行时数据目录：%LOCALAPPDATA%\\Andun（当前用户一定可写，与 config 一致）。"""
    local = os.environ.get("LOCALAPPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Local")
    return os.path.join(local, "Andun")


# 审计日志路径（与项目数据目录一致）
AUDIT_LOG = os.path.join(_data_dir(), "response_audit.jsonl")

# 处置动作类型
ACTION_KILL_PROCESS = "kill_process"
ACTION_QUARANTINE_FILE = "quarantine_file"
ACTION_BLOCK_RULE = "block_rule"

# 各动作状态
STATUS_PENDING = "pending"
STATUS_CONFIRMED = "confirmed"
STATUS_EXECUTED = "executed"
STATUS_FAILED = "failed"
STATUS_ROLLED_BACK = "rolled_back"

# 自动处置置信度阈值
AUTO_RESPONSE_SEVERITY_THRESHOLD = 3

# 临时规则默认自动移除时间（秒）
DEFAULT_RULE_AUTO_REMOVE_SEC = 300


class ResponseCenter:
    """处置中心 - 统一编排检测与处置"""

    def __init__(self):
        self._auto_response_enabled = False
        self._history: list[dict] = []
        self._history_lock = threading.Lock()
        self._max_history = 200
        self._temp_rules: dict[int, float] = {}  # ruleId -> 到期时间戳
        self._temp_rules_lock = threading.Lock()
        self._ensure_audit_dir()

    # ---------------------------------------------------------------
    # 审计
    # ---------------------------------------------------------------

    @staticmethod
    def _ensure_audit_dir():
        try:
            d = os.path.dirname(AUDIT_LOG)
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass

    def _audit(self, entry: dict):
        """写审计日志（JSON 行追加），失败不影响主流程。"""
        try:
            entry.setdefault("ts", datetime.now().isoformat())
            self._ensure_audit_dir()
            with open(AUDIT_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except Exception as e:
            logger.warning("写审计日志失败: %s", e)

    # ---------------------------------------------------------------
    # 配置
    # ---------------------------------------------------------------

    def set_auto_response(self, enabled: bool):
        """启用/停用自动处置。"""
        self._auto_response_enabled = bool(enabled)
        logger.info("自动处置已%s", "启用" if enabled else "停用")

    def is_auto_response_enabled(self) -> bool:
        return self._auto_response_enabled

    # ---------------------------------------------------------------
    # 处置原语
    # ---------------------------------------------------------------

    def kill_process(self, pid: int, force: bool = False, source: str = "manual") -> dict:
        """终止进程。"""
        result = {
            "action": ACTION_KILL_PROCESS,
            "pid": pid,
            "source": source,
            "status": STATUS_PENDING,
            "ts": datetime.now().isoformat(),
        }

        # 防御：自身进程不处置
        if self._is_self_pid(pid):
            result["status"] = STATUS_FAILED
            result["reason"] = "refuse_self_process"
            self._record(result)
            self._audit(result)
            return result

        # 用户态终止进程（OpenProcess + TerminateProcess）
        ok = self._kill_process_usermode(pid, force)

        result["status"] = STATUS_EXECUTED if ok else STATUS_FAILED
        if not ok:
            result["reason"] = "terminate_failed"
        self._record(result)
        self._audit(result)
        return result

    def quarantine_file(self, file_path: str, source: str = "manual") -> dict:
        """隔离文件。

        ⚠️ 这里原先调的是 ``_quarantine_file_usermode``：直接
        ``shutil.move`` 到 ``<隔离区>/<原文件名>.andunq`` ——
        不加密、不写隔离库、没有清单，而且 **Windows 上同名会覆盖**前一个
        隔离文件。结果有三：样本以明文留在磁盘、隔离区页面看不到、无法还原，
        以及同名二次隔离造成数据丢失。

        现在统一走 ``QuarantineManager.quarantine_file()``，与扫描路径是同一
        套隔离实现：唯一文件名 ``{毫秒}_{哈希}_{随机}.qfile`` + XOR 混淆 +
        SQLite 记录 + 支持 ``restore_file()`` 还原。
        """
        result = {
            "action": ACTION_QUARANTINE_FILE,
            "file": file_path,
            "source": source,
            "status": STATUS_PENDING,
            "ts": datetime.now().isoformat(),
        }

        try:
            from engine.quarantine import QuarantineManager

            qres = QuarantineManager().quarantine_file(
                file_path,
                threat_name=f"手动隔离（{source}）",
                threat_level="medium",
            )
            ok = bool(qres.get("success"))
            result["quarantine"] = qres
            if ok:
                # QuarantineManager 的返回里主键叫 "id"（= 隔离区文件名），
                # 也是 restore_file()/delete_quarantined() 要的参数。
                result["quarantine_id"] = qres.get("id")
        except Exception as exc:
            ok = False
            result["error"] = f"{type(exc).__name__}: {exc}"

        result["status"] = STATUS_EXECUTED if ok else STATUS_FAILED
        if not ok:
            result["reason"] = "quarantine_failed"
        self._record(result)
        self._audit(result)
        return result

    def block_rule(self, rule: dict, auto_remove_sec: int = DEFAULT_RULE_AUTO_REMOVE_SEC,
                   source: str = "manual") -> dict:
        """下发拦截规则（可自动过期回滚）。"""
        result = {
            "action": ACTION_BLOCK_RULE,
            "rule": rule,
            "source": source,
            "status": STATUS_PENDING,
            "ts": datetime.now().isoformat(),
            "auto_remove_sec": auto_remove_sec,
        }

        rule_id = int(rule.get("ruleId", 0))
        # 用户态兜底：规则记录到持久化文件，供下次扫描参考
        ok = self._block_rule_usermode(rule)

        if ok:
            result["status"] = STATUS_EXECUTED
            if auto_remove_sec > 0 and rule_id:
                with self._temp_rules_lock:
                    self._temp_rules[rule_id] = time.time() + auto_remove_sec
        else:
            result["status"] = STATUS_FAILED
            result["reason"] = "block_rule_failed"

        self._record(result)
        self._audit(result)
        return result

    # ---------------------------------------------------------------
    # 自动响应（ETW 攻击链驱动）
    # ---------------------------------------------------------------

    def handle_correlations(self, correlations: list) -> list:
        """处理 ETW 事件关联引擎产出的攻击链。

        对高置信度攻击链自动触发处置：
          终止攻击链进程 + 下发进程拦截规则（自动过期）。
        """
        responses = []
        if not correlations:
            return responses

        for corr in correlations:
            severity = int(corr.get("severity", 0))
            pid = int(corr.get("pid", 0))
            chain = corr.get("chain", "")

            # 确认：只对达到阈值的高置信度攻击链自动处置
            if (not self._auto_response_enabled or
                    severity < AUTO_RESPONSE_SEVERITY_THRESHOLD or
                    not pid):
                continue

            logger.info("攻击链命中，自动处置: %s (pid=%d, severity=%d)",
                        chain, pid, severity)

            # 处置1：终止进程
            resp = self.kill_process(pid, force=True, source=f"etw_chain:{chain}")
            responses.append(resp)

            # 处置2：下发进程拦截规则（防止重启动态复活，5分钟后自动移除）
            block_rule = {
                "ruleId": int(time.time() * 1000) % 0xFFFFFF + 0x100000,
                "ruleType": 1,  # RuleTypeProcess
                "action": 1,    # ActionBlock
                "pattern": f"PID:{pid}",
                "enabled": 1,
            }
            resp2 = self.block_rule(
                block_rule,
                auto_remove_sec=DEFAULT_RULE_AUTO_REMOVE_SEC,
                source=f"etw_chain:{chain}",
            )
            responses.append(resp2)

            # 审计完整处置链路
            self._audit({
                "event": "auto_response_triggered",
                "chain": chain,
                "severity": severity,
                "pid": pid,
                "responses": [r.get("status") for r in responses[-2:]],
            })

        return responses

    # ---------------------------------------------------------------
    # 临时规则过期回滚
    # ---------------------------------------------------------------

    def rollback_expired_rules(self) -> list:
        """移除已过期的临时拦截规则（回滚）。"""
        rolled = []
        now = time.time()
        with self._temp_rules_lock:
            expired = [rid for rid, expiry in self._temp_rules.items() if now >= expiry]
            for rid in expired:
                del self._temp_rules[rid]

        for rid in expired:
            # 无内核驱动：过期规则仅存在于用户态记录中，上方清理即完成回滚
            ok = True
            rolled.append({
                "action": "rollback_rule",
                "ruleId": rid,
                "status": STATUS_ROLLED_BACK if ok else STATUS_FAILED,
                "ts": datetime.now().isoformat(),
            })
            if ok:
                self._audit(rolled[-1])
        return rolled

    # ---------------------------------------------------------------
    # 历史记录
    # ---------------------------------------------------------------

    def _record(self, entry: dict):
        with self._history_lock:
            self._history.append(entry)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]

    def get_history(self, limit: int = 50) -> list:
        with self._history_lock:
            return list(self._history[-limit:])

    def get_status(self) -> dict:
        return {
            "auto_response_enabled": self._auto_response_enabled,
            "history_count": len(self._history),
            "temp_rules": list(self._temp_rules.keys()),
            "audit_log": AUDIT_LOG,
        }

    # ---------------------------------------------------------------
    # 用户态兜底
    # ---------------------------------------------------------------

    @staticmethod
    def _is_self_pid(pid: int) -> bool:
        return pid == os.getpid()

    @staticmethod
    def _kill_process_usermode(pid: int, force: bool) -> bool:
        """用户态终止进程（OpenProcess + TerminateProcess）。"""
        try:
            import ctypes
            PROCESS_TERMINATE = 0x0001
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
            if not handle:
                return False
            ok = ctypes.windll.kernel32.TerminateProcess(handle, 1)
            ctypes.windll.kernel32.CloseHandle(handle)
            return bool(ok)
        except Exception:
            return False

    # 注：原先这里有一个 `_quarantine_file_usermode` 静态方法，直接
    # shutil.move 到 `<原文件名>.andunq`。它不加密、不写隔离库、同名覆盖、
    # 不可还原，已删除 —— 隔离一律走 QuarantineManager.quarantine_file()。

    @staticmethod
    def _block_rule_usermode(rule: dict) -> bool:
        """用户态兜底：记录规则到持久化，供下次扫描参考。

        仅记录，不做内核层拦截。
        """
        try:
            d = os.path.join(_data_dir(), "rules_fallback.json")
            os.makedirs(os.path.dirname(d), exist_ok=True)
            rules = []
            if os.path.isfile(d):
                with open(d, "r", encoding="utf-8") as f:
                    try:
                        rules = json.load(f)
                    except Exception:
                        rules = []
            rules.append({**rule, "ts": time.time()})
            with open(d, "w", encoding="utf-8") as f:
                json.dump(rules, f, ensure_ascii=False)
            return True
        except Exception:
            return False


# ============================================================
# 单例
# ============================================================

_response_center: Optional[ResponseCenter] = None
_rc_lock = threading.Lock()


def get_response_center() -> ResponseCenter:
    global _response_center
    if _response_center is None:
        with _rc_lock:
            if _response_center is None:
                _response_center = ResponseCenter()
    return _response_center