"""
御天 自定义规则管理引擎

支持用户创建自定义安全规则，规则由用户态规则引擎本地匹配生效。

规则类型：
  - file     文件操作（创建/写入/删除）
  - process  进程启动
  - registry 注册表修改
  - network  网络连接
  - handle   句柄操作

动作：
  - allow  允许
  - block  阻断
  - ask    询问（弹窗由用户决定）

特性：
  - 内置 20+ 预设规则模板，覆盖常见攻击场景
  - 规则持久化到 data/custom_rules.json
  - 内置状态查询，供前端展示规则总数与启用情况
  - 支持批量导入/导出
  - 线程安全（双重检查锁单例 + 实例锁）
"""

import os
import json
import threading
import time
import logging
from typing import Optional

# ============================================================
# 路径与常量
# ============================================================

# data 目录：backend/data/
_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data"
)
# 规则持久化文件
RULES_FILE = os.path.join(_DATA_DIR, "custom_rules.json")
# 日志目录
_LOG_DIR = os.path.join(_DATA_DIR, "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "custom_rules.log")


# ============================================================
# 日志器
# ============================================================

def _get_logger() -> logging.Logger:
    """获取自定义规则专用日志记录器"""
    os.makedirs(_LOG_DIR, exist_ok=True)
    logger = logging.getLogger("custom_rules")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(_LOG_FILE, encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(fh)
    return logger


# ============================================================
# CustomRuleEngine — 自定义规则管理引擎
# ============================================================

class CustomRuleEngine:
    """自定义规则管理引擎

    支持用户创建自定义安全规则，规则由用户态规则引擎本地匹配生效。
    规则类型：文件操作、进程启动、注册表修改、网络连接、句柄操作
    动作：允许、阻断、询问
    """

    # 规则类型映射（与 AndunRuleType 一致）
    RULE_TYPES = {"file": 0, "process": 1, "registry": 2, "network": 3, "handle": 4}

    # 动作映射（与 AndunAction 一致）
    ACTIONS = {"allow": 0, "block": 1, "ask": 2}

    # 预设规则模板（20+ 常用规则）
    TEMPLATES = [
        {"name": "阻止写入系统目录", "type": "file", "action": "block", "pattern": "C:\\Windows\\System32\\*"},
        {"name": "阻止修改启动项", "type": "registry", "action": "ask", "pattern": "*\\CurrentVersion\\Run\\*"},
        {"name": "阻止读取文档目录", "type": "file", "action": "ask", "pattern": "C:\\Users\\*\\Documents\\*"},
        {"name": "阻止可疑进程启动", "type": "process", "action": "block", "pattern": "*mimikatz*"},
        {"name": "阻止 PowerShell 执行", "type": "process", "action": "ask", "pattern": "powershell.exe"},
        {"name": "阻止 CMD 执行", "type": "process", "action": "ask", "pattern": "cmd.exe"},
        {"name": "阻止注册表启动项删除", "type": "registry", "action": "block", "pattern": "*\\CurrentVersion\\Run"},
        {"name": "阻止 hosts 文件修改", "type": "file", "action": "block", "pattern": "*\\drivers\\etc\\hosts"},
        {"name": "阻止可疑网络连接", "type": "network", "action": "block", "pattern": "*:4444"},  # Metasploit 默认端口
        {"name": "阻止远程桌面暴力破解", "type": "network", "action": "block", "pattern": "*:3389"},
        {"name": "阻止 SSH 暴力破解", "type": "network", "action": "block", "pattern": "*:22"},
        {"name": "阻止可疑 PowerShell 进程", "type": "process", "action": "block", "pattern": "powershell.exe"},
        {"name": "阻止 WScript 执行", "type": "process", "action": "ask", "pattern": "wscript.exe"},
        {"name": "阻止 MSHTA 执行", "type": "process", "action": "block", "pattern": "mshta.exe"},
        {"name": "阻止 RegSvr32 加载远程", "type": "process", "action": "ask", "pattern": "regsvr32.exe"},
        {"name": "阻止修改浏览器扩展", "type": "file", "action": "block", "pattern": "*\\Extensions\\*"},
        {"name": "保护注册表 Winlogon", "type": "registry", "action": "block", "pattern": "*\\Winlogon\\*"},
        {"name": "阻止 IFEO 劫持", "type": "registry", "action": "block", "pattern": "*\\Image File Execution Options\\*"},
        {"name": "阻止服务安装", "type": "registry", "action": "ask", "pattern": "*\\SYSTEM\\CurrentControlSet\\Services\\*"},
        {"name": "阻止驱动加载", "type": "process", "action": "ask", "pattern": "*sc.exe*"},
    ]

    def __init__(self):
        """初始化自定义规则引擎"""
        self._logger = _get_logger()

        # 规则列表：每条规则结构如下
        # {
        #     "id": int, "type": str, "action": str, "pattern": str,
        #     "description": str, "enabled": bool, "created_at": float,
        #     "driver_rule_id": int  # 兼容字段：规则序号（与 id 相同）
        # }
        self._rules: list[dict] = None  # 延迟加载
        self._rules_lock = threading.Lock()

        # 自增 ID 计数器
        self._next_id = 1

    def _ensure_rules(self):
        """延迟加载规则（首次访问时从磁盘读取）"""
        if self._rules is None:
            self._rules = []
            self._load_rules()
            self._log("info", f"自定义规则引擎初始化完成，已加载 {len(self._rules)} 条规则")

    # ── 规则增删改 ──

    def add_rule(self, rule_type: str, action: str, pattern: str,
                 description: str = "") -> Optional[int]:
        """添加一条自定义规则

        Args:
            rule_type: 规则类型（file/process/registry/network/handle）
            action: 动作（allow/block/ask）
            pattern: 匹配模式（支持 * 通配符）
            description: 规则描述

        Returns:
            成功返回规则 ID，失败返回 None
        """
        self._ensure_rules()
        # 参数校验
        if rule_type not in self.RULE_TYPES:
            self._log("error", f"无效的规则类型: {rule_type}")
            return None
        if action not in self.ACTIONS:
            self._log("error", f"无效的动作: {action}")
            return None
        if not pattern or not pattern.strip():
            self._log("error", "规则匹配模式不能为空")
            return None

        with self._rules_lock:
            rule_id = self._next_id
            self._next_id += 1

            rule = {
                "id": rule_id,
                "type": rule_type,
                "action": action,
                "pattern": pattern.strip(),
                "description": description,
                "enabled": True,
                "created_at": time.time(),
                "driver_rule_id": rule_id,  # 兼容字段：与本地 id 一致
            }
            self._rules.append(rule)

        # 持久化
        self._save_rules()

        self._log("info", f"新增规则 #{rule_id}: type={rule_type} action={action} pattern={pattern}")
        return rule_id

    def remove_rule(self, rule_id: int) -> bool:
        """删除一条规则

        Args:
            rule_id: 规则 ID

        Returns:
            成功返回 True，规则不存在返回 False
        """
        self._ensure_rules()
        with self._rules_lock:
            target = None
            for r in self._rules:
                if r["id"] == rule_id:
                    target = r
                    break
            if target is None:
                return False
            self._rules.remove(target)

        # 持久化
        self._save_rules()

        self._log("info", f"删除规则 #{rule_id}")
        return True

    def toggle_rule(self, rule_id: int, enabled: bool) -> bool:
        """启用或禁用规则

        Args:
            rule_id: 规则 ID
            enabled: True 启用 / False 禁用

        Returns:
            成功返回 True，规则不存在返回 False
        """
        self._ensure_rules()
        with self._rules_lock:
            target = None
            for r in self._rules:
                if r["id"] == rule_id:
                    target = r
                    break
            if target is None:
                return False
            target["enabled"] = bool(enabled)

        # 持久化
        self._save_rules()

        self._log("info", f"规则 #{rule_id} 已{'启用' if enabled else '禁用'}")
        return True

    # ── 规则查询 ──

    def get_rules(self, rule_type: Optional[str] = None) -> list[dict]:
        """获取规则列表

        Args:
            rule_type: 可选，按类型过滤（file/process/registry/network/handle）

        Returns:
            规则字典列表（深拷贝，避免外部修改）
        """
        self._ensure_rules()
        with self._rules_lock:
            if rule_type is None:
                return [dict(r) for r in self._rules]
            return [dict(r) for r in self._rules if r["type"] == rule_type]

    def get_templates(self) -> list[dict]:
        """获取预设规则模板列表

        Returns:
            模板字典列表（深拷贝）
        """
        return [dict(t) for t in self.TEMPLATES]

    # ── 批量导入/导出 ──

    def import_rules(self, rules_data: list[dict]) -> dict:
        """批量导入规则

        Args:
            rules_data: 规则字典列表，每项需包含 type/action/pattern 字段，
                        可选 name/description/enabled

        Returns:
            导入结果 {"total": int, "success": int, "failed": int, "ids": list[int]}
        """
        result = {"total": len(rules_data), "success": 0, "failed": 0, "ids": []}
        for item in rules_data:
            rule_type = item.get("type", "")
            action = item.get("action", "")
            pattern = item.get("pattern", "")
            description = item.get("description") or item.get("name", "")

            rule_id = self.add_rule(rule_type, action, pattern, description)
            if rule_id is not None:
                # 处理 enabled 字段（默认启用，若导入为 False 则禁用）
                if item.get("enabled", True) is False:
                    self.toggle_rule(rule_id, False)
                result["success"] += 1
                result["ids"].append(rule_id)
            else:
                result["failed"] += 1

        self._log("info", f"批量导入规则: 总计 {result['total']}，"
                          f"成功 {result['success']}，失败 {result['failed']}")
        return result

    def export_rules(self) -> list[dict]:
        """导出所有规则

        Returns:
            规则字典列表（包含元数据，可用于备份/迁移）
        """
        self._ensure_rules()
        with self._rules_lock:
            return [dict(r) for r in self._rules]

    # ── 持久化 ──

    def _save_rules(self) -> bool:
        """将规则列表持久化到 data/custom_rules.json"""
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            with self._rules_lock:
                data = {
                    "next_id": self._next_id,
                    "rules": [dict(r) for r in self._rules],
                    "saved_at": time.time(),
                }
            # 注意：锁外执行文件 IO，避免长时间持锁
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            self._log("error", f"规则持久化失败: {e}")
            return False

    def _load_rules(self) -> bool:
        """从 data/custom_rules.json 加载规则"""
        if not os.path.exists(RULES_FILE):
            return False
        try:
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            rules = data.get("rules", [])
            next_id = data.get("next_id", 1)

            with self._rules_lock:
                self._rules = rules
                # 修正 next_id（取已存在规则最大 id + 1）
                if rules:
                    max_id = max(r.get("id", 0) for r in rules)
                    self._next_id = max(next_id, max_id + 1)
                else:
                    self._next_id = next_id

            return True
        except Exception as e:
            self._log("error", f"规则加载失败: {e}")
            return False

    # ── 状态查询 ──

    def get_status(self) -> dict:
        """获取规则引擎完整状态"""
        with self._rules_lock:
            total = len(self._rules)
            enabled = sum(1 for r in self._rules if r.get("enabled", True))
            by_type: dict[str, int] = {}
            for r in self._rules:
                by_type[r["type"]] = by_type.get(r["type"], 0) + 1

        return {
            "total_rules": total,
            "enabled_rules": enabled,
            "disabled_rules": total - enabled,
            "rules_by_type": by_type,
            # 内核驱动/HIPS 防护层已移除，保留 key 供前端读取（恒为 False）
            "driver_available": False,
            "hips_available": False,
            "rules_file": RULES_FILE,
            "next_id": self._next_id,
        }

    # ── 日志 ──

    def _log(self, level: str, message: str) -> None:
        """记录日志"""
        try:
            getattr(self._logger, level, self._logger.info)(message)
        except Exception:
            pass


# ============================================================
# 单例模式（双重检查锁）
# ============================================================

_custom_rules: Optional[CustomRuleEngine] = None
_custom_rules_lock = threading.Lock()


def get_custom_rules() -> CustomRuleEngine:
    """获取全局唯一的 CustomRuleEngine 实例（双重检查锁定单例）

    Returns:
        全局唯一的 CustomRuleEngine 实例
    """
    global _custom_rules
    if _custom_rules is None:
        with _custom_rules_lock:
            if _custom_rules is None:
                _custom_rules = CustomRuleEngine()
    return _custom_rules


# ============================================================
# 模块自检（直接运行时执行）
# ============================================================

if __name__ == "__main__":
    # 仅测试规则增删改与持久化
    engine = CustomRuleEngine()

    print("[custom_rules] 状态:", engine.get_status())
    print("[custom_rules] 模板数量:", len(engine.get_templates()))

    # 添加一条测试规则
    rid = engine.add_rule("file", "block", "C:\\Test\\*", description="测试规则")
    print(f"[custom_rules] 新增规则 ID: {rid}")

    # 查询
    print("[custom_rules] 当前规则:", engine.get_rules())

    # 禁用再启用
    if rid is not None:
        engine.toggle_rule(rid, False)
        engine.toggle_rule(rid, True)

    # 导出
    exported = engine.export_rules()
    print(f"[custom_rules] 导出规则数: {len(exported)}")

    # 删除测试规则
    if rid is not None:
        engine.remove_rule(rid)
        print(f"[custom_rules] 已删除规则 #{rid}")

    print("[custom_rules] 最终状态:", engine.get_status())
