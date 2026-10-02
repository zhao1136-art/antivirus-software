"""
御天 勒索诱捕系统

通过在用户目录中部署伪装的诱饵文件（财务/客户/合同/数据库/密码），
快速识别全盘遍历加密的勒索软件行为。

工作原理：
  1. deploy() 在指定目录部署诱饵文件，设置隐藏+只读属性，记录 SHA256 基线
  2. 通过 kernel_bridge 向内核驱动下发文件保护规则（驱动可用时）
  3. check_all() 定期检查诱饵文件是否被篡改/加密/删除
  4. on_tamper() 在检测到篡改时阻断进程，触发防护，弹窗告警
  5. recall() 撤回所有诱饵文件

特性：
  - 5 种诱饵文件类型，覆盖勒索软件最关注的高价值目标
  - SHA256 哈希基线 + 内容特征双重校验
  - 驱动不可用时降级为用户态轮询监控
  - 基线持久化到 data/honeypot_baseline.json
  - 线程安全（双重检查锁单例 + 实例锁）
"""

import os
import sys
import json
import time
import hashlib
import threading
import subprocess
import logging
from datetime import datetime
from typing import Optional, Any

IS_WINDOWS = sys.platform == "win32"

# ============================================================
# 路径与常量
# ============================================================

# data 目录：backend/data/
_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data"
)
# 基线持久化文件
BASELINE_FILE = os.path.join(_DATA_DIR, "honeypot_baseline.json")
# 日志目录
_LOG_DIR = os.path.join(_DATA_DIR, "logs")
_LOG_FILE = os.path.join(_LOG_DIR, "honeypot.log")

# 诱饵文件检查间隔（秒）
CHECK_INTERVAL = 5

# 5 种诱饵文件类型模板（财务/客户/合同/数据库/密码）
# 每种类型包含文件名模板、伪装扩展名和内容模板
DECOY_TEMPLATES = [
    {
        "type": "finance",
        "name": "~财务数据_2025_Q4_加密备份.xlsx",
        "content": (
            "[财务报表]\n"
            "编制单位: 御天科技有限公司\n"
            "报告期间: 2025 年第四季度\n"
            "营业收入: ¥12,345,678.00\n"
            "营业成本: ¥5,432,100.00\n"
            "净利润: ¥2,345,678.00\n"
            "银行账号: 6222 02 **** **** 1234 567\n"
            "出纳: 张三  复核: 李四  审批: 王五\n"
        ),
    },
    {
        "type": "customer",
        "name": "~客户资料_核心名单_保密.db",
        "content": (
            "[客户信息表]\n"
            "ID,姓名,手机号,身份证号,地址\n"
            "1001,张三,138****1234,110***********0011,北京市朝阳区***\n"
            "1002,李四,139****5678,310***********0022,上海市浦东新区***\n"
            "1003,王五,137****9012,440***********0033,广州市天河区***\n"
            "1004,赵六,135****3456,510***********0044,深圳市南山区***\n"
        ),
    },
    {
        "type": "contract",
        "name": "~商业合同_2025_机密.docx",
        "content": (
            "[商业合作合同]\n"
            "甲方: 御天科技有限公司\n"
            "乙方: ***合作伙伴***\n"
            "合同编号: YT-2025-CONTRACT-0042\n"
            "签订日期: 2025-06-15\n"
            "合同金额: ¥1,000,000.00\n"
            "保密条款: 本合同内容属商业机密，未经书面许可不得向第三方披露。\n"
            "违约责任: 任何一方违约应支付合同金额 30% 的违约金。\n"
        ),
    },
    {
        "type": "database",
        "name": "~数据库备份_生产环境_最新.sql",
        "content": (
            "-- MySQL dump 10.13  Distrib 8.0.36, for Win64\n"
            "--\n"
            "-- Host: 127.0.0.1    Database: production_db\n"
            "-- ------------------------------------------------------\n"
            "-- Server version\t8.0.36\n\n"
            "CREATE TABLE `users` (\n"
            "  `id` int NOT NULL AUTO_INCREMENT,\n"
            "  `username` varchar(64) NOT NULL,\n"
            "  `password_hash` varchar(128) NOT NULL,\n"
            "  `email` varchar(128) DEFAULT NULL,\n"
            "  PRIMARY KEY (`id`)\n"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
        ),
    },
    {
        "type": "password",
        "name": "~密码本_请勿外传_重要.txt",
        "content": (
            "[账号密码本]\n"
            "警告: 本文件包含敏感信息，请妥善保管！\n\n"
            "邮箱: admin@example.com  密码: P@ssw0rd!2025\n"
            "VPN:  账号 admin         密码: Vpn#Secur3#2025\n"
            "服务器: root@10.0.0.1    密码: S3rv3r!R00t#2025\n"
            "数据库: db_admin         密码: Db@Adm1n#2025\n"
            "OA系统: zhangsan         密码: Oa#User#2025\n"
        ),
    },
]


# ============================================================
# 日志器
# ============================================================

def _get_logger() -> logging.Logger:
    """获取诱捕系统专用日志记录器"""
    os.makedirs(_LOG_DIR, exist_ok=True)
    logger = logging.getLogger("honeypot_manager")
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
# 工具函数
# ============================================================

def _file_sha256(path: str) -> str:
    """计算文件 SHA256 哈希"""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _set_hidden_readonly(path: str) -> bool:
    """设置文件为隐藏+只读属性（仅 Windows）"""
    if not IS_WINDOWS:
        return False
    try:
        # attrib +H +R <path>
        subprocess.run(
            ["attrib", "+H", "+R", path],
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            check=False
        )
        return True
    except Exception:
        return False


def _clear_attributes(path: str) -> bool:
    """清除文件隐藏/只读属性（仅 Windows，删除前调用）"""
    if not IS_WINDOWS:
        return False
    try:
        subprocess.run(
            ["attrib", "-H", "-R", path],
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            check=False
        )
        return True
    except Exception:
        return False


# ============================================================
# HoneypotManager — 勒索诱捕系统主引擎
# ============================================================

class HoneypotManager:
    """勒索诱捕系统

    部署伪装诱饵文件，监控篡改行为，触发勒索防护。
    """

    def __init__(self, kernel_bridge: Any = None):
        """初始化诱捕系统

        Args:
            kernel_bridge: KernelBridge 实例（用于下发文件保护规则，可选）
        """
        self._kernel_bridge = kernel_bridge
        self._logger = _get_logger()

        # 诱饵文件索引：path -> {type, name, baseline_hash, deployed_at, directory, driver_rule_id}
        self._decoys: dict[str, dict] = {}
        self._decoys_lock = threading.Lock()

        # 驱动下发的规则 ID 范围（用于撤回时清理）
        self._driver_rule_ids: list[int] = []
        self._next_rule_id = 90000  # 诱饵规则 ID 从 90000 起，避免与 custom_rules 冲突

        # 监控线程控制
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitoring = False

        # 告警统计
        self._stats = {
            "deployed": 0,
            "tamper_events": 0,
            "blocked_processes": 0,
        }
        self._stats_lock = threading.Lock()

        # 基线延迟加载标记
        self._baseline_loaded = False

    def _ensure_baseline(self):
        """延迟加载基线（首次访问时从磁盘读取）"""
        if not self._baseline_loaded:
            self._load_baseline()
            self._baseline_loaded = True
            self._log("info", f"诱捕系统初始化完成，已加载 {len(self._decoys)} 个诱饵")

    # ── 属性 ──

    @property
    def driver_available(self) -> bool:
        """驱动是否可用"""
        if self._kernel_bridge is None:
            return False
        try:
            return self._kernel_bridge.is_connected()
        except Exception:
            return False

    @property
    def monitoring(self) -> bool:
        return self._monitoring

    # ── 部署 ──

    def deploy(self, directories: list[str]) -> dict:
        """在指定目录中部署诱饵文件

        Args:
            directories: 目标目录列表

        Returns:
            部署结果 {"deployed": int, "failed": int, "decoys": list[str]}
        """
        self._ensure_baseline()
        result = {"deployed": 0, "failed": 0, "decoys": []}

        for directory in directories:
            if not os.path.isdir(directory):
                self._log("warning", f"目录不存在，跳过: {directory}")
                continue

            for template in DECOY_TEMPLATES:
                decoy_path = os.path.join(directory, template["name"])
                try:
                    # 写入诱饵内容
                    content = (
                        f"[御天诱饵文件 - {template['type']}]\n"
                        f"创建时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                        f"文件ID: {hashlib.md5(decoy_path.encode('utf-8')).hexdigest()[:16]}\n"
                        f"警告: 此文件由御天诱捕系统部署，任何修改将触发勒索防护！\n"
                        f"----------------------------------------\n"
                        f"{template['content']}\n"
                    )
                    with open(decoy_path, "w", encoding="utf-8") as f:
                        f.write(content)

                    # 设置隐藏+只读属性
                    _set_hidden_readonly(decoy_path)

                    # 记录基线哈希
                    baseline_hash = _file_sha256(decoy_path)

                    # 下发驱动保护规则（驱动可用时）
                    driver_rule_id = self._push_protect_rule(decoy_path)

                    with self._decoys_lock:
                        self._decoys[decoy_path] = {
                            "type": template["type"],
                            "name": template["name"],
                            "baseline_hash": baseline_hash,
                            "deployed_at": time.time(),
                            "directory": directory,
                            "driver_rule_id": driver_rule_id,
                        }

                    result["deployed"] += 1
                    result["decoys"].append(decoy_path)

                except Exception as e:
                    self._log("error", f"部署诱饵失败 {decoy_path}: {e}")
                    result["failed"] += 1

        # 持久化基线
        self._save_baseline()

        # 更新统计
        with self._stats_lock:
            self._stats["deployed"] = len(self._decoys)

        self._log("info", f"诱饵部署完成: 成功 {result['deployed']}，失败 {result['failed']}")

        # 自动启动监控
        if result["deployed"] > 0 and not self._monitoring:
            self._start_monitor()

        return result

    # ── 检查 ──

    def check_all(self) -> list[dict]:
        """检查所有诱饵文件状态

        Returns:
            异常诱饵列表，每项 {path, status, detail}
            status: "missing" / "modified" / "encrypted"
        """
        self._ensure_baseline()
        anomalies: list[dict] = []

        with self._decoys_lock:
            decoys_snapshot = list(self._decoys.items())

        for path, info in decoys_snapshot:
            try:
                # 检查 1：文件是否存在
                if not os.path.exists(path):
                    anomalies.append({
                        "path": path,
                        "type": info["type"],
                        "status": "missing",
                        "detail": "诱饵文件被删除（疑似勒索软件清理痕迹）",
                    })
                    continue

                # 检查 2：哈希是否变化（内容被修改）
                current_hash = _file_sha256(path)
                if current_hash != info["baseline_hash"]:
                    # 检查 3：是否被加密（扩展名变化或内容熵增加）
                    encrypted = self._is_likely_encrypted(path)
                    anomalies.append({
                        "path": path,
                        "type": info["type"],
                        "status": "encrypted" if encrypted else "modified",
                        "detail": "诱饵文件被加密" if encrypted else "诱饵文件内容被篡改",
                        "baseline_hash": info["baseline_hash"],
                        "current_hash": current_hash,
                    })

            except Exception as e:
                self._log("error", f"检查诱饵失败 {path}: {e}")

        return anomalies

    def _is_likely_encrypted(self, path: str) -> bool:
        """启发式判断文件是否被加密

        判断依据：
          1. 扩展名变为已知勒索扩展名
          2. 文件内容出现大量非 ASCII 字节（高熵）
        """
        # 扩展名检查
        ext = os.path.splitext(path)[1].lower()
        ransom_exts = {
            ".lockbit", ".crypt", ".encrypted", ".enc", ".locked",
            ".cryptolocker", ".wanna", ".wncry", ".onion", ".cerber",
        }
        if ext in ransom_exts:
            return True

        # 检查同名加密文件是否存在
        for rext in ransom_exts:
            if os.path.exists(path + rext):
                return True

        # 内容熵粗略判断（前 4KB 中非 ASCII 字节占比）
        try:
            with open(path, "rb") as f:
                sample = f.read(4096)
            if sample:
                non_ascii = sum(1 for b in sample if b > 0x7F or b == 0)
                if non_ascii / len(sample) > 0.6:
                    return True
        except Exception:
            pass

        return False

    # ── 篡改响应 ──

    def on_tamper(self, decoy_path: str, pid: int) -> None:
        """诱饵文件被篡改时的响应处理

        Args:
            decoy_path: 被篡改的诱饵文件路径
            pid: 嫌疑进程 PID
        """
        with self._stats_lock:
            self._stats["tamper_events"] += 1

        info = None
        with self._decoys_lock:
            info = self._decoys.get(decoy_path)

        decoy_type = info["type"] if info else "unknown"
        self._log("critical", f"诱饵被篡改: {decoy_path} (type={decoy_type}, pid={pid})")

        # 阻断嫌疑进程
        if pid and pid > 0:
            self._block_process(pid)

        # 弹窗告警
        self._show_alert(decoy_path, pid, decoy_type)

    def _block_process(self, pid: int) -> bool:
        """终止嫌疑进程"""
        if not IS_WINDOWS:
            return False
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                with self._stats_lock:
                    self._stats["blocked_processes"] += 1
                self._log("info", f"已终止嫌疑进程: PID={pid}")
                return True
            else:
                self._log("warning", f"终止进程失败: PID={pid}, {result.stderr.strip()}")
                return False
        except Exception as e:
            self._log("error", f"终止进程异常: PID={pid}, {e}")
            return False

    def _show_alert(self, decoy_path: str, pid: int, decoy_type: str) -> None:
        """显示系统弹窗告警"""
        title = "御天 勒索诱捕告警 [严重]"
        body = (
            f"检测到勒索软件行为！\n\n"
            f"诱饵文件: {decoy_path}\n"
            f"诱饵类型: {decoy_type}\n"
            f"嫌疑进程 PID: {pid}\n\n"
            f"御天已自动终止该进程，请立即检查文件安全。\n"
            f"建议：1) 备份重要文件  2) 全盘查杀  3) 联系安全人员"
        )
        if not IS_WINDOWS:
            return
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, body, title, 0x10 | 0x1000)
        except Exception:
            try:
                subprocess.Popen(
                    ["msg", "*", f"{title}\n{body}"],
                    stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
                )
            except Exception:
                pass

    # ── 撤回 ──

    def recall(self) -> dict:
        """撤回所有诱饵文件

        Returns:
            撤回结果 {"removed": int, "failed": int}
        """
        self._ensure_baseline()
        result = {"removed": 0, "failed": 0}

        # 停止监控
        self._stop_monitor()

        with self._decoys_lock:
            decoys_snapshot = list(self._decoys.items())
            self._decoys.clear()

        for path, info in decoys_snapshot:
            try:
                # 从驱动移除保护规则
                self._remove_protect_rule(info.get("driver_rule_id", 0))

                # 清除隐藏/只读属性后删除
                if os.path.exists(path):
                    _clear_attributes(path)
                    os.remove(path)
                result["removed"] += 1
            except Exception as e:
                self._log("error", f"撤回诱饵失败 {path}: {e}")
                result["failed"] += 1

        # 清空基线
        self._save_baseline()

        with self._stats_lock:
            self._stats["deployed"] = 0

        self._log("info", f"诱饵撤回完成: 成功 {result['removed']}，失败 {result['failed']}")
        return result

    # ── 状态查询 ──

    def get_status(self) -> dict:
        """获取诱捕系统完整状态"""
        self._ensure_baseline()
        with self._decoys_lock:
            decoys_count = len(self._decoys)
            by_type: dict[str, int] = {}
            for info in self._decoys.values():
                by_type[info["type"]] = by_type.get(info["type"], 0) + 1

        with self._stats_lock:
            stats = dict(self._stats)

        return {
            "driver_available": self.driver_available,
            "monitoring": self._monitoring,
            "decoys_count": decoys_count,
            "decoys_by_type": by_type,
            "stats": stats,
            "baseline_file": BASELINE_FILE,
        }

    def get_decoys(self) -> list[dict]:
        """获取已部署诱饵列表"""
        self._ensure_baseline()
        with self._decoys_lock:
            return [
                {
                    "path": path,
                    "type": info["type"],
                    "name": info["name"],
                    "directory": info["directory"],
                    "deployed_at": info["deployed_at"],
                    "baseline_hash": info["baseline_hash"][:16] + "...",
                    "exists": os.path.exists(path),
                }
                for path, info in self._decoys.items()
            ]

    # ── 监控线程 ──

    def _start_monitor(self) -> None:
        """启动诱饵监控线程"""
        if self._monitoring:
            return
        self._monitoring = True
        self._stop_event.clear()
        t = threading.Thread(target=self._monitor_loop, daemon=True, name="HoneypotMonitor")
        t.start()
        self._monitor_thread = t
        self._log("info", "诱饵监控线程已启动")

    def _stop_monitor(self) -> None:
        """停止诱饵监控线程"""
        self._monitoring = False
        self._stop_event.set()
        t = self._monitor_thread
        if t is not None and t.is_alive():
            t.join(timeout=2.0)
        self._monitor_thread = None

    def _monitor_loop(self) -> None:
        """诱饵监控主循环：定期检查所有诱饵文件状态"""
        while not self._stop_event.is_set():
            try:
                anomalies = self.check_all()
                for anomaly in anomalies:
                    # 没有具体 PID 信息时用 0 表示（驱动事件回调会带 PID）
                    self.on_tamper(anomaly["path"], 0)
            except Exception as e:
                self._log("error", f"监控循环异常: {e}")

            self._stop_event.wait(CHECK_INTERVAL)

    # ── 驱动规则下发（私有） ──

    def _push_protect_rule(self, decoy_path: str) -> int:
        """向驱动下发诱饵文件保护规则

        驱动不可用时返回 0，进入降级模式（仅用户态监控）。
        """
        if self._kernel_bridge is None or not self.driver_available:
            self._log("info", f"驱动不可用，诱饵 {decoy_path} 仅启用用户态监控")
            return 0

        rule_id = self._next_rule_id
        self._next_rule_id += 1

        try:
            # 文件类型规则，阻断动作
            driver_rule = {
                "ruleId": rule_id,
                "ruleType": 0,  # RuleTypeFile
                "action": 1,    # ActionBlock
                "pattern": decoy_path,
                "enabled": 1,
            }
            ok = bool(self._kernel_bridge.add_rule(driver_rule))
            if ok:
                self._driver_rule_ids.append(rule_id)
                return rule_id
            else:
                self._log("warning", f"驱动下发诱饵保护规则失败: {decoy_path}")
                return 0
        except Exception as e:
            self._log("error", f"驱动下发诱饵保护规则异常: {e}")
            return 0

    def _remove_protect_rule(self, rule_id: int) -> bool:
        """从驱动移除诱饵保护规则"""
        if not rule_id or self._kernel_bridge is None:
            return False
        try:
            ok = bool(self._kernel_bridge.del_rule(rule_id))
            if ok and rule_id in self._driver_rule_ids:
                self._driver_rule_ids.remove(rule_id)
            return ok
        except Exception as e:
            self._log("error", f"驱动移除诱饵保护规则异常: {e}")
            return False

    # ── 持久化 ──

    def _save_baseline(self) -> bool:
        """将诱饵基线持久化到 data/honeypot_baseline.json"""
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            with self._decoys_lock:
                data = {
                    "saved_at": time.time(),
                    "next_rule_id": self._next_rule_id,
                    "decoys": [
                        {"path": path, **info}
                        for path, info in self._decoys.items()
                    ],
                }
            with open(BASELINE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            self._log("error", f"基线持久化失败: {e}")
            return False

    def _load_baseline(self) -> bool:
        """从 data/honeypot_baseline.json 加载诱饵基线"""
        if not os.path.exists(BASELINE_FILE):
            return False
        try:
            with open(BASELINE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            decoys_list = data.get("decoys", [])
            self._next_rule_id = data.get("next_rule_id", 90000)

            with self._decoys_lock:
                for item in decoys_list:
                    path = item.get("path", "")
                    if path:
                        info = {k: v for k, v in item.items() if k != "path"}
                        self._decoys[path] = info

            # 重新下发驱动规则（驱动可用时）
            if self.driver_available and self._decoys:
                self._resync_driver_rules()

            return True
        except Exception as e:
            self._log("error", f"基线加载失败: {e}")
            return False

    def _resync_driver_rules(self) -> None:
        """将已加载的诱饵重新下发到驱动（启动时同步用）"""
        with self._decoys_lock:
            decoys_snapshot = list(self._decoys.items())

        success = 0
        for path, info in decoys_snapshot:
            if os.path.exists(path):
                new_id = self._push_protect_rule(path)
                if new_id:
                    info["driver_rule_id"] = new_id
                    success += 1

        self._log("info", f"诱饵驱动规则同步完成: 成功 {success}/{len(decoys_snapshot)}")

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

_honeypot_manager: Optional[HoneypotManager] = None
_honeypot_lock = threading.Lock()


def get_honeypot_manager(kernel_bridge: Any = None) -> HoneypotManager:
    """获取全局唯一的 HoneypotManager 实例（双重检查锁定单例）

    首次调用时应传入 kernel_bridge 参数；后续调用参数将被忽略。

    Args:
        kernel_bridge: KernelBridge 实例

    Returns:
        全局唯一的 HoneypotManager 实例
    """
    global _honeypot_manager
    if _honeypot_manager is None:
        with _honeypot_lock:
            if _honeypot_manager is None:
                _honeypot_manager = HoneypotManager(kernel_bridge=kernel_bridge)
    return _honeypot_manager


# ============================================================
# 模块自检（直接运行时执行）
# ============================================================

if __name__ == "__main__":
    # 不依赖驱动，测试诱饵部署/检查/撤回流程
    mgr = HoneypotManager(kernel_bridge=None)

    # 使用临时目录测试
    test_dir = os.path.join(_DATA_DIR, "honeypot_test")
    os.makedirs(test_dir, exist_ok=True)

    print("[honeypot] 部署诱饵...")
    result = mgr.deploy([test_dir])
    print(f"[honeypot] 部署结果: {result}")

    print("[honeypot] 诱饵列表:")
    for d in mgr.get_decoys():
        print(f"  - {d['path']} (type={d['type']}, exists={d['exists']})")

    print("[honeypot] 检查诱饵状态:")
    anomalies = mgr.check_all()
    print(f"[honeypot] 异常数: {len(anomalies)}")

    print("[honeypot] 状态:", mgr.get_status())

    print("[honeypot] 撤回诱饵...")
    recall_result = mgr.recall()
    print(f"[honeypot] 撤回结果: {recall_result}")

    # 清理临时目录
    try:
        os.rmdir(test_dir)
    except OSError:
        pass
