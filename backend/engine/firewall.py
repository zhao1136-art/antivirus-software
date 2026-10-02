"""
御天 WFP 驱动防火墙模块

通过内核驱动的 WFP（Windows Filtering Platform）子模块实现网络包过滤：
  - IP/端口级别的阻断和放行规则
  - 进程联网控制（禁止指定进程访问网络）
  - 实时连接监控（基于 psutil 枚举活跃连接）
  - 规则持久化（JSON 存储，启动时自动加载）

驱动未安装时进入降级模式：规则仅在用户态维护，连接监控仍可用。
"""

import os
import time
import json
import threading
from datetime import datetime


class Firewall:
    """WFP 驱动防火墙

    通过内核驱动的 WFP 子模块实现网络包过滤：
    - IP/端口级别的阻断和放行规则
    - 进程联网控制
    - 实时连接监控
    """

    def __init__(self, kernel_bridge):
        self._kb = kernel_bridge
        self._enabled = False
        self._rules = None  # 延迟加载，首次访问时从 JSON 读取
        self._blocked_processes = set()  # 禁止联网的进程
        self._data_dir = os.path.join(os.path.dirname(__file__), 'data')
        self._rules_file = os.path.join(self._data_dir, 'firewall_rules.json')
        os.makedirs(self._data_dir, exist_ok=True)

    def _ensure_rules(self):
        """延迟加载规则（首次访问时从磁盘读取）"""
        if self._rules is None:
            self._rules = []
            self._load_rules()

    def enable(self) -> bool:
        """启用防火墙"""
        self._ensure_rules()
        # 设置 g_Config.networkFilterEnabled = 1
        if self._kb.is_connected():
            config = self._kb.get_config()
            config['networkFilterEnabled'] = 1
            self._kb.set_config(config)
        self._enabled = True
        # 下发所有规则到驱动
        for rule in self._rules:
            if rule['enabled']:
                self._kb.add_rule({
                    'ruleType': 3,  # RuleTypeNetwork
                    'action': 1 if rule['action'] == 'block' else 0,
                    'pattern': f"{rule.get('ip', '*')}:{rule.get('port', '*')}",
                    'enabled': True,
                })
        return True

    def disable(self) -> bool:
        """禁用防火墙"""
        if self._kb.is_connected():
            config = self._kb.get_config()
            config['networkFilterEnabled'] = 0
            self._kb.set_config(config)
        self._enabled = False
        return True

    def add_block_rule(self, ip: str, port: int = 0, protocol: str = "tcp", description: str = "") -> dict:
        """添加阻断规则"""
        self._ensure_rules()
        rule = {
            'id': int(time.time() * 1000),
            'action': 'block',
            'ip': ip,
            'port': port,
            'protocol': protocol,
            'description': description,
            'enabled': True,
            'created_at': datetime.now().isoformat(),
        }
        self._rules.append(rule)
        # 下发到驱动
        if self._enabled and self._kb.is_connected():
            pattern = f"{ip}:{port}" if port else ip
            self._kb.add_rule({
                'ruleType': 3,
                'action': 1,
                'pattern': pattern,
                'enabled': True,
            })
        self._save_rules()
        return rule

    def add_allow_rule(self, ip: str, port: int = 0, protocol: str = "tcp", description: str = "") -> dict:
        """添加放行规则"""
        self._ensure_rules()
        rule = {
            'id': int(time.time() * 1000),
            'action': 'allow',
            'ip': ip,
            'port': port,
            'protocol': protocol,
            'description': description,
            'enabled': True,
            'created_at': datetime.now().isoformat(),
        }
        self._rules.append(rule)
        if self._enabled and self._kb.is_connected():
            pattern = f"{ip}:{port}" if port else ip
            self._kb.add_rule({
                'ruleType': 3,
                'action': 0,
                'pattern': pattern,
                'enabled': True,
            })
        self._save_rules()
        return rule

    def remove_rule(self, rule_id: int) -> bool:
        """删除规则"""
        self._ensure_rules()
        before = len(self._rules)
        self._rules = [r for r in self._rules if r['id'] != rule_id]
        if len(self._rules) < before:
            # 驱动侧清空后重新下发（简单实现）
            if self._kb.is_connected():
                self._kb.clear_rules()
                if self._enabled:
                    for rule in self._rules:
                        if rule['enabled']:
                            pattern = f"{rule['ip']}:{rule['port']}" if rule['port'] else rule['ip']
                            self._kb.add_rule({
                                'ruleType': 3,
                                'action': 1 if rule['action'] == 'block' else 0,
                                'pattern': pattern,
                                'enabled': True,
                            })
            self._save_rules()
            return True
        return False

    def block_process(self, process_name: str) -> bool:
        """禁止某进程联网"""
        self._blocked_processes.add(process_name.lower())
        # 通过网络监控模块实现（或下发到驱动）
        return True

    def unblock_process(self, process_name: str) -> bool:
        self._blocked_processes.discard(process_name.lower())
        return True

    def get_blocked_processes(self) -> list:
        return list(self._blocked_processes)

    def get_rules(self) -> list:
        self._ensure_rules()
        return self._rules

    def get_connections(self) -> list:
        """获取当前活跃连接（通过 psutil 或网络监控模块）"""
        try:
            import psutil
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except:
                        proc_name = 'unknown'
                    connections.append({
                        'pid': conn.pid,
                        'process': proc_name,
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                        'status': conn.status,
                    })
            return connections
        except Exception:
            return []

    def get_stats(self) -> dict:
        """统计信息"""
        self._ensure_rules()
        if self._kb.is_connected():
            stats = self._kb.get_stats()
            return {
                'total_events': stats.get('networkOperations', 0),
                'blocked_events': stats.get('blockedEvents', 0),
                'active_rules': len([r for r in self._rules if r['enabled']]),
                'blocked_processes': len(self._blocked_processes),
                'driver_connected': True,
            }
        return {
            'total_events': 0,
            'blocked_events': 0,
            'active_rules': len([r for r in self._rules if r['enabled']]),
            'blocked_processes': len(self._blocked_processes),
            'driver_connected': False,
        }

    def get_status(self) -> dict:
        self._ensure_rules()
        return {
            'enabled': self._enabled,
            'driver_connected': self._kb.is_connected(),
            'total_rules': len(self._rules),
            'blocked_processes': len(self._blocked_processes),
        }

    def _save_rules(self):
        try:
            with open(self._rules_file, 'w', encoding='utf-8') as f:
                json.dump(self._rules, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[防火墙] 保存规则失败: {e}")

    def _load_rules(self):
        try:
            if os.path.exists(self._rules_file):
                with open(self._rules_file, 'r', encoding='utf-8') as f:
                    self._rules = json.load(f)
        except Exception as e:
            print(f"[防火墙] 加载规则失败: {e}")
            self._rules = []


_firewall = None
_firewall_lock = threading.Lock()


def get_firewall(kernel_bridge=None) -> Firewall:
    global _firewall
    if _firewall is None:
        with _firewall_lock:
            if _firewall is None:
                if kernel_bridge is None:
                    from engine.kernel_bridge import get_kernel_bridge
                    kernel_bridge = get_kernel_bridge()
                _firewall = Firewall(kernel_bridge)
    return _firewall
