"""
御天 主机入侵防御系统 (HIPS)

连接内核驱动与各防护模块的中枢：
  - 接收驱动推送的安全事件
  - 匹配用户态规则（复杂规则，驱动只做简单快速匹配）
  - 生成告警并推送给前端
  - 处理用户对询问事件的响应（允许/阻断）
"""

import threading
import json
import os
import time
from datetime import datetime


class HIPS:
    """主机入侵防御系统

    连接内核驱动与各防护模块的中枢：
    - 接收驱动推送的安全事件
    - 匹配用户态规则（复杂规则）
    - 生成告警并推送给前端
    - 处理用户对询问事件的响应
    """

    # 事件类型常量（与 andun.h 一致）
    EVENT_FILE_CREATE = 1
    EVENT_FILE_WRITE = 2
    EVENT_FILE_DELETE = 3
    EVENT_PROCESS_CREATE = 4
    EVENT_PROCESS_TERMINATE = 5
    EVENT_REGISTRY_SET = 6
    EVENT_REGISTRY_DELETE = 7
    EVENT_NETWORK_CONNECT = 8
    EVENT_HANDLE_OPEN = 9
    EVENT_DRIVER_LOAD = 10
    EVENT_ROOTKIT_DETECTED = 11

    # 动作常量
    ACTION_ALLOW = 0
    ACTION_BLOCK = 1
    ACTION_ASK = 2

    def __init__(self, kernel_bridge):
        self._kb = kernel_bridge
        self._enabled = False
        self._handlers = {}  # event_type -> list of handler functions
        self._alerts = None  # 延迟加载
        self._pending_actions = {}  # 等待用户响应的事件
        self._lock = threading.Lock()
        self._data_dir = os.path.join(os.path.dirname(__file__), 'data')
        self._alerts_file = os.path.join(self._data_dir, 'hips_alerts.json')

        # 确保数据目录存在
        os.makedirs(self._data_dir, exist_ok=True)

        # 注册为内核驱动的事件处理器（不加载数据，仅注册回调）
        self._register_to_kernel()

    def _ensure_alerts(self):
        """延迟加载告警历史（首次访问时从磁盘读取）"""
        if self._alerts is None:
            self._alerts = []
            self._load_alerts()

    def enable(self):
        """启用 HIPS"""
        self._enabled = True
        if self._kb.is_connected():
            self._register_to_kernel()

    def disable(self):
        """禁用 HIPS"""
        self._enabled = False
        if self._kb.is_connected():
            for et in range(self.EVENT_FILE_CREATE, self.EVENT_ROOTKIT_DETECTED + 1):
                try:
                    self._kb.unregister_handler(et, self.on_event)
                except Exception:
                    pass

    def is_enabled(self) -> bool:
        return self._enabled

    def on_event(self, event: dict):
        """处理驱动推送的事件

        event 字典包含:
        - eventType: 事件类型
        - pid: 进程ID
        - ppid: 父进程ID
        - processName: 进程名
        - processPath: 进程路径
        - targetPath: 目标路径
        - remoteAddr: 远程地址
        - remotePort: 远程端口
        - action: 动作(0=允许, 1=阻断, 2=询问)
        - timestamp: 时间戳
        """
        if not self._enabled:
            return

        # 如果驱动已经阻断（action=1），记录告警
        if event.get('action') == self.ACTION_BLOCK:
            self._add_alert(event, 'blocked')

        # 如果驱动标记为询问（action=2），加入待处理队列
        elif event.get('action') == self.ACTION_ASK:
            self._add_pending(event)

        # 分发给注册的处理器
        event_type = event.get('eventType', 0)
        with self._lock:
            handlers = self._handlers.get(event_type, []) + self._handlers.get(0, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                print(f"[HIPS] 事件处理器异常: {e}")

    def register_handler(self, event_type, handler):
        """注册事件处理器
        event_type: 事件类型，0 表示处理所有事件
        """
        with self._lock:
            if event_type not in self._handlers:
                self._handlers[event_type] = []
            self._handlers[event_type].append(handler)

    def unregister_handler(self, event_type, handler):
        with self._lock:
            if event_type in self._handlers:
                self._handlers[event_type].remove(handler)

    def respond_to_pending(self, event_id: str, action: str):
        """用户对待处理事件的响应
        action: 'allow' 或 'block'
        """
        with self._lock:
            event = self._pending_actions.pop(event_id, None)
        if event:
            if action == 'block':
                # 如果需要阻断，下发规则到驱动
                self._add_alert(event.get('event', event), 'user_blocked')
                # 可以通过 kernel_bridge 下发临时阻断规则
            else:
                self._add_alert(event.get('event', event), 'user_allowed')

    def get_alerts(self, limit=50) -> list:
        """获取告警历史"""
        self._ensure_alerts()
        with self._lock:
            return self._alerts[-limit:]

    def get_pending_actions(self) -> list:
        """获取待用户响应的事件列表"""
        with self._lock:
            return list(self._pending_actions.values())

    def get_status(self) -> dict:
        self._ensure_alerts()
        return {
            'enabled': self._enabled,
            'driver_connected': self._kb.is_connected(),
            'total_alerts': len(self._alerts),
            'pending_actions': len(self._pending_actions),
        }

    def _add_alert(self, event: dict, source: str):
        """添加告警记录"""
        self._ensure_alerts()
        alert = {
            'id': f"{event.get('pid', 0)}_{int(time.time()*1000)}",
            'timestamp': datetime.now().isoformat(),
            'event_type': event.get('eventType'),
            'pid': event.get('pid'),
            'process_name': event.get('processName', ''),
            'process_path': event.get('processPath', ''),
            'target': event.get('targetPath', ''),
            'remote_addr': event.get('remoteAddr', ''),
            'remote_port': event.get('remotePort', 0),
            'action': event.get('action'),
            'source': source,
        }
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-500:]
        # 异步保存
        threading.Thread(target=self._save_alerts, daemon=True).start()

    def _add_pending(self, event: dict):
        """添加待处理事件"""
        event_id = f"{event.get('pid', 0)}_{int(time.time()*1000)}"
        with self._lock:
            self._pending_actions[event_id] = {
                'id': event_id,
                'timestamp': datetime.now().isoformat(),
                'event': event,
            }
        # 5 分钟后自动允许
        threading.Timer(300, lambda: self.respond_to_pending(event_id, 'allow')).start()

    def _register_to_kernel(self):
        """注册为内核驱动的事件处理器（为每个事件类型分别注册）"""
        if self._kb.is_connected():
            for et in range(self.EVENT_FILE_CREATE, self.EVENT_ROOTKIT_DETECTED + 1):
                try:
                    self._kb.register_handler(et, self.on_event)
                except Exception:
                    pass

    def _save_alerts(self):
        try:
            with open(self._alerts_file, 'w', encoding='utf-8') as f:
                json.dump(self._alerts[-200:], f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[HIPS] 保存告警失败: {e}")

    def _load_alerts(self):
        try:
            if os.path.exists(self._alerts_file):
                with open(self._alerts_file, 'r', encoding='utf-8') as f:
                    self._alerts = json.load(f)
        except Exception as e:
            print(f"[HIPS] 加载告警失败: {e}")
            self._alerts = []


# 单例
_hips = None
_hips_lock = threading.Lock()


def get_hips(kernel_bridge=None) -> HIPS:
    global _hips
    if _hips is None:
        with _hips_lock:
            if _hips is None:
                if kernel_bridge is None:
                    from engine.kernel_bridge import get_kernel_bridge
                    kernel_bridge = get_kernel_bridge()
                _hips = HIPS(kernel_bridge)
    return _hips
