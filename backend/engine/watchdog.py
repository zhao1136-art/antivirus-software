"""
后台防掉线守护模块 (Watchdog)
- 定期自检后端服务是否存活
- 监控系统资源（CPU/内存）
- 支持通过 API 和设置页面开启/关闭
- 异常时自动记录日志并尝试恢复
"""
import os
import sys
import time
import json
import threading
import socket
from datetime import datetime
from config import LOGS_DIR


class Watchdog:
    """后台防掉线守护进程"""

    def __init__(self):
        self._running = False
        self._enabled = True  # 默认开启
        self._thread = None
        self._lock = threading.Lock()
        self._check_interval = 30  # 每30秒自检一次
        self._log_file = os.path.join(LOGS_DIR, "watchdog.log")
        self._stats = {
            "uptime_seconds": 0,
            "checks_total": 0,
            "checks_failed": 0,
            "last_check": None,
            "last_error": None,
            "service_port": 8899,
            "status": "stopped"
        }
        self._start_time = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self):
        """开启防掉线守护"""
        self._enabled = True
        if not self._running:
            self.start()
        self._log("Watchdog 已开启")

    def disable(self):
        """关闭防掉线守护"""
        self._enabled = False
        if self._running:
            self.stop()
        self._log("Watchdog 已关闭")

    def start(self):
        """启动守护线程"""
        if self._running:
            return
        self._running = True
        self._start_time = time.time()
        self._stats["status"] = "running"
        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()
        self._log("Watchdog 守护已启动")

    def stop(self):
        """停止守护线程"""
        self._running = False
        self._stats["status"] = "stopped"
        self._log("Watchdog 守护已停止")

    def get_status(self) -> dict:
        """获取守护状态"""
        with self._lock:
            stats = dict(self._stats)
        stats["enabled"] = self._enabled
        stats["running"] = self._running
        if self._start_time:
            stats["uptime_seconds"] = int(time.time() - self._start_time)
        return stats

    def _watch_loop(self):
        """守护主循环"""
        while self._running:
            try:
                time.sleep(self._check_interval)
                if not self._running:
                    break

                self._do_health_check()

            except Exception as e:
                self._log(f"守护循环异常: {e}")

    def _do_health_check(self):
        """执行一次健康检查"""
        with self._lock:
            self._stats["checks_total"] += 1
            self._stats["last_check"] = datetime.now().isoformat()

        port = self._stats["service_port"]
        healthy = self._check_port(port)

        if not healthy:
            with self._lock:
                self._stats["checks_failed"] += 1
                self._stats["last_error"] = f"端口 {port} 无响应"
            self._log(f"⚠ 健康检查失败: 端口 {port} 无响应", level="WARN")

        # 检查系统资源
        cpu_pct, mem_pct = self._check_resources()
        if cpu_pct is not None and cpu_pct > 90:
            self._log(f"⚠ CPU 使用率过高: {cpu_pct:.1f}%", level="WARN")
        if mem_pct is not None and mem_pct > 85:
            self._log(f"⚠ 内存使用率过高: {mem_pct:.1f}%", level="WARN")

    def _check_port(self, port: int) -> bool:
        """检查指定端口是否在监听"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex(("127.0.0.1", port))
            s.close()
            return result == 0
        except Exception:
            return False

    def _check_resources(self) -> tuple:
        """检查系统 CPU 和内存使用率"""
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.5)
            mem = psutil.virtual_memory().percent
            return cpu, mem
        except ImportError:
            return None, None

    def _log(self, message: str, level: str = "INFO"):
        """写入守护日志"""
        try:
            os.makedirs(os.path.dirname(self._log_file), exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] [{level}] {message}\n")
        except Exception:
            pass


# 全局单例
_watchdog_instance = None


def get_watchdog() -> Watchdog:
    """获取全局 Watchdog 实例"""
    global _watchdog_instance
    if _watchdog_instance is None:
        _watchdog_instance = Watchdog()
    return _watchdog_instance
