"""
御天 进程联网监控模块
监控进程外联连接，匹配 C2 威胁情报黑名单，检测可疑网络行为
"""
import os
import time
import threading
from dataclasses import dataclass, field, asdict
from typing import Optional
from collections import defaultdict

@dataclass
class NetworkConnection:
    pid: int
    process_name: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str  # ESTABLISHED / LISTEN / CLOSE_WAIT / SYN_SENT
    c2_match: bool = False
    c2_source: str = ""       # 匹配到的情报源
    c2_family: str = ""       # 恶意软件家族
    risk: str = "unknown"     # safe / suspicious / high


class NetworkMonitor:
    """进程联网监控器，检测 C2 外联"""

    def __init__(self):
        self._c2_intel = None
        self._threat_intel = None
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._last_connections: list[NetworkConnection] = []
        self._alert_callbacks: list = []
        self._scan_interval = 5  # 扫描间隔（秒）
        self._known_c2_hits: set = set()  # 已报告的 C2 连接，避免重复告警

    def _lazy_load_intel(self):
        """延迟加载威胁情报引擎"""
        if self._c2_intel is None:
            try:
                from engine.c2_intel import C2IntelEngine
                self._c2_intel = C2IntelEngine()
                self._c2_intel.reload()
            except Exception:
                self._c2_intel = None
        if self._threat_intel is None:
            try:
                from engine.threat_intel import ThreatIntelEngine
                self._threat_intel = ThreatIntelEngine()
                self._threat_intel.reload()
            except Exception:
                self._threat_intel = None

    def _check_c2(self, ip: str) -> Optional[dict]:
        """检查 IP 是否匹配 C2 黑名单"""
        result = {"match": False, "source": "", "family": ""}
        if self._c2_intel:
            try:
                c2_result = self._c2_intel.lookup_ip(ip)
                if c2_result and c2_result.get("is_c2"):
                    result["match"] = True
                    result["source"] = "C2 Intel (Maltrail/AbuseCH)"
                    result["family"] = c2_result.get("family", "")
                    return result
            except Exception:
                pass
        if self._threat_intel:
            try:
                families = self._threat_intel.lookup_ioc(ip)
                if families and len(families) > 0:
                    result["match"] = True
                    result["source"] = "Threat Intel (Malware IOC)"
                    result["family"] = ", ".join(families[:3])
                    return result
            except Exception:
                pass
        return result

    def scan_connections(self) -> list[NetworkConnection]:
        """扫描当前所有网络连接并进行 C2 匹配"""
        self._lazy_load_intel()
        connections = []
        try:
            import psutil
        except ImportError:
            return connections

        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.raddr or not conn.laddr:
                    continue
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "unknown"

                remote_ip = conn.raddr.ip if conn.raddr else ""
                c2_info = self._check_c2(remote_ip) if remote_ip else {"match": False, "source": "", "family": ""}

                # 风险评估
                risk = "unknown"
                if c2_info["match"]:
                    risk = "high"
                elif remote_ip and not remote_ip.startswith(("127.", "192.168.", "10.", "172.16.", "172.17.",
                                                              "172.18.", "172.19.", "172.20.", "172.21.",
                                                              "172.22.", "172.23.", "172.24.", "172.25.",
                                                              "172.26.", "172.27.", "172.28.", "172.29.",
                                                              "172.30.", "172.31.")):
                    # 公网连接需要关注
                    risk = "suspicious"

                nc = NetworkConnection(
                    pid=conn.pid,
                    process_name=proc_name,
                    local_addr=conn.laddr.ip if conn.laddr else "",
                    local_port=conn.laddr.port if conn.laddr else 0,
                    remote_addr=remote_ip,
                    remote_port=conn.raddr.port if conn.raddr else 0,
                    status=conn.status,
                    c2_match=c2_info["match"],
                    c2_source=c2_info["source"],
                    c2_family=c2_info["family"],
                    risk=risk,
                )
                connections.append(nc)
        except (psutil.AccessDenied, Exception):
            pass

        return connections

    def scan_summary(self) -> dict:
        """扫描并返回摘要"""
        conns = self.scan_connections()
        high_risk = [c for c in conns if c.risk == "high"]
        suspicious = [c for c in conns if c.risk == "suspicious"]
        established = [c for c in conns if c.status == "ESTABLISHED"]

        # 检测新 C2 命中
        new_alerts = []
        for c in high_risk:
            key = f"{c.pid}:{c.remote_addr}:{c.remote_port}"
            if key not in self._known_c2_hits:
                self._known_c2_hits.add(key)
                new_alerts.append(c)
                for cb in self._alert_callbacks:
                    try:
                        cb(c)
                    except Exception:
                        pass

        return {
            "total_connections": len(conns),
            "established": len(established),
            "high_risk": len(high_risk),
            "suspicious": len(suspicious),
            "new_c2_alerts": len(new_alerts),
            "high_risk_details": [asdict(c) for c in high_risk],
            "suspicious_details": [asdict(c) for c in suspicious],
            "all_connections": [asdict(c) for c in conns],
        }

    def on_alert(self, callback):
        """注册告警回调"""
        self._alert_callbacks.append(callback)

    def start_monitor(self, interval: int = 5):
        """启动后台监控线程"""
        self._scan_interval = interval
        if self._running:
            return
        self._running = True

        def _loop():
            while self._running:
                try:
                    self.scan_summary()
                except Exception:
                    pass
                time.sleep(self._scan_interval)

        self._monitor_thread = threading.Thread(target=_loop, daemon=True, name="net-monitor")
        self._monitor_thread.start()

    def stop_monitor(self):
        """停止监控"""
        self._running = False


# 全局单例
_monitor_instance: Optional[NetworkMonitor] = None


def get_network_monitor() -> NetworkMonitor:
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = NetworkMonitor()
    return _monitor_instance



