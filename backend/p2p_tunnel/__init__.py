"""
P2P 内网穿透模块 - 安盾内网穿透组件

提供基于 STUN + TCP Simultaneous Open 的 P2P 端口穿透能力。
无需自建服务端，两端流量点对点直连。

主要接口：

    P2PTunnel    - 高级封装，一键完成 NAT 检测 + 打洞 + 隧道建立
    NATDetector  - NAT 类型检测
    STUNClient   - STUN 协议客户端
    PeerInfo     - 对等节点连接信息
    SignalingExchange - 信令交换工具

典型用法：

    # === 暴露端（要把本机 8080 端口暴露出去）===
    from p2p_tunnel import P2PTunnel, PeerInfo

    tunnel = P2PTunnel(role="exposer", target_port=8080)
    local_info = tunnel.get_local_info()
    # 将 local_info.encode() 发送给访问端
    remote_info = PeerInfo.decode(input("对方连接码: "))
    tunnel.connect(remote_info)
    tunnel.start_forward()

    # === 访问端（映射到本地 9090 端口访问远端服务）===
    from p2p_tunnel import P2PTunnel, PeerInfo

    tunnel = P2PTunnel(role="visitor", local_listen_port=9090)
    local_info = tunnel.get_local_info()
    # 将 local_info.encode() 发送给暴露端
    remote_info = PeerInfo.decode(input("对方连接码: "))
    tunnel.connect(remote_info)
    tunnel.start_forward()
"""

import logging
from .config import logger as _logger

# 设置默认日志级别
_logger.setLevel(logging.WARNING)
_logger.addHandler(logging.NullHandler())

from .exceptions import (
    P2PTunnelError,
    STUNError,
    STUNTimeoutError,
    NATPunchError,
    SymmetricNATError,
    TunnelError,
    TunnelDisconnectedError,
    SignalingError,
)

from .stun_client import STUNClient
from .nat_detect import NATDetector, NATType
from .tcp_punch import TCPPunchClient, tcp_simultaneous_open
from .tunnel import TunnelExposer, TunnelVisitor
from .signaling import PeerInfo, SignalingExchange
from .reconnect import ReconnectManager, auto_reconnect


class P2PTunnel:
    """
    P2P 隧道高级封装

    整合 NAT 检测、打洞、隧道建立，提供简洁的调用接口。
    适合嵌入到御天主程序中使用。
    """

    def __init__(self, role: str,
                 target_port: int = 0,
                 local_listen_port: int = 0):
        """
        Args:
            role: "exposer"（暴露本地服务）或 "visitor"（访问远端服务）
            target_port: 暴露端 - 要暴露的本地服务端口
            local_listen_port: 访问端 - 本地监听端口
        """
        if role not in ("exposer", "visitor"):
            raise ValueError(f"无效角色: {role}，必须是 'exposer' 或 'visitor'")

        self._role = role
        self._target_port = target_port
        self._local_listen_port = local_listen_port

        # 组件
        self._detector: NATDetector = None
        self._punch_client: TCPPunchClient = None
        self._local_info: PeerInfo = None
        self._remote_info: PeerInfo = None
        self._reconnect_mgr: ReconnectManager = None

        # 状态
        self._connected = False
        self._running = False

    # ── 属性 ──────────────────────────────────

    @property
    def role(self) -> str:
        return self._role

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def nat_type(self) -> NATType:
        return self._detector.nat_type if self._detector else NATType.UNKNOWN

    # ── 公共接口 ──────────────────────────────

    def get_local_info(self) -> PeerInfo:
        """
        执行 NAT 检测并生成本机连接信息。

        调用时机：打洞前必须调用，获取本机公网地址。

        Returns:
            本机 PeerInfo，可用于 encode() 后发送给对方
        """
        # NAT 检测
        print("正在检测 NAT 类型...")
        self._detector = NATDetector()
        nat_type = self._detector.detect()
        print(self._detector.summary())

        if not nat_type.can_punch:
            raise SymmetricNATError()

        # 创建打洞客户端（绑定端口）
        from .config import PUNCH_PORT_RANGE
        import random
        punch_port = random.randint(*PUNCH_PORT_RANGE)
        self._punch_client = TCPPunchClient(punch_port)

        self._local_info = PeerInfo(
            role=self._role,
            public_ip=self._detector.public_ip,
            public_port=self._detector.public_port,
            punch_port=punch_port,
            target_port=self._target_port,
        )

        return self._local_info

    def connect(self, remote_info: PeerInfo) -> None:
        """
        连接到对方。

        执行 TCP 打洞，建立 P2P 直连通道。

        Args:
            remote_info: 对方的 PeerInfo

        Raises:
            NATPunchError: 打洞失败
        """
        self._remote_info = remote_info

        print(f"\n开始 P2P 打洞...")
        print(f"  本机: {self._local_info.public_ip}:{self._local_info.punch_port}")
        print(f"  远端: {remote_info.public_ip}:{remote_info.punch_port}")

        # 执行打洞（使用对方的 punch_port，假设锥形NAT不改变端口号）
        self._punch_client.punch(
            remote_info.public_ip,
            remote_info.punch_port
        )
        self._connected = True
        print("P2P 直连隧道已建立!")

    def start_forward(self) -> None:
        """
        启动端口转发。

        暴露端：将 P2P 隧道数据转发到本地目标服务
        访问端：监听本地端口，将入站连接通过隧道转发到远端
        """
        if not self._connected:
            raise TunnelError("尚未建立 P2P 连接")

        if self._role == "exposer":
            if not self._target_port:
                raise ValueError("暴露端需要指定 target_port")
            self._start_exposer()
        else:
            if not self._local_listen_port:
                raise ValueError("访问端需要指定 local_listen_port")
            target = self._remote_info.target_port if self._remote_info else 80
            self._start_visitor(target)

    def _start_exposer(self) -> None:
        """暴露端：转发 P2P 数据到本地服务"""
        exposer = TunnelExposer(
            self._punch_client.socket,
            target_host="127.0.0.1",
            target_port=self._target_port,
        )
        self._running = True
        try:
            exposer.start()
        except Exception as e:
            logger.error("暴露端异常: %s", e)
            raise
        finally:
            self._running = False
            self._connected = False

    def _start_visitor(self, remote_target_port: int) -> None:
        """访问端：本地监听 → P2P 隧道 → 远端服务"""
        visitor = TunnelVisitor(
            self._punch_client.socket,
            local_listen_host="127.0.0.1",
            local_listen_port=self._local_listen_port,
        )
        self._running = True
        try:
            visitor.start(single_connection=True)
        except Exception as e:
            logger.error("访问端异常: %s", e)
            raise
        finally:
            self._running = False
            self._connected = False

    def close(self) -> None:
        """关闭隧道"""
        self._connected = False
        self._running = False
        if self._punch_client:
            self._punch_client.close()


__all__ = [
    # 高级封装
    "P2PTunnel",
    # 核心组件
    "STUNClient",
    "NATDetector",
    "NATType",
    "TCPPunchClient",
    "tcp_simultaneous_open",
    "TunnelExposer",
    "TunnelVisitor",
    # 信令
    "PeerInfo",
    "SignalingExchange",
    # 重连
    "ReconnectManager",
    "auto_reconnect",
    # 异常
    "P2PTunnelError",
    "STUNError",
    "STUNTimeoutError",
    "NATPunchError",
    "SymmetricNATError",
    "TunnelError",
    "TunnelDisconnectedError",
    "SignalingError",
]

__version__ = "1.0.0"
