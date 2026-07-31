"""
P2P 内网穿透模块 - TCP 打洞核心

基于 TCP Simultaneous Open 技术实现 NAT 穿透。
双方同时在相同端口向对方发起 TCP 连接，利用 NAT 的状态
跟踪机制建立直连通道。

参考: https://en.wikipedia.org/wiki/TCP_hole_punching
"""

import socket
import struct
import time
import logging
import random
from typing import Tuple, Optional

from .config import (
    PUNCH_TIMEOUT, PUNCH_PORT_RANGE, PUNCH_MAX_ATTEMPTS,
    PUNCH_RETRY_INTERVAL,
)
from .exceptions import NATPunchError

logger = logging.getLogger(__name__)


def _set_socket_options(sock: socket.socket) -> None:
    """为打洞设置必要的 socket 选项"""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # 禁用 Nagle 算法，减少延迟
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    # 设置 keepalive
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    # Windows 特定的 keepalive 设置
    try:
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, struct.pack('III', 1, 30000, 10000))
    except (OSError, AttributeError):
        pass


def _create_punch_socket(local_port: int) -> socket.socket:
    """
    创建用于打洞的 socket，绑定到指定本地端口。

    Args:
        local_port: 本地端口号

    Returns:
        已绑定但未连接的 socket（非阻塞模式）
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _set_socket_options(sock)

    try:
        sock.bind(('0.0.0.0', local_port))
    except OSError as e:
        raise NATPunchError(f"无法绑定端口 {local_port}: {e}")

    sock.setblocking(False)
    return sock


def tcp_simultaneous_open(local_port: int, remote_ip: str, remote_port: int,
                          timeout: float = PUNCH_TIMEOUT) -> socket.socket:
    """
    TCP 同时打开 - 核心打洞函数。

    此函数需要在通信双方同时调用。
    双方在相同端口上向对方的公网地址发起 TCP 连接。
    NAT 设备看到双方同时在通信，会认为这是一个合法的双向通信，
    从而允许数据包通过。

    Args:
        local_port: 本地端口号（双方必须使用相同端口范围）
        remote_ip: 对方的公网 IP
        remote_port: 对方的公网端口（NAT 映射后的端口）
        timeout: 超时时间（秒）

    Returns:
        建立好的 TCP socket 连接

    Raises:
        NATPunchError: 打洞失败
    """
    logger.info(
        "TCP 同时打开: 本地端口=%d, 远端=%s:%d, 超时=%ds",
        local_port, remote_ip, remote_port, timeout
    )

    sock = None
    deadline = time.time() + timeout

    for attempt in range(1, PUNCH_MAX_ATTEMPTS + 1):
        logger.debug("打洞尝试 %d/%d", attempt, PUNCH_MAX_ATTEMPTS)

        if sock:
            try:
                sock.close()
            except Exception:
                pass

        try:
            sock = _create_punch_socket(local_port)
        except NATPunchError:
            # 端口被占用，换一个端口
            local_port = random.randint(*PUNCH_PORT_RANGE)
            try:
                sock = _create_punch_socket(local_port)
            except NATPunchError as e:
                logger.error("无法绑定打洞端口: %s", e)
                continue

        # ── 核心：发起非阻塞 connect ──────────
        # TCP simultaneous open 的关键：
        # 双方都发起 connect，NAT 会看到双方的 SYN 包，
        # 当 NAT 认为这是同一会话时，就会放行。
        try:
            sock.connect((remote_ip, remote_port))
        except BlockingIOError:
            # 非阻塞 socket 的正常行为：连接正在建立中
            pass
        except OSError as e:
            logger.debug("connect 错误 (尝试 %d): %s", attempt, e)
            # 某些错误（如 EADDRNOTAVAIL）可能是暂时的，重试
            if attempt < PUNCH_MAX_ATTEMPTS:
                time.sleep(PUNCH_RETRY_INTERVAL)
                continue
            raise NATPunchError(f"发起连接失败: {e}") from e

        # ── 等待连接建立 ──────────────────────
        remaining = deadline - time.time()
        if remaining <= 0:
            raise NATPunchError("打洞超时")

        sock.settimeout(remaining)

        try:
            # select 方式等待可写（连接建立成功）
            _, writable, errored = None, None, None
            try:
                import select
                readable, writable, errored = select.select(
                    [], [sock], [sock], remaining
                )
            except (ValueError, OSError) as e:
                logger.debug("select 错误: %s", e)
                if attempt < PUNCH_MAX_ATTEMPTS:
                    time.sleep(PUNCH_RETRY_INTERVAL)
                    continue
                raise NATPunchError(f"select 失败: {e}") from e

            if sock in writable and sock not in errored:
                # 检查连接是否真正建立
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    sock.setblocking(True)
                    peer = sock.getpeername()
                    logger.info("打洞成功! 连接建立: %s:%d", peer[0], peer[1])
                    return sock
                else:
                    logger.debug("连接失败 (SO_ERROR=%d), 尝试 %d", err, attempt)
            elif sock in errored:
                logger.debug("连接出错 (errored), 尝试 %d", attempt)
            else:
                logger.debug("等待超时，尝试 %d", attempt)

        except socket.timeout:
            logger.debug("socket 超时，尝试 %d", attempt)

        if attempt < PUNCH_MAX_ATTEMPTS:
            logger.debug("等待 %ds 后重试...", PUNCH_RETRY_INTERVAL)
            time.sleep(PUNCH_RETRY_INTERVAL)

    # 所有尝试失败
    if sock:
        try:
            sock.close()
        except Exception:
            pass
    raise NATPunchError("打洞失败，当前网络环境无法P2P直连")


class TCPPunchClient:
    """
    TCP 打洞客户端

    封装打洞逻辑，提供更友好的接口。
    """

    def __init__(self, local_port: int = None):
        """
        Args:
            local_port: 本地打洞端口，None 则自动选择
        """
        self._local_port = local_port or random.randint(*PUNCH_PORT_RANGE)
        self._sock: Optional[socket.socket] = None

    @property
    def local_port(self) -> int:
        return self._local_port

    @property
    def is_connected(self) -> bool:
        return self._sock is not None

    @property
    def socket(self) -> Optional[socket.socket]:
        return self._sock

    def punch(self, remote_ip: str, remote_port: int,
              timeout: float = PUNCH_TIMEOUT) -> socket.socket:
        """
        执行 TCP 打洞。

        Args:
            remote_ip: 对方的公网 IP
            remote_port: 对方的公网端口
            timeout: 超时时间

        Returns:
            建立好连接的 socket

        Raises:
            NATPunchError: 打洞失败
        """
        self._sock = tcp_simultaneous_open(
            self._local_port, remote_ip, remote_port, timeout
        )
        return self._sock

    def close(self):
        """关闭打洞连接"""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
