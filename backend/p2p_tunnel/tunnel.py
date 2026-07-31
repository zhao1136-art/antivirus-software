"""
P2P 内网穿透模块 - 隧道转发

在 P2P 连接建立后，实现双向数据流转发：
- 暴露端（Exposer）：将 P2P 隧道数据转发到本地目标服务
- 访问端（Visitor）：监听本地端口，将入站连接通过 P2P 隧道转发到远端
"""

import socket
import threading
import time
import logging
import select
from typing import Optional, Callable

from .config import BUFFER_SIZE, KEEPALIVE_INTERVAL, IDLE_TIMEOUT

logger = logging.getLogger(__name__)


def _forward_data(src: socket.socket, dst: socket.socket,
                  name: str = "forward",
                  on_close: Callable = None) -> None:
    """
    单向数据转发循环。

    Args:
        src: 源 socket
        dst: 目标 socket
        name: 转发通道名称（用于日志）
        on_close: 连接关闭时的回调
    """
    logger.debug("[%s] 转发启动", name)
    try:
        while True:
            try:
                data = src.recv(BUFFER_SIZE)
            except (ConnectionError, OSError) as e:
                logger.debug("[%s] 读取错误: %s", name, e)
                break

            if not data:
                logger.debug("[%s] 远端关闭连接", name)
                break

            try:
                dst.sendall(data)
            except (ConnectionError, OSError) as e:
                logger.debug("[%s] 写入错误: %s", name, e)
                break
    finally:
        logger.debug("[%s] 转发结束", name)
        if on_close:
            on_close()


def _close_socket(sock: socket.socket) -> None:
    """安全关闭 socket"""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except (OSError, Exception):
        pass
    try:
        sock.close()
    except (OSError, Exception):
        pass


class TunnelExposer:
    """
    隧道暴露端

    将本地服务的端口通过 P2P 隧道暴露给远端访问。
    工作流程：
    1. P2P 打洞建立连接后，获得 p2p_socket
    2. p2p_socket 收到数据 → 转发到 local_host:local_port
    3. local_host:local_port 返回数据 → 转发回 p2p_socket
    """

    def __init__(self, p2p_socket: socket.socket,
                 target_host: str = "127.0.0.1", target_port: int = 80):
        """
        Args:
            p2p_socket: P2P 打洞建立好的 socket
            target_host: 要暴露的本地服务地址
            target_port: 要暴露的本地服务端口
        """
        self._p2p_sock = p2p_socket
        self._target_host = target_host
        self._target_port = target_port
        self._target_sock: Optional[socket.socket] = None
        self._running = False
        self._threads: list = []
        self._lock = threading.Lock()

    def start(self) -> None:
        """启动隧道暴露服务（阻塞直到一方断开）"""
        self._running = True

        # 连接到本地目标服务
        logger.info("连接本地目标服务 %s:%d ...", self._target_host, self._target_port)
        self._target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._target_sock.settimeout(10)
        try:
            self._target_sock.connect((self._target_host, self._target_port))
        except (ConnectionError, socket.timeout) as e:
            logger.error("无法连接本地目标服务: %s", e)
            _close_socket(self._p2p_sock)
            raise ConnectionError(f"无法连接本地服务 {self._target_host}:{self._target_port}") from e

        self._target_sock.settimeout(None)
        logger.info("隧道已建立: P2P <--> %s:%d", self._target_host, self._target_port)

        # 双向转发
        t1 = threading.Thread(
            target=_forward_data,
            args=(self._p2p_sock, self._target_sock, "P2P->Local"),
            daemon=True
        )
        t2 = threading.Thread(
            target=_forward_data,
            args=(self._target_sock, self._p2p_sock, "Local->P2P"),
            daemon=True
        )
        self._threads = [t1, t2]
        t1.start()
        t2.start()

        t1.join()
        t2.join()

        self.stop()

    def stop(self) -> None:
        """停止隧道服务"""
        self._running = False
        _close_socket(self._p2p_sock)
        if self._target_sock:
            _close_socket(self._target_sock)


class TunnelVisitor:
    """
    隧道访问端

    在本地监听端口，将入站连接通过 P2P 隧道转发到远端暴露的服务。
    工作流程：
    1. 本地监听 local_port
    2. 当有客户端连接进来 → 通过 P2P 隧道连接到远端
    3. 双向转发数据
    """

    def __init__(self, p2p_socket: socket.socket,
                 local_listen_host: str = "127.0.0.1", local_listen_port: int = 9090):
        """
        Args:
            p2p_socket: P2P 打洞建立好的 socket
            local_listen_host: 本地监听地址
            local_listen_port: 本地监听端口
        """
        self._p2p_sock = p2p_socket
        self._listen_host = local_listen_host
        self._listen_port = local_listen_port
        self._listen_sock: Optional[socket.socket] = None
        self._running = False

    def start(self, single_connection: bool = True) -> None:
        """
        启动隧道访问服务。

        Args:
            single_connection: True=单连接模式，接受一个本地连接后即停止监听
                               False=持续监听，每个连接建立新P2P隧道（需要多路复用）
        """
        self._running = True
        self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen_sock.bind((self._listen_host, self._listen_port))
        self._listen_sock.listen(5)
        self._listen_sock.settimeout(None)

        logger.info(
            "隧道访问端已启动: 监听 %s:%d -> P2P",
            self._listen_host, self._listen_port
        )
        print(f"  [访问端] 可通过 http://{self._listen_host}:{self._listen_port} 访问远端服务")

        try:
            while self._running:
                try:
                    client_sock, client_addr = self._listen_sock.accept()
                except OSError:
                    if not self._running:
                        break
                    continue

                logger.info("本地客户端连接: %s:%d", client_addr[0], client_addr[1])
                print(f"  [访问端] 新连接: {client_addr[0]}:{client_addr[1]}")

                # 直接双向转发
                t1 = threading.Thread(
                    target=_forward_data,
                    args=(client_sock, self._p2p_sock, "LocalClient->P2P"),
                    daemon=True
                )
                t2 = threading.Thread(
                    target=_forward_data,
                    args=(self._p2p_sock, client_sock, "P2P->LocalClient"),
                    daemon=True
                )
                t1.start()
                t2.start()

                if single_connection:
                    # 单连接模式：接受一个连接后等待
                    t1.join()
                    t2.join()
                    logger.info("单连接结束，停止监听")
                    break

        finally:
            self.stop()

    def stop(self) -> None:
        """停止隧道访问服务"""
        self._running = False
        _close_socket(self._p2p_sock)
        if self._listen_sock:
            _close_socket(self._listen_sock)
