"""
P2P 内网穿透模块 - 断线重连

当 P2P 隧道因网络波动断开时，自动重试建立新隧道。
使用指数退避策略控制重试节奏。
"""

import time
import logging
import threading
from typing import Callable, Optional

from .config import (
    RECONNECT_MAX_ATTEMPTS, RECONNECT_BASE_DELAY,
    RECONNECT_MAX_DELAY, RECONNECT_BACKOFF_FACTOR,
)

logger = logging.getLogger(__name__)


class ReconnectManager:
    """
    重连管理器

    当检测到隧道断开时，自动按指数退避策略重试建立连接。

    使用方式:
        manager = ReconnectManager(connect_func, on_connected, on_failed)
        manager.start()
    """

    def __init__(self,
                 connect_func: Callable[[], bool],
                 on_connected: Callable[[], None] = None,
                 on_failed: Callable[[], None] = None,
                 max_attempts: int = RECONNECT_MAX_ATTEMPTS,
                 base_delay: float = RECONNECT_BASE_DELAY,
                 max_delay: float = RECONNECT_MAX_DELAY,
                 backoff_factor: float = RECONNECT_BACKOFF_FACTOR):
        """
        Args:
            connect_func: 连接函数，返回 True 表示成功
            on_connected: 连接成功后的回调
            on_failed: 所有重试失败后的回调
            max_attempts: 最大重试次数（0 表示无限）
            base_delay: 初始重试延迟（秒）
            max_delay: 最大重试延迟（秒）
            backoff_factor: 延迟倍增因子
        """
        self._connect_func = connect_func
        self._on_connected = on_connected
        self._on_failed = on_failed
        self._max_attempts = max_attempts
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._backoff_factor = backoff_factor

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """启动重连循环（在后台线程中运行）"""
        if self._thread and self._thread.is_alive():
            logger.warning("重连管理器已在运行")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._reconnect_loop, daemon=True)
        self._thread.start()
        logger.info("重连管理器已启动")

    def stop(self) -> None:
        """停止重连"""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("重连管理器已停止")

    def _reconnect_loop(self) -> None:
        """重连循环"""
        attempt = 0

        while not self._stop_event.is_set():
            if self._max_attempts > 0 and attempt >= self._max_attempts:
                logger.error("已达到最大重试次数 (%d)，放弃重连", self._max_attempts)
                if self._on_failed:
                    self._on_failed()
                return

            attempt += 1

            # 计算延迟
            delay = min(
                self._base_delay * (self._backoff_factor ** (attempt - 1)),
                self._max_delay
            )

            logger.info(
                "重连尝试 %d/%s，等待 %.1f 秒...",
                attempt,
                str(self._max_attempts) if self._max_attempts > 0 else "∞",
                delay
            )
            print(f"  [重连] 第 {attempt} 次尝试，等待 {delay:.0f} 秒...")

            # 等待延迟（可被中断）
            if self._stop_event.wait(delay):
                return

            # 尝试连接
            try:
                success = self._connect_func()
            except Exception as e:
                logger.error("重连异常: %s", e)
                success = False

            if success:
                logger.info("重连成功!")
                print("  [重连] 连接成功!")
                if self._on_connected:
                    self._on_connected()
                return

    def reset(self) -> None:
        """重置重连计数器（连接成功后调用）"""
        pass  # 当前实现中不需要，每次 start 重新计数


def auto_reconnect(connect_func: Callable[[], bool],
                   on_disconnect: Callable = None) -> ReconnectManager:
    """
    便捷函数：创建自动重连管理器。

    用法:
        def try_connect():
            # 尝试打洞 + 建立隧道
            return True  # 返回是否成功

        mgr = auto_reconnect(try_connect)
        mgr.start()

        # ... 当检测到断线时 ...
        mgr.start()  # 开始重连

    Args:
        connect_func: 重连函数
        on_disconnect: 断线回调（检测到断线时调用）

    Returns:
        ReconnectManager 实例
    """
    return ReconnectManager(
        connect_func=connect_func,
        on_failed=lambda: print("  [!] 所有重连尝试均失败，请检查网络后重新启动程序")
    )
