"""
P2P 内网穿透模块 - STUN 客户端

基于 RFC 5389 实现 STUN Binding Request/Response，
用于获取本机在 NAT 后的公网 IP 和端口。
"""

import socket
import struct
import random
import os
import logging
from typing import Tuple, Optional

from .config import STUN_TIMEOUT, STUN_MAX_RETRIES
from .exceptions import STUNTimeoutError, STUNServerUnreachableError

logger = logging.getLogger(__name__)

# ── STUN 常量 ──────────────────────────────────────
STUN_MAGIC_COOKIE = 0x2112A442

# 消息类型
BINDING_REQUEST = 0x0001
BINDING_RESPONSE_SUCCESS = 0x0101

# 属性类型
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_RESPONSE_ORIGIN = 0x802B
ATTR_OTHER_ADDRESS = 0x802C
ATTR_CHANGE_REQUEST = 0x0003
ATTR_SOFTWARE = 0x8022


def _gen_transaction_id() -> bytes:
    """生成 12 字节随机 Transaction ID"""
    return os.urandom(12)


def _build_binding_request() -> bytes:
    """构造 STUN Binding Request 报文"""
    # 消息类型: Binding Request = 0x0001
    msg_type = struct.pack("!H", BINDING_REQUEST)
    # 消息长度: 0（无属性）
    msg_length = struct.pack("!H", 0)
    # Magic Cookie
    magic = struct.pack("!I", STUN_MAGIC_COOKIE)
    # Transaction ID
    tid = _gen_transaction_id()

    return msg_type + msg_length + magic + tid


def _build_change_request(change_ip: bool = False, change_port: bool = False) -> bytes:
    """构造带 CHANGE-REQUEST 属性的 Binding Request（用于 NAT 检测）"""
    # CHANGE-REQUEST 属性值: 4字节
    # bit 0: change IP, bit 1: change port
    flags = 0
    if change_ip:
        flags |= 0x04
    if change_port:
        flags |= 0x02
    attr_value = struct.pack("!I", flags)

    # 属性头
    attr_type = struct.pack("!H", ATTR_CHANGE_REQUEST)
    attr_len = struct.pack("!H", 4)

    attrs = attr_type + attr_len + attr_value
    total_attr_len = len(attrs)

    msg_type = struct.pack("!H", BINDING_REQUEST)
    msg_length = struct.pack("!H", total_attr_len)
    magic = struct.pack("!I", STUN_MAGIC_COOKIE)
    tid = _gen_transaction_id()

    return msg_type + msg_length + magic + tid + attrs


def _parse_mapped_address(data: bytes) -> Tuple[str, int]:
    """解析 MAPPED-ADDRESS 或 XOR-MAPPED-ADDRESS 属性值"""
    if len(data) < 4:
        raise ValueError(f"地址属性数据太短: {len(data)} 字节")

    # 跳过 reserved 字节
    family = data[1]

    if family == 0x01:  # IPv4
        port = struct.unpack("!H", data[2:4])[0]
        ip = socket.inet_ntoa(data[4:8])
        return ip, port
    elif family == 0x02:  # IPv6
        port = struct.unpack("!H", data[2:4])[0]
        ip = socket.inet_ntop(socket.AF_INET6, data[4:20])
        return ip, port
    else:
        raise ValueError(f"未知地址族: {family}")


def _parse_xor_mapped_address(data: bytes) -> Tuple[str, int]:
    """解析 XOR-MAPPED-ADDRESS 属性值（RFC 5389 Section 15.2）"""
    if len(data) < 4:
        raise ValueError(f"地址属性数据太短: {len(data)} 字节")

    family = data[1]

    # XOR 端口（与 Magic Cookie 高 16 位异或）
    magic_high = (STUN_MAGIC_COOKIE >> 16) & 0xFFFF
    port_xor = struct.unpack("!H", data[2:4])[0]
    port = port_xor ^ magic_high

    if family == 0x01:  # IPv4
        # XOR 地址（与 Magic Cookie 异或）
        addr_raw = struct.unpack("!I", data[4:8])[0]
        addr = addr_raw ^ STUN_MAGIC_COOKIE
        ip = socket.inet_ntoa(struct.pack("!I", addr))
        return ip, port
    elif family == 0x02:  # IPv6
        # IPv6 XOR: 前 4 字节与 Magic Cookie 异或，后 12 字节与 Transaction ID 异或
        # 简化处理：这里暂时只取前16字节，实际需要传入 transaction_id
        ip_bytes = bytearray(data[4:20])
        magic_bytes = struct.pack("!I", STUN_MAGIC_COOKIE)
        for i in range(4):
            ip_bytes[i] ^= magic_bytes[i]
        ip = socket.inet_ntop(socket.AF_INET6, bytes(ip_bytes))
        return ip, port
    else:
        raise ValueError(f"未知地址族: {family}")


def _parse_binding_response(data: bytes, transaction_id: bytes) -> Tuple[str, int, str, int]:
    """
    解析 STUN Binding Response 报文。
    返回: (公网IP, 公网端口, 备用服务器IP, 备用服务器端口)
    """
    if len(data) < 20:
        raise ValueError(f"STUN 响应太短: {len(data)} 字节")

    msg_type = struct.unpack("!H", data[0:2])[0]
    msg_length = struct.unpack("!H", data[2:4])[0]
    magic = struct.unpack("!I", data[4:8])[0]

    if magic != STUN_MAGIC_COOKIE:
        raise ValueError(f"Magic Cookie 不匹配: {magic:#x}")

    resp_tid = data[8:20]
    if resp_tid != transaction_id:
        raise ValueError("Transaction ID 不匹配")

    if msg_type != BINDING_RESPONSE_SUCCESS:
        raise ValueError(f"非成功响应，消息类型: {msg_type:#06x}")

    mapped_ip = None
    mapped_port = None
    other_ip = None
    other_port = None

    offset = 20
    end = 20 + msg_length

    while offset < end:
        if offset + 4 > len(data):
            break

        attr_type = struct.unpack("!H", data[offset:offset + 2])[0]
        attr_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        offset += 4

        if offset + attr_len > len(data):
            break

        attr_value = data[offset:offset + attr_len]

        if attr_type == ATTR_XOR_MAPPED_ADDRESS:
            mapped_ip, mapped_port = _parse_xor_mapped_address(attr_value)
        elif attr_type == ATTR_MAPPED_ADDRESS and mapped_ip is None:
            mapped_ip, mapped_port = _parse_mapped_address(attr_value)
        elif attr_type == ATTR_OTHER_ADDRESS:
            other_ip, other_port = _parse_mapped_address(attr_value)
        elif attr_type == ATTR_RESPONSE_ORIGIN:
            try:
                other_ip, other_port = _parse_mapped_address(attr_value)
            except (ValueError, struct.error):
                pass

        # 对齐到 4 字节边界
        offset += attr_len
        if attr_len % 4 != 0:
            offset += 4 - (attr_len % 4)

    if mapped_ip is None:
        raise ValueError("响应中未找到 MAPPED-ADDRESS")

    return mapped_ip, mapped_port, (other_ip or ""), (other_port or 0)


class STUNClient:
    """
    STUN 客户端

    用于向 STUN 服务器发送 Binding Request，获取本机的公网 IP 和端口映射。
    支持 NAT 类型检测所需的 CHANGE-REQUEST 属性。
    """

    def __init__(self, server_host: str, server_port: int = 3478,
                 timeout: float = STUN_TIMEOUT, max_retries: int = STUN_MAX_RETRIES):
        self._server_host = server_host
        self._server_port = server_port
        self._timeout = timeout
        self._max_retries = max_retries

        # 缓存最后一次查询结果
        self._public_ip: Optional[str] = None
        self._public_port: Optional[int] = None
        self._other_ip: Optional[str] = None
        self._other_port: Optional[int] = None

    @property
    def public_ip(self) -> Optional[str]:
        return self._public_ip

    @property
    def public_port(self) -> Optional[int]:
        return self._public_port

    @property
    def public_addr(self) -> Optional[Tuple[str, int]]:
        if self._public_ip and self._public_port:
            return (self._public_ip, self._public_port)
        return None

    def query(self, use_change_request: bool = False,
              change_ip: bool = False, change_port: bool = False) -> Tuple[str, int]:
        """
        发送 STUN Binding Request 并返回公网 (IP, 端口)。

        Args:
            use_change_request: 是否使用 CHANGE-REQUEST 属性
            change_ip: 要求服务器从备用 IP 回包
            change_port: 要求服务器从备用端口回包

        Returns:
            (public_ip, public_port)

        Raises:
            STUNTimeoutError: 请求超时
            STUNServerUnreachableError: 服务器不可达
        """
        last_error = None

        for attempt in range(self._max_retries):
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self._timeout)

                # 构造请求
                if use_change_request:
                    request = _build_change_request(change_ip=change_ip, change_port=change_port)
                else:
                    request = _build_binding_request()

                # 提取 Transaction ID（偏移 8，长度 12）
                tid = request[8:20]

                # 解析服务器地址
                addr_info = socket.getaddrinfo(
                    self._server_host, self._server_port,
                    socket.AF_INET, socket.SOCK_DGRAM
                )
                server_addr = addr_info[0][4]

                # 发送请求
                sock.sendto(request, server_addr)

                # 接收响应
                try:
                    response, _ = sock.recvfrom(2048)
                except socket.timeout:
                    raise STUNTimeoutError(
                        f"STUN 服务器 {self._server_host}:{self._server_port} 无响应"
                    )

                # 解析响应
                mapped_ip, mapped_port, other_ip, other_port = \
                    _parse_binding_response(response, tid)

                self._public_ip = mapped_ip
                self._public_port = mapped_port
                if other_ip:
                    self._other_ip = other_ip
                    self._other_port = other_port

                logger.debug(
                    "STUN(%s:%d) -> 公网地址 %s:%d",
                    self._server_host, self._server_port,
                    mapped_ip, mapped_port
                )

                return mapped_ip, mapped_port

            except STUNTimeoutError:
                last_error = STUNTimeoutError(
                    f"STUN 请求超时 ({self._server_host}:{self._server_port})，"
                    f"已重试 {attempt + 1}/{self._max_retries}"
                )
                logger.warning(str(last_error))
            except (socket.gaierror, socket.error) as e:
                last_error = STUNServerUnreachableError(
                    f"无法连接 STUN 服务器 {self._server_host}:{self._server_port}: {e}"
                )
                logger.warning(str(last_error))
                break  # 网络错误不重试
            except Exception as e:
                last_error = e
                logger.warning("STUN 查询异常: %s", e)
            finally:
                if sock:
                    sock.close()

        raise last_error or STUNTimeoutError("STUN 查询失败")
