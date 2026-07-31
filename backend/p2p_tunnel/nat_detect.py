"""
P2P 内网穿透模块 - NAT 类型检测

通过对多个 STUN 服务器请求的结果来判断 NAT 类型。
主要区分：开放网络 / 非对称NAT（可打洞） / 对称NAT（不可打洞）。
"""

import socket
import logging
from enum import Enum, auto
from typing import Tuple, List

from .stun_client import STUNClient
from .config import STUN_SERVERS, STUN_TIMEOUT, STUN_MAX_RETRIES

logger = logging.getLogger(__name__)


class NATType(Enum):
    """NAT 类型枚举"""
    OPEN_INTERNET = auto()           # 公网直连，无 NAT
    FULL_CONE = auto()               # 全锥形 NAT
    RESTRICTED_CONE = auto()         # 受限锥形 NAT
    PORT_RESTRICTED_CONE = auto()    # 端口受限锥形 NAT
    SYMMETRIC = auto()               # 对称型 NAT（极难打洞）
    UNKNOWN = auto()                 # 无法确定

    @property
    def can_punch(self) -> bool:
        """该 NAT 类型是否支持 TCP 打洞"""
        return self in (
            NATType.OPEN_INTERNET,
            NATType.FULL_CONE,
            NATType.RESTRICTED_CONE,
            NATType.PORT_RESTRICTED_CONE,
        )

    @property
    def display_name(self) -> str:
        """中文显示名"""
        names = {
            NATType.OPEN_INTERNET: "公网直连（无NAT）",
            NATType.FULL_CONE: "全锥形NAT",
            NATType.RESTRICTED_CONE: "受限锥形NAT",
            NATType.PORT_RESTRICTED_CONE: "端口受限锥形NAT",
            NATType.SYMMETRIC: "对称型NAT",
            NATType.UNKNOWN: "未知类型",
        }
        return names.get(self, "未知")


def _get_local_ips() -> List[str]:
    """获取本机所有非回环 IPv4 地址"""
    ips = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    return ips


def _is_public_ip(ip: str) -> bool:
    """判断是否为公网 IP"""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False

    # 私有地址段
    if octets[0] == 10:
        return False
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return False
    if octets[0] == 192 and octets[1] == 168:
        return False
    # 回环
    if octets[0] == 127:
        return False
    # CGNAT (100.64.0.0/10)
    if octets[0] == 100 and 64 <= octets[1] <= 127:
        return False

    return True


class NATDetector:
    """
    NAT 类型检测器

    通过向多个 STUN 服务器发送请求来判断当前网络的 NAT 类型。
    核心逻辑：
    - 本地 IP == 公网 IP  →  无 NAT / 公网直连
    - 不同 STUN 服务器返回不同映射端口  →  对称型 NAT
    - 同一映射端口  →  非对称 NAT（锥形，可打洞）
    """

    def __init__(self, stun_servers: List[Tuple[str, int]] = None,
                 timeout: float = STUN_TIMEOUT):
        self._servers = stun_servers or STUN_SERVERS
        self._timeout = timeout

        # 检测结果
        self._nat_type: NATType = NATType.UNKNOWN
        self._public_ip: str = ""
        self._public_port: int = 0
        self._local_ips: List[str] = []

    @property
    def nat_type(self) -> NATType:
        return self._nat_type

    @property
    def public_ip(self) -> str:
        return self._public_ip

    @property
    def public_port(self) -> int:
        return self._public_port

    @property
    def public_addr(self) -> Tuple[str, int]:
        return (self._public_ip, self._public_port)

    @property
    def local_ips(self) -> List[str]:
        return self._local_ips

    @property
    def can_punch(self) -> bool:
        return self._nat_type.can_punch

    def detect(self) -> NATType:
        """
        执行 NAT 类型检测。

        Returns:
            检测到的 NAT 类型

        策略：
        1. 先尝试多个 STUN 服务器，统计映射地址
        2. 如果所有服务器返回的映射地址一致 → 非对称NAT
        3. 如果不一致 → 对称NAT
        4. 如果本地IP就是公网IP → 无NAT
        """
        self._local_ips = _get_local_ips()
        logger.info("本机内网 IP: %s", self._local_ips)

        # 收集多个 STUN 服务器的映射结果
        mappings: List[Tuple[str, int]] = []
        working_servers = []

        for host, port in self._servers:
            try:
                client = STUNClient(host, port, timeout=self._timeout,
                                    max_retries=STUN_MAX_RETRIES)
                ip, mapped_port = client.query()
                mappings.append((ip, mapped_port))
                working_servers.append((host, port))
                logger.debug("  %s:%d → %s:%d", host, port, ip, mapped_port)
            except Exception as e:
                logger.debug("  %s:%d 不可用: %s", host, port, e)

        if not mappings:
            logger.error("所有 STUN 服务器均不可达")
            self._nat_type = NATType.UNKNOWN
            return NATType.UNKNOWN

        # 取第一个成功的映射作为主要公网地址
        self._public_ip, self._public_port = mappings[0]
        logger.info("主映射公网地址: %s:%d", self._public_ip, self._public_port)

        # ── 判断 NAT 类型 ──────────────────────

        # 1. 检查是否公网直连（本地IP包含公网IP）
        if self._public_ip in self._local_ips:
            self._nat_type = NATType.OPEN_INTERNET
            logger.info("NAT 类型: 公网直连")
            return NATType.OPEN_INTERNET

        # 检查本地IP是否为公网IP（多网卡场景）
        for local_ip in self._local_ips:
            if _is_public_ip(local_ip):
                self._nat_type = NATType.OPEN_INTERNET
                self._public_ip = local_ip
                logger.info("NAT 类型: 公网直连 (多网卡)")
                return NATType.OPEN_INTERNET

        # 2. 检查是否对称 NAT（不同服务器返回不同映射端口）
        unique_mappings = set(mappings)
        if len(unique_mappings) > 1:
            # 收集不同端口
            ports = sorted(set(p for _, p in mappings))
            logger.info(
                "检测到不同映射端口: %s → Symmetric NAT", ports
            )
            self._nat_type = NATType.SYMMETRIC
            return NATType.SYMMETRIC

        # 3. 非对称 NAT，尝试细分
        #    由于公共 STUN 服务器通常不支持 CHANGE-REQUEST，
        #    无法精确区分 Full Cone / Restricted / Port Restricted。
        #    保守标记为 PORT_RESTRICTED_CONE（最常见的家庭NAT类型）
        self._nat_type = NATType.PORT_RESTRICTED_CONE
        logger.info("NAT 类型: 锥形NAT (非对称，可尝试打洞)")
        return NATType.PORT_RESTRICTED_CONE

    def summary(self) -> str:
        """返回检测结果摘要"""
        lines = [
            "=" * 50,
            "  NAT 类型检测结果",
            "=" * 50,
            f"  本机内网 IP : {', '.join(self._local_ips) if self._local_ips else '未知'}",
            f"  公网映射地址: {self._public_ip}:{self._public_port}",
            f"  NAT 类型    : {self._nat_type.display_name}",
            f"  是否可打洞  : {'是' if self.can_punch else '否'}",
            "=" * 50,
        ]
        return "\n".join(lines)
