"""
P2P 内网穿透模块 - 异常定义
"""


class P2PTunnelError(Exception):
    """P2P隧道基础异常"""
    pass


class STUNError(P2PTunnelError):
    """STUN 协议相关错误"""
    pass


class STUNTimeoutError(STUNError):
    """STUN 请求超时"""
    pass


class STUNServerUnreachableError(STUNError):
    """STUN 服务器不可达"""
    pass


class NATPunchError(P2PTunnelError):
    """NAT 打洞失败"""

    def __init__(self, message="打洞失败，当前网络环境无法P2P直连"):
        super().__init__(message)


class SymmetricNATError(NATPunchError):
    """对称型 NAT，无法打洞"""

    def __init__(self):
        super().__init__("当前网络为对称型NAT(Symmetric NAT)，无法进行P2P打洞直连")


class TunnelError(P2PTunnelError):
    """隧道相关错误"""
    pass


class TunnelDisconnectedError(TunnelError):
    """隧道连接断开"""
    pass


class TunnelTimeoutError(TunnelError):
    """隧道操作超时"""
    pass


class SignalingError(P2PTunnelError):
    """信令交换错误"""
    pass


class ConnectionRefusedError(P2PTunnelError):
    """远端拒绝连接"""
    pass
