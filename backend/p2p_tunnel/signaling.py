"""
P2P 内网穿透模块 - 信令交换

在没有自建信令服务器的情况下，通过编码/解码连接信息，
实现双方的信息交换。支持手动输入、剪贴板等方式。

连接信息（PeerInfo）包含：
- 公网 IP 和端口（用于打洞）
- 目标服务端口（暴露端告诉访问端应该转发到哪个端口）
- 角色标识
"""

import json
import base64
import logging
from dataclasses import dataclass, asdict
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class PeerInfo:
    """
    对等节点信息

    包含 P2P 打洞所需的全部信息，可序列化为字符串用于传递。
    """
    # 角色: "exposer"(暴露端) / "visitor"(访问端)
    role: str

    # 公网 IP（STUN 获取）
    public_ip: str

    # 公网端口（STUN 获取）
    public_port: int

    # 打洞用的本地端口
    punch_port: int

    # 目标服务端口（仅暴露端有效，告诉访问端要转发到哪个端口）
    target_port: int = 0

    # 协议版本
    version: str = "1.0"

    @classmethod
    def from_json(cls, data: dict) -> "PeerInfo":
        """从字典创建"""
        return cls(**data)

    def to_json(self) -> dict:
        """转为字典"""
        return asdict(self)

    def encode(self) -> str:
        """
        编码为可传输的字符串（Base64 JSON）。
        用户可以通过 IM / 邮件 / 口头传递此字符串。
        """
        json_str = json.dumps(self.to_json(), ensure_ascii=False)
        return base64.b64encode(json_str.encode("utf-8")).decode("ascii")

    @classmethod
    def decode(cls, encoded: str) -> "PeerInfo":
        """
        从编码字符串解码。

        Args:
            encoded: Base64 编码的连接信息字符串

        Returns:
            PeerInfo 实例

        Raises:
            ValueError: 解码失败
        """
        try:
            json_str = base64.b64decode(encoded.encode("ascii")).decode("utf-8")
            data = json.loads(json_str)
            return cls.from_json(data)
        except Exception as e:
            raise ValueError(f"解码连接信息失败: {e}") from e

    def display(self) -> str:
        """生成可显示的信息摘要"""
        lines = [
            "-" * 45,
            f"  角色       : {'暴露端 (服务提供方)' if self.role == 'exposer' else '访问端 (服务消费方)'}",
            f"  公网地址   : {self.public_ip}:{self.public_port}",
            f"  打洞端口   : {self.punch_port}",
        ]
        if self.target_port:
            lines.append(f"  目标端口   : {self.target_port}")
        lines.append("-" * 45)
        return "\n".join(lines)


class SignalingExchange:
    """
    信令交换器

    提供交互式界面让用户输入/查看连接信息。
    在没有信令服务器的情况下，用户通过其他渠道（IM、邮件等）
    传递编码后的连接信息字符串。
    """

    @staticmethod
    def show_local_info(info: PeerInfo) -> str:
        """
        显示本机连接信息，返回编码字符串供用户传递给对方。

        Args:
            info: 本机的 PeerInfo

        Returns:
            编码后的连接信息字符串
        """
        encoded = info.encode()
        print()
        print(info.display())
        print(f"  [连接码] 请将此字符串发送给对方:")
        print(f"  {encoded}")
        print()
        return encoded

    @staticmethod
    def input_remote_info() -> PeerInfo:
        """
        交互式输入对方的连接信息。

        Returns:
            对方的 PeerInfo
        """
        print()
        print("=" * 50)
        print("  请输入对方的连接码（Base64字符串）")
        print("=" * 50)
        while True:
            try:
                encoded = input("  连接码: ").strip()
                if not encoded:
                    print("  [!] 输入不能为空")
                    continue
                info = PeerInfo.decode(encoded)
                print()
                print("  对方信息:")
                print(info.display())
                return info
            except ValueError as e:
                print(f"  [!] 无效的连接码: {e}")
                print("  请重新输入")

    @staticmethod
    def confirm_ready() -> bool:
        """提示用户确认是否准备好开始打洞"""
        print()
        inp = input("  双方信息已交换，是否开始打洞连接? (y/n): ").strip().lower()
        return inp in ("y", "yes", "")
