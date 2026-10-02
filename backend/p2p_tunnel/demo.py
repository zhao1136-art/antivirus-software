"""
P2P 内网穿透 - 控制台演示程序

演示基于 STUN + TCP Simultaneous Open 的端口穿透功能。

用法:
    python -m p2p_tunnel.demo

角色说明:
    - 暴露端: 把本机服务端口暴露出去，让对方能访问
    - 访问端: 通过 P2P 隧道访问暴露端的服务

    双方需同时运行本程序，选择不同角色，通过交换连接码完成配对。
"""

import sys
import time
import socket
import logging
import argparse

from . import (
    P2PTunnel, PeerInfo, SignalingExchange,
    NATPunchError, SymmetricNATError, NATType,
)
from .tcp_punch import TCPPunchClient
from .config import PUNCH_PORT_RANGE


def _setup_logging(verbose: bool = False):
    """配置日志"""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    else:
        logging.basicConfig(
            level=logging.WARNING,
            format="%(levelname)s: %(message)s",
        )


def _check_local_service(host: str, port: int) -> bool:
    """验证本地服务是否可达"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        sock.close()
        return True
    except Exception:
        return False


def _persistent_punch(local_info: PeerInfo, remote_info: PeerInfo,
                      max_duration: float = 60.0,
                      attempt_timeout: float = 8.0) -> socket.socket:
    """
    持续尝试打洞，直到成功或超时。

    双方可能不在完全相同的时刻开始打洞，
    因此需要持续重试来覆盖时间窗口。

    Args:
        local_info: 本机连接信息
        remote_info: 对方连接信息
        max_duration: 最大尝试时长（秒）
        attempt_timeout: 单次尝试超时

    Returns:
        建立好的 socket

    Raises:
        NATPunchError: 所有尝试失败
    """
    deadline = time.time() + max_duration
    attempt = 0

    # 打洞远程端口使用对方的 punch_port（假设锥形NAT不改变端口号）
    # STUN返回的public_port是UDP映射，不能直接用于TCP打洞
    remote_port = remote_info.punch_port

    print()
    print("  [*] 开始持续打洞，请确保对方也已启动...")
    print(f"  [*] 本机端口: {local_info.punch_port}, 远端: {remote_info.public_ip}:{remote_port}")
    print(f"  [*] 最长等待 {max_duration:.0f} 秒")

    last_error = None

    while time.time() < deadline:
        attempt += 1
        remaining = deadline - time.time()
        single_timeout = min(attempt_timeout, remaining)

        if single_timeout <= 0:
            break

        # 使用约定端口持续重试，覆盖双方启动时间差
        client = TCPPunchClient(local_info.punch_port)

        try:
            sock = client.punch(
                remote_info.public_ip,
                remote_port,
                timeout=single_timeout,
            )
            print(f"\n  [OK] 第 {attempt} 次尝试成功!")
            return sock
        except NATPunchError as e:
            last_error = e
            elapsed = time.time() - (deadline - max_duration)
            print(f"\r  [..] 打洞尝试 {attempt} (已耗时 {elapsed:.0f}s)...", end="")
            time.sleep(1.5)
        except Exception as e:
            last_error = e
            time.sleep(1.5)

    print()
    raise last_error or NATPunchError("打洞失败，当前网络环境无法P2P直连")


def _run_exposer(args):
    """运行暴露端"""
    print()
    print("=" * 55)
    print("   安盾 P2P 内网穿透 - 暴露端 (服务提供方)")
    print("=" * 55)

    # 输入参数
    if args.target_port:
        target_port = args.target_port
    else:
        try:
            target_port = int(input("  要暴露的本地服务端口: ").strip())
        except ValueError:
            print("  [!] 无效端口号")
            return 1

    # 验证本地服务
    print(f"  验证本地服务 127.0.0.1:{target_port} ...")
    if not _check_local_service("127.0.0.1", target_port):
        print(f"  [!] 警告: 本地端口 {target_port} 没有可访问的服务")
        print(f"  [!] 请确保目标服务已启动，然后重新运行")
        yn = input("  是否继续? (y/n): ").strip().lower()
        if yn not in ("y", "yes"):
            return 1
    else:
        print(f"  [OK] 本地服务 127.0.0.1:{target_port} 可达")

    # NAT 检测
    print()
    print("  [*] 正在检测 NAT 类型...")
    tunnel = P2PTunnel(role="exposer", target_port=target_port)

    try:
        local_info = tunnel.get_local_info()
    except SymmetricNATError as e:
        print(f"\n  [X] {e}")
        print("  打洞失败，当前网络环境无法P2P直连")
        return 1

    if tunnel.nat_type == NATType.OPEN_INTERNET:
        print("  [OK] 公网直连，无需打洞")

    # 显示连接码
    SignalingExchange.show_local_info(local_info)

    # 获取对方信息
    remote_info = SignalingExchange.input_remote_info()

    if remote_info.role != "visitor":
        print("  [!] 警告: 对方角色不是'访问端'，请确认")

    # 开始打洞
    try:
        sock = _persistent_punch(local_info, remote_info,
                                 max_duration=args.punch_timeout)
    except NATPunchError as e:
        print(f"\n  [X] {e}")
        return 1

    # 启动隧道转发
    print()
    print("  [*] 启动隧道转发...")
    print(f"  P2P 隧道 <--> 本地服务 127.0.0.1:{target_port}")
    print("  等待对方访问...")
    print()

    from .tunnel import TunnelExposer
    exposer = TunnelExposer(
        sock,
        target_host="127.0.0.1",
        target_port=target_port,
    )

    try:
        exposer.start()
    except KeyboardInterrupt:
        print("\n  [*] 用户中断")
    except Exception as e:
        print(f"\n  [X] 隧道异常: {e}")

    return 0


def _run_visitor(args):
    """运行访问端"""
    print()
    print("=" * 55)
    print("   御天 P2P 内网穿透 - 访问端 (服务消费方)")
    print("=" * 55)

    # 输入参数
    if args.listen_port:
        listen_port = args.listen_port
    else:
        try:
            listen_port = int(input("  本地监听端口（访问远端服务的入口）: ").strip())
        except ValueError:
            print("  [!] 无效端口号")
            return 1

    # NAT 检测
    print()
    print("  [*] 正在检测 NAT 类型...")
    tunnel = P2PTunnel(role="visitor", local_listen_port=listen_port)

    try:
        local_info = tunnel.get_local_info()
    except SymmetricNATError as e:
        print(f"\n  [X] {e}")
        print("  打洞失败，当前网络环境无法P2P直连")
        return 1

    # 显示连接码
    SignalingExchange.show_local_info(local_info)

    # 获取对方信息
    remote_info = SignalingExchange.input_remote_info()

    if remote_info.role != "exposer":
        print("  [!] 警告: 对方角色不是'暴露端'，请确认")

    target_port = remote_info.target_port or 80
    print(f"  远端服务端口: {target_port}")

    # 开始打洞
    try:
        sock = _persistent_punch(local_info, remote_info,
                                 max_duration=args.punch_timeout)
    except NATPunchError as e:
        print(f"\n  [X] {e}")
        return 1

    # 启动隧道转发
    print()
    print("  [*] 启动端口转发...")
    print(f"  本地 http://127.0.0.1:{listen_port} <--> P2P <--> 远端服务 (端口 {target_port})")
    print(f"  现在可以通过 http://127.0.0.1:{listen_port} 访问远端服务")
    print()

    from .tunnel import TunnelVisitor
    visitor = TunnelVisitor(
        sock,
        local_listen_host="127.0.0.1",
        local_listen_port=listen_port,
    )

    try:
        visitor.start(single_connection=True)
    except KeyboardInterrupt:
        print("\n  [*] 用户中断")
    except Exception as e:
        print(f"\n  [X] 隧道异常: {e}")

    return 0


def _run_interactive(args):
    """交互式选择模式"""
    print()
    print("=" * 55)
    print("   安盾 P2P 内网穿透工具 v1.0")
    print("   基于 STUN + TCP Simultaneous Open")
    print("=" * 55)
    print()
    print("  请选择运行模式:")
    print("    [1] 暴露端 - 把本机服务暴露给对方访问")
    print("    [2] 访问端 - 访问对方暴露的服务")
    print()

    while True:
        choice = input("  请输入 (1/2): ").strip()
        if choice == "1":
            return _run_exposer(args)
        elif choice == "2":
            return _run_visitor(args)
        else:
            print("  [!] 无效选择，请输入 1 或 2")


def main():
    parser = argparse.ArgumentParser(
        description="御天 P2P 内网穿透 - 端口转发演示",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python -m p2p_tunnel.demo                        # 交互式模式
  python -m p2p_tunnel.demo expose -p 8080         # 暴露端：暴露本地8080端口
  python -m p2p_tunnel.demo visit -p 9090          # 访问端：映射到本地9090端口
  python -m p2p_tunnel.demo expose -p 8080 -v      # 暴露端 + 详细日志
        """,
    )
    parser.add_argument(
        "mode", nargs="?", default="interactive",
        choices=["interactive", "expose", "visit"],
        help="运行模式: interactive(交互式) / expose(暴露端) / visit(访问端)"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=0, dest="port",
        help="端口号（暴露端=目标服务端口，访问端=本地监听端口）"
    )
    parser.add_argument(
        "-t", "--punch-timeout", type=float, default=60.0,
        help="打洞超时时间（秒），默认60"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="显示详细日志"
    )

    args = parser.parse_args()

    # 适配参数
    args.target_port = args.port if args.mode in ("expose",) else 0
    args.listen_port = args.port if args.mode in ("visit",) else 0

    _setup_logging(args.verbose)

    try:
        if args.mode == "expose":
            return _run_exposer(args)
        elif args.mode == "visit":
            return _run_visitor(args)
        else:
            return _run_interactive(args)
    except KeyboardInterrupt:
        print("\n\n  [*] 程序已退出")
        return 0
    except Exception as e:
        print(f"\n  [X] 未预期的错误: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
