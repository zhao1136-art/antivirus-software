"""
P2P 内网穿透模块 - GUI 后端服务

基于 Python http.server 的轻量级 HTTP 服务，
为 Web 前端提供 REST API，桥接 GUI 与 P2P 隧道模块。

启动方式:
    python -m p2p_tunnel.gui_server
    python -m p2p_tunnel.gui_server --port 9020
"""

import json
import os
import sys
import time
import random
import socket
import threading
import logging
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any
from urllib.parse import urlparse

from .config import PUNCH_PORT_RANGE, PUNCH_TIMEOUT
from .nat_detect import NATDetector, NATType
from .signaling import PeerInfo
from .tcp_punch import TCPPunchClient
from .tunnel import TunnelExposer, TunnelVisitor
from .exceptions import NATPunchError, SymmetricNATError

logger = logging.getLogger(__name__)

# GUI 文件路径（兼容开发模式与 PyInstaller 打包）
if getattr(sys, 'frozen', False):
    # PyInstaller 打包后，资源在临时解压目录
    _GUI_DIR = os.path.join(sys._MEIPASS, "p2p_tunnel", "gui")
else:
    _GUI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui")


# ── 全局状态（单用户模式，内存存储）─────────────────
class AppState:
    """应用全局状态"""
    def __init__(self):
        self.lock = threading.Lock()
        self.nat_detector: Optional[NATDetector] = None
        self.peer_info: Optional[PeerInfo] = None
        self.remote_info: Optional[PeerInfo] = None
        self.punch_client: Optional[TCPPunchClient] = None
        self.tunnel_socket: Optional[socket.socket] = None
        self.tunnel_running = False
        self.tunnel_thread: Optional[threading.Thread] = None
        self.stop_tunnel = threading.Event()

        # 隧道组件
        self.exposer: Optional[TunnelExposer] = None
        self.visitor: Optional[TunnelVisitor] = None

    def reset(self):
        """重置状态"""
        with self.lock:
            if self.tunnel_thread and self.tunnel_thread.is_alive():
                self.stop_tunnel.set()
            if self.tunnel_socket:
                try:
                    self.tunnel_socket.close()
                except Exception:
                    pass
            if self.punch_client:
                try:
                    self.punch_client.close()
                except Exception:
                    pass
            self.tunnel_socket = None
            self.punch_client = None
            self.tunnel_running = False
            self.remote_info = None
            self.stop_tunnel.clear()


_state = AppState()


# ── API 处理器 ──────────────────────────────────

def _build_peer_info(detector: NATDetector, role: str, target_port: int) -> PeerInfo:
    """根据 NAT 检测结果构建 PeerInfo"""
    punch_port = random.randint(*PUNCH_PORT_RANGE)
    return PeerInfo(
        role=role,
        public_ip=detector.public_ip,
        public_port=detector.public_port,
        punch_port=punch_port,
        target_port=target_port,
    )


def handle_detect(data: dict) -> dict:
    """
    POST /api/detect
    执行 NAT 检测，返回结果和连接码
    """
    role = data.get("role", "exposer")
    target_port = data.get("target_port", 8080)
    listen_port = data.get("listen_port", 9090)

    _state.reset()

    # NAT 检测
    detector = NATDetector()
    nat_type = detector.detect()

    if not nat_type.can_punch:
        # 即使不能打洞也返回结果，前端会提示
        pass

    _state.nat_detector = detector
    peer_info = _build_peer_info(detector, role, target_port)
    _state.peer_info = peer_info

    connection_code = peer_info.encode()

    return {
        "ok": True,
        "nat_type": nat_type.name,
        "nat_type_name": nat_type.display_name,
        "can_punch": nat_type.can_punch,
        "public_ip": detector.public_ip,
        "public_port": detector.public_port,
        "punch_port": peer_info.punch_port,
        "connection_code": connection_code,
        "peer_info": peer_info.to_json(),
    }


def handle_connect(data: dict) -> dict:
    """
    POST /api/connect
    执行 P2P 打洞和隧道建立
    """
    role = data.get("role", "exposer")
    remote_code = data.get("remote_code", "")
    my_info_dict = data.get("my_info")
    target_port = data.get("target_port", 8080)
    listen_port = data.get("listen_port", 9090)

    # 解码远程信息
    try:
        remote_info = PeerInfo.decode(remote_code)
    except ValueError as e:
        return {"ok": False, "error": f"无效的连接码: {e}"}

    _state.remote_info = remote_info

    # 重建本地 peer_info
    if my_info_dict:
        try:
            _state.peer_info = PeerInfo.from_json(my_info_dict)
        except Exception:
            pass

    if not _state.peer_info:
        return {"ok": False, "error": "请先执行 NAT 检测"}

    local_info = _state.peer_info

    # ── 执行打洞 ──────────────────────────────
    logger.info("开始 P2P 打洞: 本机 %s:%d -> 远端 %s:%d",
                local_info.public_ip, local_info.punch_port,
                remote_info.public_ip, remote_info.punch_port)

    _state.punch_client = TCPPunchClient(local_info.punch_port)

    try:
        sock = _state.punch_client.punch(
            remote_info.public_ip,
            remote_info.punch_port,
            timeout=PUNCH_TIMEOUT,
        )
        _state.tunnel_socket = sock
    except NATPunchError as e:
        _state.reset()
        return {"ok": False, "error": str(e)}
    except Exception as e:
        _state.reset()
        return {"ok": False, "error": f"打洞异常: {e}"}

    # ── 启动隧道转发 ──────────────────────────
    _state.stop_tunnel.clear()

    if role == "exposer":
        _state.exposer = TunnelExposer(
            sock,
            target_host="127.0.0.1",
            target_port=target_port,
        )
        _state.tunnel_thread = threading.Thread(
            target=_run_exposer_tunnel, daemon=True
        )
    else:
        _state.visitor = TunnelVisitor(
            sock,
            local_listen_host="127.0.0.1",
            local_listen_port=listen_port,
        )
        _state.tunnel_thread = threading.Thread(
            target=_run_visitor_tunnel, daemon=True
        )

    _state.tunnel_running = True
    _state.tunnel_thread.start()

    # 构建响应
    entry_url = ""
    if role == "visitor":
        entry_url = f"http://127.0.0.1:{listen_port}"
    elif role == "exposer":
        entry_url = f"http://127.0.0.1:{target_port} (本地服务)"

    remote_addr = f"{remote_info.public_ip}:{remote_info.punch_port}"

    return {
        "ok": True,
        "connected": True,
        "local_addr": f"127.0.0.1:{local_info.punch_port}",
        "remote_addr": remote_addr,
        "entry_url": entry_url,
    }


def _run_exposer_tunnel():
    """在后台线程中运行暴露端隧道"""
    try:
        _state.exposer.start()
    except Exception as e:
        logger.error("暴露端隧道异常: %s", e)
    finally:
        _state.tunnel_running = False


def _run_visitor_tunnel():
    """在后台线程中运行访问端隧道"""
    try:
        _state.visitor.start(single_connection=True)
    except Exception as e:
        logger.error("访问端隧道异常: %s", e)
    finally:
        _state.tunnel_running = False


def handle_disconnect(data: dict = None) -> dict:
    """
    POST /api/disconnect
    断开连接
    """
    _state.reset()
    return {"ok": True, "disconnected": True}


# ── 路由表 ──────────────────────────────────────

API_ROUTES = {
    "/api/detect": ("POST", handle_detect),
    "/api/connect": ("POST", handle_connect),
    "/api/disconnect": ("POST", handle_disconnect),
}


# ── HTTP 请求处理器 ────────────────────────────

class GUIRequestHandler(BaseHTTPRequestHandler):
    """自定义 HTTP 请求处理器"""

    def log_message(self, format, *args):
        """使用自定义日志"""
        logger.debug("%s - %s", self.client_address[0], format % args)

    def _send_json(self, data: dict, status: int = 200):
        """发送 JSON 响应"""
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, content: str, status: int = 200):
        """发送 HTML 响应"""
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, message: str, status: int = 400):
        """发送错误 JSON"""
        self._send_json({"ok": False, "error": message}, status)

    def _read_body(self) -> dict:
        """读取 JSON 请求体"""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        raw = self.rfile.read(content_length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def do_OPTIONS(self):
        """处理 CORS 预检请求"""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        """处理 GET 请求"""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            # 返回 GUI 页面
            html_path = os.path.join(_GUI_DIR, "index.html")
            try:
                with open(html_path, "r", encoding="utf-8") as f:
                    html = f.read()
                self._send_html(html)
            except FileNotFoundError:
                self._send_error_json("GUI 页面未找到", 404)
        else:
            self._send_error_json("Not Found", 404)

    def do_POST(self):
        """处理 POST 请求"""
        parsed = urlparse(self.path)
        path = parsed.path

        if path in API_ROUTES:
            method, handler = API_ROUTES[path]
            if method != "POST":
                self._send_error_json("Method Not Allowed", 405)
                return

            try:
                data = self._read_body()
                result = handler(data)
                status = 200 if result.get("ok", True) else 400
                self._send_json(result, status)
            except Exception as e:
                logger.exception("API 处理异常")
                self._send_error_json(f"内部错误: {e}", 500)
        else:
            self._send_error_json("Not Found", 404)


class ThreadingHTTPServer(HTTPServer):
    """支持多线程的 HTTP 服务器"""
    # 允许端口重用
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


# ── 主入口 ──────────────────────────────────────

def run_server(host: str = "127.0.0.1", port: int = 9020):
    """启动 GUI 服务器"""
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [GUI] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    server = ThreadingHTTPServer((host, port), GUIRequestHandler)

    print()
    print("=" * 55)
    print("  安盾 P2P 内网穿透 - Web 控制台")
    print("=" * 55)
    print(f"  服务地址: http://{host}:{port}")
    print(f"  按 Ctrl+C 停止服务")
    print("=" * 55)
    print()

    logger.info("GUI 服务器启动: %s:%d", host, port)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止服务...")
        _state.reset()
        server.shutdown()
        print("服务已停止")


def main():
    parser = argparse.ArgumentParser(description="安盾 P2P 内网穿透 - GUI 服务器")
    parser.add_argument(
        "-p", "--port", type=int, default=9020,
        help="HTTP 服务端口（默认: 9020）"
    )
    parser.add_argument(
        "-H", "--host", default="127.0.0.1",
        help="绑定地址（默认: 127.0.0.1）"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="详细日志"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("p2p_tunnel").setLevel(logging.DEBUG)

    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
