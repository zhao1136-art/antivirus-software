"""
P2P 内网穿透模块 - 全局配置
"""

import logging

# ── 日志 ──────────────────────────────────────────
logger = logging.getLogger("p2p_tunnel")

# ── STUN 配置 ──────────────────────────────────────
# 公共 STUN 服务器列表（用于获取公网地址 & NAT 类型检测）
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun3.l.google.com", 19302),
    ("stun4.l.google.com", 19302),
    ("stun.ekiga.net", 3478),
    ("stun.ideasip.com", 3478),
    ("stun.voipbuster.com", 3478),
]

# STUN 请求超时（秒）
STUN_TIMEOUT = 5
# STUN 请求最大重试次数
STUN_MAX_RETRIES = 2

# ── 打洞配置 ───────────────────────────────────────
# TCP simultaneous open 超时（秒）
PUNCH_TIMEOUT = 15
# 打洞端口范围（双方在此范围内选择端口进行同时打开）
PUNCH_PORT_RANGE = (40000, 50000)
# 打洞最大重试次数（单次打洞过程内）
PUNCH_MAX_ATTEMPTS = 3
# 打洞重试间隔（秒）
PUNCH_RETRY_INTERVAL = 2

# ── 隧道配置 ───────────────────────────────────────
# 数据转发缓冲区大小
BUFFER_SIZE = 65536
# keepalive 间隔（秒），0 表示不发送
KEEPALIVE_INTERVAL = 15
# 连接空闲超时（秒），0 表示不超时
IDLE_TIMEOUT = 300

# ── 重连配置 ───────────────────────────────────────
# 重连最大次数（0 表示无限）
RECONNECT_MAX_ATTEMPTS = 10
# 重连初始延迟（秒）
RECONNECT_BASE_DELAY = 2
# 重连最大延迟（秒）
RECONNECT_MAX_DELAY = 60
# 重连延迟倍增因子
RECONNECT_BACKOFF_FACTOR = 2

# ── 信令配置 ───────────────────────────────────────
# 信令通道类型: "manual"（手动输入）| "clipboard"（剪贴板）| "auto"（自动尝试）
SIGNALING_MODE = "manual"
