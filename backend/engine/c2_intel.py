"""
C2 威胁情报模块
加载 C2IntelFeeds 数据，提供 C2 IP/域名 查询能力
兼容 Python 3.10+
"""

import csv
import time
from collections import OrderedDict
from pathlib import Path


# ── 数据目录定位（基于本文件所在位置） ──────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_C2_DATA_DIR = _PROJECT_ROOT / "C2IntelFeeds-master" / "C2IntelFeeds-master"
_FEEDS_DIR = _C2_DATA_DIR / "feeds"
_CONFIGS_DIR = _C2_DATA_DIR / "C2_configs"


# ══════════════════════════════════════════════════════════════════
#  简易 TTL 缓存
# ══════════════════════════════════════════════════════════════════

class _TTLCache:
    """带过期时间的内存缓存，LRU 淘汰策略"""

    def __init__(self, maxsize: int = 4096, ttl: float = 300):
        """
        :param maxsize: 最大缓存条目数
        :param ttl:      缓存生存时间（秒），默认 5 分钟
        """
        self._maxsize = maxsize
        self._ttl = ttl
        self._store: OrderedDict[str, tuple[float, object]] = OrderedDict()

    def get(self, key: str):
        """获取缓存值，过期或不存在返回 None"""
        if key not in self._store:
            return None
        ts, val = self._store[key]
        if time.monotonic() - ts > self._ttl:
            del self._store[key]
            return None
        # 移到末尾（LRU）
        self._store.move_to_end(key)
        return val

    def set(self, key: str, value: object):
        """写入缓存"""
        if key in self._store:
            self._store.move_to_end(key)
        self._store[key] = (time.monotonic(), value)
        # 超量淘汰最久未使用条目
        while len(self._store) > self._maxsize:
            self._store.popitem(last=False)

    def clear(self):
        self._store.clear()

    def __len__(self):
        return len(self._store)


# ══════════════════════════════════════════════════════════════════
#  C2IP 读取辅助
# ══════════════════════════════════════════════════════════════════

def _read_csv_skip_comments(filepath: Path):
    """读取以 # 开头注释行的 CSV，自动跳过注释行"""
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(line for line in fh if not line.lstrip().startswith("#"))
        yield from reader


# ══════════════════════════════════════════════════════════════════
#  C2IntelEngine  —— 核心类
# ══════════════════════════════════════════════════════════════════

class C2IntelEngine:
    """C2 威胁情报查询引擎"""

    def __init__(self):
        # 原始数据存储
        self._ip_map: dict[str, str] = {}           # IP → IOC 描述
        self._domain_map: dict[str, str] = {}       # 域名 → IOC 描述
        self._ipport_map: dict[str, list[dict]] = {}  # IP → [{"port": ..., "ioc": ...}]
        self._cobalt_strike: list[dict] = []        # Cobalt Strike 配置列表

        # 统计信息
        self._stats: dict = {}
        self._loaded = False

        # 查询结果缓存
        self._cache = _TTLCache(maxsize=4096, ttl=300)

    # ── 数据加载 ──────────────────────────────────────────────

    def load(self, force: bool = False):
        """
        加载所有 C2 威胁情报数据
        :param force: 为 True 时强制重新加载
        """
        if self._loaded and not force:
            return

        self._ip_map.clear()
        self._domain_map.clear()
        self._ipport_map.clear()
        self._cobalt_strike.clear()
        self._cache.clear()

        self._load_ipc2s()
        self._load_domainc2s()
        self._load_ipportc2s()
        self._load_cobaltstrike_config()

        self._loaded = True

    def _load_ipc2s(self):
        """加载 feeds/IPC2s.csv —— 已验证 C2 IP 列表"""
        path = _FEEDS_DIR / "IPC2s.csv"
        if not path.is_file():
            return
        for row in _read_csv_skip_comments(path):
            if len(row) < 2:
                continue
            ip = row[0].strip()
            ioc = row[1].strip()
            if ip:
                self._ip_map[ip] = ioc

    def _load_domainc2s(self):
        """加载 feeds/domainC2s-filter-abused.csv —— 已验证 C2 域名列表"""
        path = _FEEDS_DIR / "domainC2s-filter-abused.csv"
        if not path.is_file():
            return
        for row in _read_csv_skip_comments(path):
            if len(row) < 2:
                continue
            domain = row[0].strip()
            ioc = row[1].strip()
            if domain:
                self._domain_map[domain] = ioc

    def _load_ipportc2s(self):
        """加载 feeds/IPPortC2s.csv —— 已验证 C2 IP:端口 列表"""
        path = _FEEDS_DIR / "IPPortC2s.csv"
        if not path.is_file():
            return
        for row in _read_csv_skip_comments(path):
            if len(row) < 3:
                continue
            ip = row[0].strip()
            port = row[1].strip()
            ioc = row[2].strip()
            if ip and port:
                self._ipport_map.setdefault(ip, []).append({
                    "port": port,
                    "ioc": ioc,
                })

    def _load_cobaltstrike_config(self):
        """加载 C2_configs/cobaltstrike.csv —— Cobalt Strike 服务端配置"""
        path = _CONFIGS_DIR / "cobaltstrike.csv"
        if not path.is_file():
            return
        # cobaltstrike.csv 有标准表头，字段内可能含换行，用 csv.DictReader 解析
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                # 只保留有效 IP 的记录
                ip = (row.get("ip") or "").strip()
                if not ip:
                    continue
                entry = {
                    "ip": ip,
                    "port": (row.get("Port") or row.get("port") or "").strip(),
                    "c2_server": (row.get("C2Server") or "").strip(),
                    "host_header": (row.get("HostHeader") or "").strip(),
                    "beacon_type": (row.get("BeaconType") or "").strip(),
                    "user_agent": (row.get("UserAgent") or "").strip(),
                    "first_seen": (row.get("FirstSeen") or "").strip(),
                    "asn": (row.get("ASN") or "").strip(),
                    "watermark": (row.get("Watermark") or "").strip(),
                }
                self._cobalt_strike.append(entry)

    # ── 查询接口 ──────────────────────────────────────────────

    def lookup_ip(self, ip: str) -> dict | None:
        """
        查询指定 IP 的 C2 情报
        :return: 命中时返回详细字典，否则返回 None
        """
        ip = ip.strip()
        if not ip:
            return None

        cache_key = f"ip:{ip}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        # 确保数据已加载
        if not self._loaded:
            self.load()

        result = {}

        # 来自 IPC2s 的基本信息
        if ip in self._ip_map:
            result["ioc"] = self._ip_map[ip]

        # 来自 IPPortC2s 的端口信息
        if ip in self._ipport_map:
            result["ports"] = self._ipport_map[ip]

        # 来自 Cobalt Strike 配置的详细信息
        cs_entries = [e for e in self._cobalt_strike if e["ip"] == ip]
        if cs_entries:
            result["cobalt_strike"] = cs_entries

        outcome = result if result else None
        self._cache.set(cache_key, outcome)
        return outcome

    def lookup_domain(self, domain: str) -> dict | None:
        """
        查询指定域名的 C2 情报
        :return: 命中时返回详细字典，否则返回 None
        """
        domain = domain.strip().lower()
        if not domain:
            return None

        cache_key = f"domain:{domain}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        if not self._loaded:
            self.load()

        result = None
        if domain in self._domain_map:
            result = {"ioc": self._domain_map[domain]}

        self._cache.set(cache_key, result)
        return result

    def lookup_cobalt_strike(self, ip: str) -> list[dict]:
        """
        查询 Cobalt Strike 配置中匹配 IP 的所有条目
        :return: 匹配的配置字典列表（可能为空）
        """
        ip = ip.strip()
        if not ip:
            return []

        cache_key = f"cs:{ip}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        if not self._loaded:
            self.load()

        result = [e for e in self._cobalt_strike if e["ip"] == ip]
        self._cache.set(cache_key, result)
        return result

    # ── 统计接口 ──────────────────────────────────────────────

    def get_stats(self) -> dict:
        """返回当前加载数据的统计信息"""
        if not self._loaded:
            self.load()

        # 统计去重 IP 数（来自三个数据源的并集）
        all_ips = set(self._ip_map.keys())
        all_ips.update(self._ipport_map.keys())
        all_ips.update(e["ip"] for e in self._cobalt_strike)

        return {
            "ip_count": len(all_ips),
            "ip_basic_count": len(self._ip_map),
            "ip_port_count": len(self._ipport_map),
            "domain_count": len(self._domain_map),
            "cobalt_strike_count": len(self._cobalt_strike),
        }

    def reload(self):
        """强制重新加载所有数据"""
        self.load(force=True)


# ══════════════════════════════════════════════════════════════════
#  模块级单例（可选）
# ══════════════════════════════════════════════════════════════════

_engine: C2IntelEngine | None = None


def get_engine() -> C2IntelEngine:
    """获取模块级 C2IntelEngine 单例"""
    global _engine
    if _engine is None:
        _engine = C2IntelEngine()
        _engine.load()
    return _engine
