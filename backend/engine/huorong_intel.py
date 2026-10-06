# -*- coding: utf-8 -*-
"""
火绒（Huorong）情报库集成 —— 方案 B：不经 YARA，直接内容字符串匹配

数据来源
--------
`backend/engine/huorong_data/`，由 `huorong_extract`（火绒 6.0.12.1 特征库）逆向提取：

    content_sigs.txt      内容特征串 64,972 条（prop.db 提取，已用 System32 合法文件做
                          良性语料校准，剔除会命中正常文件的通用串）
    url_blocklist.txt     恶意域名 52,204 条（malurl.db: phising/spy/fraud/rogue）
    url_categories.json   URL 内容分类（urlcls.db，仅标注类别，不用于拦截）
    detection_names.txt   检测名/家族名 67,926 个（pset.db）
    hashsig_troj.csv      火绒私有哈希签名 141,977 条（troj.db，存档）
    hashsig_hwl.csv       火绒私有哈希签名 214,708 条（hwl.db，存档）

为什么不用 YARA
---------------
这批特征串提取时只保留了 ASCII 字面量，原始的十六进制模式/偏移/掩码结构已经丢失，
本质就是"一堆字面量"。YARA 的语法层在这里没有额外能力，反而会强制走
`rule_quality` 的"最短字面量 >= 12 即判 high -> 自动隔离"逻辑。
这里直接复用项目已有的 Aho-Corasick 原生后端（`engine.aho_native`，与 yara_scanner 同款，
`add/build/find` 契约一致），匹配语义等价于 `any of them`，但更快、无转义限制，
并且**置信度与是否隔离完全由本模块控制**。

安全取舍（对齐项目"宁可漏报，不可滥杀"）
----------------------------------------
1. 分片：matcher.dll 单实例约 1.4 万模式上限（实测 1.6 万即 build 失败），
   故按 1 万/片切分，逐片匹配，结果合并。
2. 无原生匹配器时**不加载**：纯 Python AC 承载数万模式会卡死，故直接停用并记录原因。
3. 默认**仅告警**：`config.HUORONG_CONTENT_AUTO_QUARANTINE=False` 时，命中一律给
   `confidence="low"`，交由处置层降级为仅告警（不弹窗、不隔离）。
   置 True 才按字面量长度分档（>=24 high / >=16 medium / >=12 low）允许处置。

哈希签名说明
------------
火绒是私有 4+8 字节哈希，算法未逆向，**无法对文件重算**，因此不参与查杀，
仅作为 IOC 存档保留（见 `HASHSIG_*`）。
"""
from __future__ import annotations

import json
import os
import sys
import threading

__all__ = [
    "HUORONG_DATA_DIR", "get_content_sig_engine", "warmup_content_sigs",
    "url_blocklist_match", "lookup_url_category", "get_huorong_stats",
]

# ── 数据目录（随包分发的只读资源；兼容 PyInstaller）──
def _resolve_data_dir() -> str:
    if getattr(sys, "frozen", False):
        candidates = [
            os.path.join(getattr(sys, "_MEIPASS", "") or "", "engine", "huorong_data"),
            os.path.join(os.path.dirname(sys.executable), "engine", "huorong_data"),
            os.path.join(os.path.dirname(sys.executable), "_internal", "engine", "huorong_data"),
        ]
        for c in candidates:
            if c and os.path.isdir(c):
                return c
        return candidates[0]
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "huorong_data")


HUORONG_DATA_DIR = _resolve_data_dir()
CONTENT_SIGS_FILE = os.path.join(HUORONG_DATA_DIR, "content_sigs.txt")
URL_BLOCKLIST_FILE = os.path.join(HUORONG_DATA_DIR, "url_blocklist.txt")
URL_CATEGORIES_FILE = os.path.join(HUORONG_DATA_DIR, "url_categories.json")
DETECTION_NAMES_FILE = os.path.join(HUORONG_DATA_DIR, "detection_names.txt")
HASHSIG_TROJ_FILE = os.path.join(HUORONG_DATA_DIR, "hashsig_troj.csv")
HASHSIG_HWL_FILE = os.path.join(HUORONG_DATA_DIR, "hashsig_hwl.csv")
MANIFEST_FILE = os.path.join(HUORONG_DATA_DIR, "manifest.json")

# matcher.dll 单实例模式数上限约 1.4 万，取 1 万留出余量
_AC_CHUNK = 10000

# 字面量长度 -> 置信度分档（仅当允许自动处置时生效）
TIER_HIGH_LEN = 24
TIER_MED_LEN = 16
TIER_LOW_LEN = 12

_MAX_HITS_RETURNED = 5


def _cfg(name: str, default):
    """从 config 读取开关，读不到则用默认值（保证模块可独立导入）"""
    try:
        import config
        return getattr(config, name, default)
    except Exception:
        return default


def _tier_of(length: int) -> str:
    if length >= TIER_HIGH_LEN:
        return "high"
    if length >= TIER_MED_LEN:
        return "medium"
    return "low"


# ══════════════════════════════════════════════════════════════════
# 内容特征串引擎（Aho-Corasick 分片）
# ══════════════════════════════════════════════════════════════════
class HuorongContentSignatures:
    """火绒内容特征串引擎（懒加载 + 后台预热 + 分片匹配）"""

    CONFIDENCE_SOURCE = "huorong_content"

    def __init__(self, sigs_file: str = CONTENT_SIGS_FILE):
        self._file = sigs_file
        self._literals: list[str] = []
        self._chunks: list = []
        self._lock = threading.Lock()
        self._load_attempted = False
        self._available = os.path.isfile(sigs_file)
        self._error = "" if self._available else "内容特征串数据文件不存在"
        self._native = True
        self.scanned_files = 0
        self.scanned_hits = 0

    # ── 数据文件是否就绪 ──
    @property
    def available(self) -> bool:
        return self._available

    @property
    def error(self) -> str:
        return self._error

    # ── 原生匹配器可用性 ──
    @staticmethod
    def _native_available() -> bool:
        try:
            from engine.aho_native import native_available
            return bool(native_available())
        except Exception:
            return False

    def ensure_loaded(self) -> bool:
        """构建分片 AC。失败不抛异常，仅停用并记录原因。"""
        if self._load_attempted:
            return bool(self._chunks)
        with self._lock:
            if self._load_attempted:
                return bool(self._chunks)
            self._load_attempted = True
            if not self._available:
                return False
            # 纯 Python AC 承载数万模式会卡死，故无原生匹配器时不加载
            if not self._native_available():
                self._native = False
                self._available = False
                self._error = "matcher.dll 不可用，内容特征串已停用（避免纯 Python 匹配卡死）"
                return False
            try:
                from engine.aho_native import NativeAhoCorasick
                with open(self._file, "r", encoding="utf-8", errors="ignore") as f:
                    lits = [ln.rstrip("\n") for ln in f if ln.strip()]
                self._literals = lits
                for start in range(0, len(lits), _AC_CHUNK):
                    ac = NativeAhoCorasick()
                    for j, s in enumerate(lits[start:start + _AC_CHUNK]):
                        ac.add(s.encode("latin-1", errors="ignore"), start + j)
                    ac.build()
                    self._chunks.append(ac)
                return True
            except Exception as exc:
                self._chunks = []
                self._available = False
                self._error = "内容特征串加载失败: %s" % exc
                return False

    def warmup(self):
        """后台预热（供启动时调用，避免首次扫描阻塞）"""
        try:
            self.ensure_loaded()
        except Exception:
            pass

    # ── 匹配 ──
    def scan_content(self, content: bytes, top_k: int = _MAX_HITS_RETURNED) -> list[dict]:
        """扫描内存内容，返回命中的内容特征串（按字面量长度降序）。

        返回 [{literal, length, tier, confidence, source}]
        """
        if not content or not self.ensure_loaded():
            return []
        idx: set[int] = set()
        for ac in self._chunks:
            try:
                idx.update(ac.find(content))
            except Exception:
                continue
        if not idx:
            return []
        self.scanned_files += 1
        self.scanned_hits += len(idx)
        auto = bool(_cfg("HUORONG_CONTENT_AUTO_QUARANTINE", False))
        out = []
        for i in sorted(idx, key=lambda k: -len(self._literals[k]))[:top_k]:
            lit = self._literals[i]
            tier = _tier_of(len(lit))
            out.append({
                "literal": lit,
                "length": len(lit),
                "tier": tier,
                # 默认仅告警：强制 low，由处置层（scheduler/realtime_guard）降级为 alert
                "confidence": tier if auto else "low",
                "source": self.CONFIDENCE_SOURCE,
            })
        return out

    def get_stats(self) -> dict:
        return {
            "available": self._available,
            "native": self._native,
            "literals": len(self._literals),
            "chunks": len(self._chunks),
            "scanned_files": self.scanned_files,
            "scanned_hits": self.scanned_hits,
            "error": self._error,
        }


_engine: HuorongContentSignatures | None = None
_engine_lock = threading.Lock()


def get_content_sig_engine() -> HuorongContentSignatures:
    """全局单例（线程安全懒加载）"""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = HuorongContentSignatures()
    return _engine


def warmup_content_sigs():
    """启动时后台预热（失败静默）"""
    try:
        t = threading.Thread(target=get_content_sig_engine().warmup, daemon=True,
                             name="huorong-warmup")
        t.start()
        return t
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════
# 恶意网址库
# ══════════════════════════════════════════════════════════════════
_url_lock = threading.Lock()
_url_state: dict | None = None


def _load_url_blocklist() -> dict:
    """加载恶意域名黑名单：{hosts:set, bare_domains:set, count:int}"""
    global _url_state
    if _url_state is not None:
        return _url_state
    with _url_lock:
        if _url_state is not None:
            return _url_state
        hosts, bare = set(), set()
        try:
            with open(URL_BLOCKLIST_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    s = ln.strip().lower()
                    if not s or s.startswith("#"):
                        continue
                    hosts.add(s)
                    if s.count(".") == 1:      # 裸注册域名，可按主域匹配子域
                        bare.add(s)
        except Exception:
            pass
        _url_state = {"hosts": hosts, "bare_domains": bare, "count": len(hosts)}
        return _url_state


def url_blocklist_match(host: str, domain: str = "") -> bool:
    """host 是否命中火绒恶意域名黑名单（精确 host，或命中裸注册域名）"""
    if not _cfg("HUORONG_URL_BLOCKLIST_ENABLED", True):
        return False
    if not host:
        return False
    st = _load_url_blocklist()
    host = host.lower()
    if host in st["hosts"]:
        return True
    return bool(domain) and domain.lower() in st["bare_domains"]


def get_url_blocklist_count() -> int:
    return _load_url_blocklist()["count"]


_cat_lock = threading.Lock()
_cat_state: dict | None = None


def lookup_url_category(host: str) -> list[str]:
    """按 host 查询火绒 URL 内容分类（如 gamb/porn/news），仅标注不拦截"""
    global _cat_state
    if not host:
        return []
    with _cat_lock:
        if _cat_state is None:
            _cat_state = {}
            try:
                with open(URL_CATEGORIES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for key, values in (data.get("categories") or {}).items():
                    for v in values:
                        _cat_state.setdefault(v, []).append(key)
            except Exception:
                pass
    return list(_cat_state.get(host.lower(), []))


# ══════════════════════════════════════════════════════════════════
# 统计 / 清单
# ══════════════════════════════════════════════════════════════════
def _count_lines(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for ln in f if ln.strip() and not ln.startswith("#"))
    except Exception:
        return 0


def get_huorong_stats() -> dict:
    """火绒情报库总览（供 API / 健康检查展示）"""
    man = {}
    try:
        with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
            man = json.load(f)
    except Exception:
        pass
    return {
        "data_dir": HUORONG_DATA_DIR,
        "content_sigs": get_content_sig_engine().get_stats(),
        "url_blocklist": {"count": get_url_blocklist_count(),
                          "enabled": bool(_cfg("HUORONG_URL_BLOCKLIST_ENABLED", True))},
        "detection_names": {"total": man.get("detection_names", {}).get("total")
                            or _count_lines(DETECTION_NAMES_FILE)},
        "hashsig": man.get("hashsig", {}),
        "hashsig_usable_for_scan": False,
        "hashsig_note": man.get("hashsig_note", ""),
        "auto_quarantine": bool(_cfg("HUORONG_CONTENT_AUTO_QUARANTINE", False)),
        "generated_at": man.get("generated_at", ""),
        "source": man.get("source", ""),
    }
