"""
统一威胁情报管理模块
加载 Maltrail 恶意软件规则库，提供 IOC 查询能力
兼容 Python 3.10+
"""

from pathlib import Path


# ── 数据目录定位（基于本文件所在位置） ──────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_MALTRAIL_DIR = (
    _PROJECT_ROOT
    / "maltrail-master"
    / "maltrail-master"
    / "trails"
    / "static"
    / "malware"
)


# ══════════════════════════════════════════════════════════════════
#  ThreatIntelEngine  —— 核心类
# ══════════════════════════════════════════════════════════════════

class ThreatIntelEngine:
    """统一威胁情报查询引擎

    数据量中等时使用 dict + set 即够用；若未来扩展可替换底层存储。
    """

    def __init__(self):
        # IOC → 所属家族集合  例如 {"evil.com": {"emotet", "cobalt"}}
        self._ioc_to_families: dict[str, set[str]] = {}

        # 家族 → IOC 列表（用于 search_family 时的反向查询）
        self._family_to_iocs: dict[str, list[str]] = {}

        # 加载状态
        self._loaded = False
        self._family_count = 0
        self._ioc_total_count = 0

    # ── 数据加载 ──────────────────────────────────────────────

    def load(self, force: bool = False):
        """
        加载 maltrail/static/malware/ 下所有 .txt 规则文件
        :param force: 为 True 时强制重新加载
        """
        if self._loaded and not force:
            return

        self._ioc_to_families.clear()
        self._family_to_iocs.clear()
        self._loaded = False
        self._family_count = 0
        self._ioc_total_count = 0

        if not _MALTRAIL_DIR.is_dir():
            self._loaded = True
            return

        for filepath in _MALTRAIL_DIR.glob("*.txt"):
            family = filepath.stem  # 文件名（不含扩展名）就是家族名
            iocs = self._parse_txt_file(filepath)
            if not iocs:
                continue

            self._family_count += 1
            self._family_to_iocs[family] = iocs

            for ioc in iocs:
                self._ioc_to_families.setdefault(ioc, set()).add(family)

        # 统计去重后的 IOC 总数
        self._ioc_total_count = len(self._ioc_to_families)
        self._loaded = True

    @staticmethod
    def _parse_txt_file(filepath: Path) -> list[str]:
        """
        解析单个规则文件，返回 IOC 列表
        规则：
          - 以 # 开头的行为注释，跳过
          - 空行跳过
          - 其余行为 IOC（域名 / IP:端口 / URL）
        """
        iocs: list[str] = []
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                iocs.append(stripped)
        return iocs

    # ── 查询接口 ──────────────────────────────────────────────

    def lookup_ioc(self, value: str) -> list[str]:
        """
        查询某个 IOC 属于哪些恶意软件家族
        :param value: IOC 字符串（域名、IP:端口 或 URL）
        :return: 所属家族名称列表（可能为空）
        """
        value = value.strip()
        if not value:
            return []

        if not self._loaded:
            self.load()

        families = self._ioc_to_families.get(value)
        if families is None:
            return []
        return sorted(families)

    def search_family(self, name: str) -> list[str]:
        """
        搜索包含关键词的恶意软件家族
        :param name: 搜索关键词（大小写不敏感）
        :return: 匹配的家族名称列表
        """
        name_lower = name.strip().lower()
        if not name_lower:
            return []

        if not self._loaded:
            self.load()

        results: list[str] = []
        for family in self._family_to_iocs:
            if name_lower in family.lower():
                results.append(family)
        return sorted(results)

    def get_family_iocs(self, family: str) -> list[str]:
        """
        获取指定家族的完整 IOC 列表
        :param family: 家族名称（精确匹配）
        :return: IOC 列表（可能为空）
        """
        if not self._loaded:
            self.load()
        return self._family_to_iocs.get(family, []).copy()

    # ── 统计接口 ──────────────────────────────────────────────

    def get_stats(self) -> dict:
        """返回当前加载数据的统计信息"""
        if not self._loaded:
            self.load()

        # 按家族 IOC 数量排序，取 Top 10
        top_families = sorted(
            self._family_to_iocs.items(),
            key=lambda kv: len(kv[1]),
            reverse=True,
        )[:10]
        top_list = [{"family": f, "ioc_count": len(iocs)} for f, iocs in top_families]

        return {
            "family_count": self._family_count,
            "ioc_total_count": self._ioc_total_count,
            "top_families": top_list,
        }

    def reload(self):
        """强制重新加载所有数据"""
        self.load(force=True)


# ══════════════════════════════════════════════════════════════════
#  模块级单例（可选）
# ══════════════════════════════════════════════════════════════════

_engine: ThreatIntelEngine | None = None


def get_engine() -> ThreatIntelEngine:
    """获取模块级 ThreatIntelEngine 单例"""
    global _engine
    if _engine is None:
        _engine = ThreatIntelEngine()
        _engine.load()
    return _engine
