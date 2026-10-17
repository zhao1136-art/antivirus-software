#!/usr/bin/env python3
"""组合信号加权评分 —— 只评分，不做处置。

为什么要有它
------------
御天现在的判定是**串联的硬闸门**：YARA 命中 -> 查置信度 -> 查系统文件 -> 查第二引擎。
每条判据都是独立的生死开关，没有「三个弱证据加起来等于一个强证据」的逻辑。
而实测过的两次误报灾难（EXE_in_LNK 88%、ML 48%）根子都是同一个：
**单一信号被当成了唯一判据**。

这个模块把各引擎的信号汇总成一个分数 + 可解释的分解，用于：
  * 诊断：某个文件为什么被报/为什么没报
  * 校准：给定标注语料，看当前权重能不能分开恶意与良性

**它不参与处置。** 不写隔离、不写处置、不改任何 action。这是刻意的：
权重在没有 ROC 数据之前只能算先验，先验不该有搬走用户文件的权力。

每一条权重都写了理由；理由里能引用实测数据的就引用，引用不了的老实说「先验」。

用法
----
    # 单个文件：看分数与分解
    python signal_score.py <文件>

    # 校准：给标注语料，看分数分布与分离度
    python signal_score.py --calibrate --malware <目录> --benign <目录>
"""
from __future__ import annotations

import argparse
import json
import math
import os
import struct
import sys
from collections import Counter

_BACKEND = os.environ.get("YUTIAN_BACKEND") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
if os.path.isdir(_BACKEND):
    sys.path.insert(0, _BACKEND)

import hashlib  # noqa: E402


# ══════════════════════════════════════════════════════════════════
# 权重表
#
# 数值只是**先验**，不是标定值。`--calibrate` 就是用来看它到底行不行的。
# 每一行的理由尽量引用实测数据；引用不了的写「先验」。
# ══════════════════════════════════════════════════════════════════
WEIGHTS = {
    # —— 正面（指向恶意）——
    "db_hit": (
        100,
        "特征库精确命中。哈希库是唯一「确定」的信号，238k 条里命中的是已知样本。"),
    "yara_high": (
        45,
        "YARA 高置信度命中。置信度分级来自有效鉴别力实测（<8 字节的字面量降级为 low），"
        "high 档是条件够长、组合够刁的规则。"),
    "yara_medium": (
        20,
        "YARA 中置信度命中。仍可能撞正常文件（EXE_in_LNK 就是中置信度过高误报）。"),
    "heur_score": (
        0.4,   # 乘子：分数 * 0.4，上限 100
        "启发式是加权规则，实测 0/300 误报（PE 与 generic 两条路径），"
        "所以给正权重；但它是启发式，不该单独定生死，故打折。"),
    "high_entropy": (
        15,
        "存在熵 >7.2 的区段。加壳/加密的常见特征，但正常压缩资源也会高熵 —— 只作辅证。"),
    "rwx_section": (
        25,
        "区段同时可写可执行。正常编译器产物极少这样，JIT 类除外。"),
    "no_signature": (
        10,
        "**内嵌签名与目录签名都没有**（走产品自带的 verify_signature_full："
        "先 WinVerifyTrust 验内嵌，再查 CatRoot 的 .cat）。"
        "国内大量正常软件也没签名，单这一条几乎无区分度，只作辅证。"),
    "signature_tampered": (
        70,
        "**签名存在但文件被改过**（TRUST_E_BAD_DIGEST / status=bad_digest）。"
        "这是很强的恶意信号 —— 有人篡改了一个原本合法的已签名文件，"
        "典型的白加黑手法，或直接改系统文件。"),
    "signature_untrusted": (
        30,
        "签名被显式吊销或不信任（0x800B0111）。可能是已知泄露/被滥用的证书。"),
    "double_ext": (
        15,
        "双扩展名（如 .pdf.exe）。钓鱼投递的经典手法。"),
    "tiny_pe": (
        10,
        "PE 小于 4KB。正常可执行文件极少这么小。"),
    "overlay_ratio": (
        12,
        "覆盖层占文件 >50%。可能是附加载荷，也可能是安装包/自解压。"),

    # —— 反面（指向正常）——
    "signed": (
        -40,
        "有有效数字签名。这是最强的「良性」佐证 —— 但要小心白加黑："
        "签名只证明这个文件没被改，不证明它加载的 jar/dll 是干净的。"),
    "system_path": (
        -30,
        "位于系统目录。2026-10-03 那次 42 个系统文件被搬走，就是规则没考虑这一条。"),
    "known_publisher": (
        -25,
        "签名主体是已知大厂（微软/腾讯/360 等）。同类产品的白加黑恰恰利用这一点，"
        "所以只是减分，不是免除。"),

    # —— 明确零权重（有信号但不采信）——
    "ml_malicious": (
        0,
        "**刻意给 0**。实测：40 个合法 System32 文件里 ML 判 SUSPICIOUS 21 个 + "
        "MALICIOUS 4 个 = 误报 62.5%；扩到 936 个文件两个语料一致 48%。"
        "它已经有处置权被撤销的记录，这里也不给分。"),
    "yara_low": (
        0,
        "**刻意给 0**。低置信度规则（有效鉴别力 <8 字节）已经被闸门零降级为仅告警，"
        "不该在评分里再贡献一次。"),
}

#: 组合升级：单个信号都不致命，凑在一起才是典型恶意形态
COMBOS = [
    (("rwx_section", "high_entropy", "no_signature"), 35,
     "可写可执行 + 高熵 + 无签名 —— 加壳载荷的典型三件套"),
    (("high_entropy", "overlay_ratio"), 20,
     "高熵 + 大覆盖层 —— 可能是「正常程序外壳 + 加密载荷」"),
    (("double_ext", "tiny_pe"), 20,
     "双扩展名 + 极小 PE —— 钓鱼投递的经典组合"),
]

#: 判读区间（只是给人看的标签，不触发任何动作）
BANDS = [
    (100, "极高（已知样本或铁证组合）"),
    (60, "高（多个强信号一致）"),
    (30, "中（有可疑迹象，建议人工看）"),
    (0, "低（信号不足）"),
    (-1 << 30, "倾向正常（有明确良性佐证）"),
]


def band_of(score: float) -> str:
    for lo, label in BANDS:
        if score >= lo:
            return label
    return "?"


# ══════════════════════════════════════════════════════════════════
# PE 结构（只取评分需要的字段）
# ══════════════════════════════════════════════════════════════════
def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    cnt = [0] * 256
    for x in b:
        cnt[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in cnt if c)


def pe_signals(data: bytes) -> dict:
    """返回 {is_pe, max_section_entropy, has_rwx, has_signature, overlay_ratio}"""
    out = {"is_pe": False, "max_section_entropy": 0.0, "has_rwx": False,
           "has_signature": False, "overlay_ratio": 0.0}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return out
    try:
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[lfanew:lfanew + 4] != b"PE\x00\x00":
            return out
        out["is_pe"] = True
        nsec = struct.unpack_from("<H", data, lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", data, lfanew + 20)[0]
        oh = lfanew + 24
        magic = struct.unpack_from("<H", data, oh)[0]
        pe64 = magic == 0x20B
        dd = oh + (112 if pe64 else 96)
        try:
            srva, ssz = struct.unpack_from("<II", data, dd + 4 * 8)
            out["has_signature"] = bool(srva and ssz >= 8)
        except Exception:
            pass
        sh = oh + opt_size
        max_end = 0
        for i in range(nsec):
            o = sh + i * 40
            if o + 40 > len(data):
                break
            rawsize = struct.unpack_from("<I", data, o + 16)[0]
            rawptr = struct.unpack_from("<I", data, o + 20)[0]
            chars = struct.unpack_from("<I", data, o + 36)[0]
            if (chars & 0x80000000) and (chars & 0x20000000):
                out["has_rwx"] = True
            body = data[rawptr:rawptr + rawsize] if rawptr + rawsize <= len(data) else b""
            if body:
                out["max_section_entropy"] = max(out["max_section_entropy"],
                                                 _entropy(body))
            max_end = max(max_end, rawptr + rawsize)
        if max_end and max_end < len(data):
            out["overlay_ratio"] = (len(data) - max_end) / len(data)
    except Exception:
        pass
    return out


# ══════════════════════════════════════════════════════════════════
# 信号采集
# ══════════════════════════════════════════════════════════════════
class Engines:
    """惰性加载后端引擎；后端不在就只用内置信号。"""

    def __init__(self) -> None:
        self.yara = None
        self.heur = None
        self.sig = None
        self.notes: list[str] = []
        try:
            from engine.yara_scanner import YaraScanner
            self.yara = YaraScanner(os.path.join(_BACKEND, "engine", "yara_rules"))
            self.notes.append(f"YARA {len(self.yara.rules)} 条")
        except Exception as exc:
            self.notes.append(f"YARA 不可用: {type(exc).__name__}")
        try:
            from engine.heuristic_engine import get_heuristic_engine
            self.heur = get_heuristic_engine()
            self.notes.append("启发式 ok")
        except Exception as exc:
            self.notes.append(f"启发式 不可用: {type(exc).__name__}")
        try:
            from engine.signature_manager import get_signature_manager
            self.sig = get_signature_manager()
            self.notes.append(f"特征库 {self.sig.get_stats()['total_signatures']:,} 条")
        except Exception as exc:
            self.notes.append(f"特征库 不可用: {type(exc).__name__}")


def collect(path: str, engines: Engines) -> dict:
    """采集一个文件的全部信号。返回原始信号（未加权）。"""
    with open(path, "rb") as fh:
        data = fh.read()
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    sig = {"size": len(data), "is_pe": False}

    pe = pe_signals(data)
    sig["is_pe"] = pe["is_pe"]
    sig["high_entropy"] = pe["max_section_entropy"] > 7.2
    sig["rwx_section"] = pe["has_rwx"]

    # 签名：**不自己解析 PE 安全目录**。
    # 大量系统文件是**目录签名**（.cat），PE 里的安全目录是空的 ——
    # 实测 notepad.exe / cmd.exe / winver.exe 经 Windows 权威接口全部 Valid 签名
    # （CN=Microsoft Windows），但它们的安全目录都是 0x0/0。
    # 自己解析会把它们全误判成"无签名"。
    # 正确做法是复用 engine.threat_decision.verify_signature_full：
    # 内嵌 WinVerifyTrust -> CatRoot 目录签名 -> 分类结论。
    # （heuristic_engine.py 里也留了同样的规矩：不自己写签名校验。）
    sig["signed"] = False
    sig["no_signature"] = False
    sig["signature_tampered"] = False
    sig["signature_untrusted"] = False
    sig["signature_status"] = "unknown"
    sig["has_embedded_signature"] = pe["has_signature"]   # 仅作信息，不参与评分
    try:
        from engine.threat_decision import verify_signature_full
        full = verify_signature_full(path)
        st = full.get("status") or "error"
        sig["signature_status"] = st
        sig["signature_detail"] = (full.get("detail") or "")[:200]
        sig["signature_method"] = full.get("method")
        if st in ("embedded", "catalog"):
            sig["signed"] = True
        elif st == "bad_digest":
            sig["signature_tampered"] = True
        elif st == "untrusted":
            sig["signature_untrusted"] = True
        elif st == "unsigned":
            sig["no_signature"] = True
        # status == "error"：检查本身失败 —— 未知不等于无签名，不给任何权重
    except Exception as exc:
        sig["signature_status"] = f"unavailable:{type(exc).__name__}"
    sig["overlay_ratio"] = pe["overlay_ratio"] > 0.5
    sig["tiny_pe"] = pe["is_pe"] and len(data) < 4096
    # 双扩展名：形如 xxx.pdf.exe / xxx.doc.js
    parts = name.lower().split(".")
    sig["double_ext"] = (len(parts) >= 3 and
                         parts[-1] in ("exe", "scr", "com", "js", "vbs", "ps1",
                                       "bat", "cmd", "lnk", "hta") and
                         parts[-2] not in ("", "tar", "gz"))

    try:
        from engine.threat_decision import is_system_path
        sig["system_path"] = bool(is_system_path(path))
    except Exception:
        sig["system_path"] = False

    # 特征库
    sig["db_hit"] = False
    if engines.sig:
        try:
            r = engines.sig.lookup(md5=md5, sha256=sha256)
            sig["db_hit"] = bool(r)
            if r:
                sig["db_name"] = r.get("threat_name")
        except Exception:
            pass

    # YARA
    sig["yara_high"] = sig["yara_medium"] = sig["yara_low"] = False
    sig["yara_rules"] = []
    if engines.yara:
        try:
            hits = engines.yara.scan_content(data, name)
            for h in hits:
                sig["yara_rules"].append(h["rule"])
                conf = (h.get("confidence") or "medium").lower()
                if conf == "high":
                    sig["yara_high"] = True
                elif conf == "low":
                    sig["yara_low"] = True
                else:
                    sig["yara_medium"] = True
        except Exception:
            pass

    # 启发式
    sig["heur_score"] = 0
    if engines.heur:
        try:
            r = (engines.heur.analyze_generic(data[:65536], name, md5, sha256,
                                              len(data))
                 or engines.heur.analyze_pe(data[:64], name, md5, sha256,
                                            len(data)))
            if isinstance(r, dict):
                sig["heur_score"] = int(r.get("heuristic_score") or 0)
                sig["heur_reasons"] = r.get("reasons") or []
        except Exception:
            pass

    sig["ml_malicious"] = False   # 权重 0；这里也不采集，避免给人一种"它有用"的错觉
    return sig


# ══════════════════════════════════════════════════════════════════
# 评分
# ══════════════════════════════════════════════════════════════════
def score(sig: dict) -> dict:
    """返回 {score, breakdown:[(signal, delta, why)], combos:[...]}"""
    total = 0.0
    breakdown: list[tuple[str, float, str]] = []

    for key, (w, why) in WEIGHTS.items():
        if key == "heur_score":
            hs = sig.get("heur_score") or 0
            if hs:
                delta = min(hs * w, 100 * w)
                total += delta
                breakdown.append((f"heur_score={hs}", delta, why))
            continue
        if not sig.get(key):
            continue
        total += w
        breakdown.append((key, w, why))

    combos: list[tuple[str, float, str]] = []
    for keys, bonus, why in COMBOS:
        if all(sig.get(k) for k in keys):
            total += bonus
            combos.append(("+".join(keys), bonus, why))

    return {"score": total, "band": band_of(total),
            "breakdown": breakdown, "combos": combos}


# ══════════════════════════════════════════════════════════════════
# 校准
# ══════════════════════════════════════════════════════════════════
def _auc(mal: list[float], ben: list[float]) -> float:
    """Mann-Whitney AUC。0.5 = 完全分不开，1.0 = 完美分开。"""
    if not mal or not ben:
        return float("nan")
    wins = 0.0
    for m in mal:
        for b in ben:
            if m > b:
                wins += 1
            elif m == b:
                wins += 0.5
    return wins / (len(mal) * len(ben))


def calibrate(mal_dir: str, ben_dir: str, limit: int = 200) -> dict:
    eng = Engines()
    mal_scores: list[float] = []
    ben_scores: list[float] = []

    def walk(d, acc):
        n = 0
        for dp, _dn, fns in os.walk(d):
            for f in sorted(fns):
                if n >= limit:
                    return
                p = os.path.join(dp, f)
                try:
                    if os.path.getsize(p) == 0:
                        continue
                    r = score(collect(p, eng))
                    acc.append(r["score"])
                    n += 1
                except Exception:
                    continue

    walk(mal_dir, mal_scores)
    walk(ben_dir, ben_scores)

    def hist(v):
        c = Counter()
        for s in v:
            c[int(s // 20) * 20] += 1
        return {str(k): c[k] for k in sorted(c)}

    return {
        "engines": eng.notes,
        "malware": {"n": len(mal_scores),
                    "min": min(mal_scores) if mal_scores else None,
                    "median": sorted(mal_scores)[len(mal_scores) // 2] if mal_scores else None,
                    "max": max(mal_scores) if mal_scores else None,
                    "hist": hist(mal_scores)},
        "benign": {"n": len(ben_scores),
                   "min": min(ben_scores) if ben_scores else None,
                   "median": sorted(ben_scores)[len(ben_scores) // 2] if ben_scores else None,
                   "max": max(ben_scores) if ben_scores else None,
                   "hist": hist(ben_scores)},
        "auc": _auc(mal_scores, ben_scores),
    }


def render_calibration(r: dict) -> str:
    L = ["# 评分权重校准", ""]
    L.append(f"- 引擎：{' / '.join(r['engines'])}")
    L.append("")
    L.append("| | 样本数 | 最小 | 中位 | 最大 |")
    L.append("|---|---|---|---|---|")
    for k in ("malware", "benign"):
        d = r[k]
        L.append(f"| {k} | {d['n']} | {d['min']} | {d['median']} | {d['max']} |")
    L.append("")
    auc = r["auc"]
    L.append(f"**AUC = {auc:.4f}**" if auc == auc else "**AUC 无法计算**（某一侧样本为空）")
    L.append("")
    if auc == auc:
        if auc >= 0.95:
            L.append("> 分得很开。但这只能说明权重能分开**这批**样本，"
                     "不代表对未知样本有效 —— 样本来源单一会有偏。")
        elif auc >= 0.8:
            L.append("> 尚可分开，仍有重叠区。重叠区的样本才是真正需要人工看的。")
        else:
            L.append("> **分不开**。当前权重不该用于任何自动判定 —— "
                     "这也正是它现在只评分、不处置的原因。")
    L.append("")
    L.append("## 分数分布")
    L.append("")
    L.append("```")
    L.append("恶意: " + json.dumps(r["malware"]["hist"], ensure_ascii=False))
    L.append("良性: " + json.dumps(r["benign"]["hist"], ensure_ascii=False))
    L.append("```")
    return "\n".join(L)


# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="组合信号加权评分（只评分，不做处置）")
    ap.add_argument("files", nargs="*", help="要评分的文件")
    ap.add_argument("--calibrate", action="store_true", help="校准模式")
    ap.add_argument("--malware", help="恶意样本目录")
    ap.add_argument("--benign", help="良性样本目录")
    ap.add_argument("--limit", type=int, default=200, help="每侧最多取多少个")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.calibrate:
        if not (args.malware and args.benign):
            print("校准模式需要 --malware 与 --benign", file=sys.stderr)
            return 2
        r = calibrate(args.malware, args.benign, args.limit)
        print(json.dumps(r, ensure_ascii=False, indent=2) if args.json
              else render_calibration(r))
        return 0

    if not args.files:
        ap.print_help()
        return 2

    eng = Engines()
    out = []
    for p in args.files:
        try:
            sig = collect(p, eng)
            r = score(sig)
        except Exception as exc:
            out.append({"file": p, "error": f"{type(exc).__name__}: {exc}"})
            continue
        out.append({"file": p, "signals": {k: v for k, v in sig.items()
                                           if not isinstance(v, list) or v},
                    "score": r["score"], "band": r["band"],
                    "breakdown": r["breakdown"], "combos": r["combos"]})

    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0

    for o in out:
        print("=" * 70)
        print(o["file"])
        if o.get("error"):
            print("  错误:", o["error"])
            continue
        print(f"  分数 {o['score']:.1f}  ->  {o['band']}")
        for name, delta, why in o["breakdown"]:
            print(f"    {delta:+7.1f}  {name}")
            print(f"             {why}")
        for name, bonus, why in o["combos"]:
            print(f"    {bonus:+7.1f}  [组合] {name}")
            print(f"             {why}")
        print("  说明：本分数不参与任何处置，仅供参考与校准。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
