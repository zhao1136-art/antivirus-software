"""
规则质量分级 —— 按字面量特征给每条 YARA 规则算置信度

为什么需要它
------------
2026-10-03 拿 585 个**确定合法**的系统文件（System32 / SysWOW64 / PowerShell
模块）去扫这套规则集，实测结果：

    EXE_in_LNK              命中 514 / 585 = 88%
    Archive_in_LNK          命中 493 / 585 = 84%
    Download_in_LNK         命中 110
    PS_in_LNK                命中 41
    AndroRAT_Android_Trojan  命中  9 个 Windows 系统 DLL（这是**安卓**木马规则）
    ── 8 MB 纯随机数据也能命中 WinRAR_ADS_Traversal / AndroRAT_Version_Identity

而 1153 个字面量里有 **51 个 <=4 字节**（`js` / `exe` / `ftp` / `.7z` / `vbs`）。
这些串在任何正常文件里都会出现，**没有鉴别力**。

根本问题不是"规则写得不够准"，而是**没有「什么时候不该报」这一层**：
YARA 说你是什么，你就是什么，然后直接自动隔离。

分级口径（保守 —— 宁可漏报，不可滥杀）
--------------------------------------
    high    最长字面量 >= 8 且 字面量数 >= 2，或 最长字面量 >= 12
    medium  最长字面量 >= 6
    low     最长字面量 <= 5
    weak    所有字面量都 <= 4（单独标注，噪声的主要来源）

`low` / `weak` 在处置层被降级为**仅告警** —— 不弹窗、不隔离、只记录。
"""
from __future__ import annotations

__all__ = ["analyze_literals", "TIERS", "LOW", "MEDIUM", "HIGH", "WEAK"]

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
WEAK = "weak"          # 仅作为低置信度的标记，不是独立档位
TIERS = (HIGH, MEDIUM, LOW)

WEAK_MAX_LEN = 4       # 字面量长到这个数以下就没有鉴别力
LOW_MAX_LEN = 5
MED_MAX_LEN = 7
HIGH_MIN_LEN = 8
STRONG_LEN = 12


def analyze_literals(literals, condition_type: str = "any", condition_n: int = 1) -> dict:
    """按字面量特征给一条规则打分。

    **关键**：有效鉴别力取决于**条件类型**，不是最长字面量。

    第一版只看最长字面量，结果 8 条真正在误报的规则全被判成 high
    （EXE_in_LNK 在 400 个 System32 文件上命中 400 次，却因为它内部有一个
    >=12 字节的串而被认为"足够特异"）。这些规则的条件是 `any of them` ——
    **只要最短那个字面量命中就成立**，所以鉴别力等于**最短**字面量。

        any     有效鉴别力 = 最短字面量
        all     有效鉴别力 = 最长字面量（必须全部命中才成立）
        N of    有效鉴别力 = 升序第 N 短（命中任意 N 个即可）
        custom  拿不准，按 any 保守处理

    literals: 可迭代的 bytes/str
    返回 {tier, score, max_len, min_len, effective_len, count, avg_len,
          weak_count, reason}
    """
    lens = []
    for v in literals or ():
        if v is None:
            continue
        try:
            n = len(v)
        except TypeError:
            continue
        if n > 0:
            lens.append(n)

    if not lens:
        # 没有字面量的规则（纯 condition / filesize / 仅用 pe.* 模块之类）：
        # 没有任何可用于判断"这条规则有多具体"的证据。
        # ⚠️ 原先按 MEDIUM(0.5) 处理，导致这类最空洞的规则反而能通过处置层
        # 的置信度闸门去搬用户文件 —— 方向反了。没有字面量 => 不可信 => LOW，
        # 处置层据此降级为仅告警。这与文件头"宁可漏报，不可滥杀"的口径一致。
        return {"tier": LOW, "score": 0.2, "max_len": 0, "min_len": 0,
                "effective_len": 0, "count": 0, "avg_len": 0.0, "weak_count": 0,
                "reason": "无字面量，无鉴别力证据 → 仅告警"}

    lens.sort()
    asc = lens[:]
    desc = list(reversed(lens))
    max_len = desc[0]
    min_len = asc[0]
    count = len(lens)
    avg_len = sum(lens) / count
    weak_count = sum(1 for n in lens if n <= WEAK_MAX_LEN)

    ct = (condition_type or "any").lower()
    if ct == "all":
        eff = max_len
        eff_src = "all of them -> 最短的那个也必须命中，取最长字面量"
    elif ct in ("n", "n_of"):
        k = max(1, min(int(condition_n or 1), count))
        eff = asc[k - 1]
        eff_src = "%d of them -> 取升序第 %d 短" % (k, k)
    else:                      # any / custom
        eff = min_len
        eff_src = "%s -> 任一字面量命中即可，取最短" % (ct if ct in ("any", "custom") else "any")

    # ── 按"有效鉴别力"定档 ──
    if eff >= STRONG_LEN:
        tier, reason = HIGH, "有效鉴别力 %d 字节（%s）" % (eff, eff_src)
    elif eff >= HIGH_MIN_LEN:
        tier, reason = MEDIUM, "有效鉴别力 %d 字节（%s）" % (eff, eff_src)
    else:
        # 8 字节以下一律降级。实测依据：EXE_in_LNK 的有效鉴别力是 6 字节，
        # 在 400 个合法 System32 文件上命中 400 次（100%）——
        # 6 字节的门槛仍然太松。宁可漏报，不可滥杀。
        tier = LOW
        if weak_count:
            reason = "**有效鉴别力仅 %d 字节**（%s）；%d/%d 个字面量 <= %d 字节，没有鉴别力" % (
                eff, eff_src, weak_count, count, WEAK_MAX_LEN)
        else:
            reason = "有效鉴别力仅 %d 字节（%s）" % (eff, eff_src)

    score = min(1.0, max(0.0, (eff - 3) / 9.0))
    if tier == HIGH:
        score = max(score, 0.7)
    elif tier == LOW:
        score = min(score, 0.3)

    return {"tier": tier, "score": round(score, 3), "max_len": max_len,
            "min_len": min_len, "effective_len": eff, "count": count,
            "avg_len": round(avg_len, 1), "weak_count": weak_count,
            "reason": reason}


def confidence_of_hit(quality: dict) -> str:
    """处置层用的置信度：low 与 weak 都归为 low。"""
    t = (quality or {}).get("tier", MEDIUM)
    return LOW if t in (LOW, WEAK) else t
