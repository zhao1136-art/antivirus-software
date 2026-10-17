#!/usr/bin/env python3
"""汇总误报上报，输出「哪条判定该复核」。

数据来源：backend/engine/data/false_positive_reports/*.json
每条由 POST /api/v1/quarantine/report-false-positive 写入，含隔离当时的上下文
（威胁名、等级、哈希、目录类别、扩展名、是否系统路径、用户备注）。

为什么需要它
------------
误报上报本身没有价值，**汇总出「哪条规则在什么位置误报」才有价值**。
判断一条命中是不是"结构性误报"，看的是**集中度**：

    某规则 12 次误报里 11 次在 System32 / Program Files
        → 它在系统性地下手系统文件，规则的有效鉴别力有问题（该降级或重写）
    某规则 3 次误报全在用户下载目录、扩展名各不相同
        → 更像是"某个正常软件的新版本"，补白名单即可

用法
----
    python collect_fp.py                     # 看汇总（Markdown）
    python collect_fp.py --json              # 机器可读
    python collect_fp.py --min 1             # 只列出现次数 >= N 的结论
    python collect_fp.py -o 误报汇总.md       # 写文件
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict

#: 误报报告目录（与 backend/engine/quarantine.py 的 QUARANTINE_DIR 同级）
_DEFAULT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "backend", "engine", "data", "false_positive_reports")

#: 这些目录里出现误报，说明规则在系统性地咬系统文件 —— 严重
_SYSTEM_DIRS = {"Windows\\System32", "Windows\\SysWOW64", "Windows (其它)"}
_PROGRAM_FILES = {"Program Files"}


def load_reports(report_dir: str) -> list[dict]:
    out: list[dict] = []
    if not os.path.isdir(report_dir):
        return out
    for name in sorted(os.listdir(report_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(report_dir, name)
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            continue
        if isinstance(data, dict) and data.get("schema"):
            data["_file"] = name
            out.append(data)
    return out


def analyze(reports: list[dict]) -> dict:
    by_rule: dict[str, dict] = defaultdict(
        lambda: {"count": 0, "dirs": Counter(), "exts": Counter(),
                 "levels": Counter(), "notes": [], "first": None, "last": None})
    dir_total: Counter = Counter()
    ext_total: Counter = Counter()
    sys_total = 0

    for r in reports:
        q = r.get("quarantine") or {}
        p = r.get("path_context") or {}
        rule = str(q.get("threat_name") or "(无威胁名)")
        d = by_rule[rule]
        d["count"] += 1
        d["dirs"][p.get("dir_category") or "?"] += 1
        d["exts"][p.get("extension") or "(无)"] += 1
        d["levels"][q.get("threat_level") or "?"] += 1
        note = (r.get("user_note") or "").strip()
        if note and len(d["notes"]) < 3:
            d["notes"].append(note[:80])
        ts = r.get("generated_at")
        if ts:
            d["first"] = min(filter(None, [d["first"], ts]))
            d["last"] = max(filter(None, [d["last"], ts]))

        dc = p.get("dir_category") or "?"
        dir_total[dc] += 1
        ext_total[p.get("extension") or "(无)"] += 1
        if p.get("is_system_path") or dc in _SYSTEM_DIRS:
            sys_total += 1

    return {
        "total": len(reports),
        "system_hits": sys_total,
        "by_rule": {k: {
            "count": v["count"],
            "dirs": dict(v["dirs"]),
            "exts": dict(v["exts"]),
            "levels": dict(v["levels"]),
            "notes": v["notes"],
            "first": v["first"],
            "last": v["last"],
        } for k, v in by_rule.items()},
        "by_dir": dict(dir_total),
        "by_ext": dict(ext_total),
    }


def verdict_for(info: dict) -> tuple[str, str]:
    """给这条规则一个处置建议。返回 (等级, 说明)。"""
    n = info["count"]
    dirs = info["dirs"]
    sys_n = sum(v for k, v in dirs.items() if k in _SYSTEM_DIRS)
    pf_n = sum(v for k, v in dirs.items() if k in _PROGRAM_FILES)
    risky = sys_n + pf_n

    if n == 0:
        return "无数据", ""
    ratio = risky / n
    if sys_n and ratio >= 0.5:
        return "结构性问题", (f"{n} 次误报中 {sys_n} 次在系统目录（{ratio:.0%}）"
                          f"—— 规则在系统性咬系统文件，应复核有效鉴别力并降级为仅告警")
    if pf_n and ratio >= 0.5:
        return "需复核", (f"{n} 次误报中 {pf_n} 次在 Program Files（{ratio:.0%}）"
                      f"—— 可能把正常软件判了，建议核对签名豁免")
    if n >= 3:
        return "观察", f"{n} 次误报，分布分散（{len(dirs)} 个目录类别）—— 更像个案，补白名单"
    return "个案", f"{n} 次"


def render_md(result: dict, min_count: int = 1) -> str:
    L: list[str] = []
    L.append("# 误报汇总")
    L.append("")
    L.append(f"- 上报总数：**{result['total']}**")
    if result["total"]:
        pct = result["system_hits"] / result["total"]
        L.append(f"- 其中落在系统目录/系统文件：**{result['system_hits']}**"
                 f"（{pct:.0%}）")
    L.append("")
    if not result["total"]:
        L.append("> 还没有任何误报上报。隔离区里每条记录右侧有「这是误报」按钮。")
        return "\n".join(L)

    L.append("## 按目录类别")
    L.append("")
    L.append("| 目录类别 | 次数 |")
    L.append("|---|---|")
    for k, v in sorted(result["by_dir"].items(), key=lambda x: -x[1]):
        L.append(f"| {k} | {v} |")
    L.append("")

    L.append("## 按扩展名")
    L.append("")
    L.append("| 扩展名 | 次数 |")
    L.append("|---|---|")
    for k, v in sorted(result["by_ext"].items(), key=lambda x: -x[1])[:15]:
        L.append(f"| `{k}` | {v} |")
    L.append("")

    L.append("## 按威胁名（处置建议）")
    L.append("")
    order = {"结构性问题": 0, "需复核": 1, "观察": 2, "个案": 3, "无数据": 4}
    rows = []
    for rule, info in result["by_rule"].items():
        if info["count"] < min_count:
            continue
        level, why = verdict_for(info)
        rows.append((order.get(level, 9), -info["count"], rule, info, level, why))
    rows.sort()
    if not rows:
        L.append(f"> 没有出现次数 >= {min_count} 的规则。")
        return "\n".join(L)

    for _o, _n, rule, info, level, why in rows:
        L.append(f"### `{rule}`　—　{level}")
        L.append("")
        L.append(f"- 误报次数：**{info['count']}**")
        L.append(f"- 目录分布：{info['dirs']}")
        L.append(f"- 扩展名：{info['exts']}")
        L.append(f"- 等级：{info['levels']}")
        if info["first"]:
            L.append(f"- 时间：{info['first']} ~ {info['last']}")
        if info["notes"]:
            L.append(f"- 用户备注：{' / '.join(info['notes'])}")
        if why:
            L.append(f"- **建议：{why}**")
        L.append("")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="汇总误报上报")
    ap.add_argument("--dir", default=_DEFAULT_DIR, help="误报报告目录")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--min", type=int, default=1, help="只列出现次数 >= N")
    ap.add_argument("-o", "--output", default=None, help="写文件")
    args = ap.parse_args(argv)

    reports = load_reports(args.dir)
    result = analyze(reports)

    if args.json:
        text = json.dumps(result, ensure_ascii=False, indent=2)
    else:
        text = render_md(result, args.min)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"汇总 -> {args.output}  ({result['total']} 条上报)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
