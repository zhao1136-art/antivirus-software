#!/usr/bin/env python3
"""从 ETW 原生层代码生成「覆盖地图」文档。

不手抄规则归属 —— 直接解析 etw_rules.cpp 的 analyze_* 函数边界，
把每个函数体内出现的全大写规则名归到对应 provider 名下。
数据（事件 ID 白名单、限流值、缓冲容量）也从源码里读，避免文档和代码脱节。

用法：python gen_etw_coverage.py [-o 输出路径]
"""
from __future__ import annotations

import argparse
import os
import re
import sys

NG = r"H:\Caelire\backend\engine\native_guard"
RULES_CPP = os.path.join(NG, "etw_rules.cpp")
GUARD_CPP = os.path.join(NG, "etw_guard.cpp")
GUARD_H = os.path.join(NG, "etw_guard.h")

OUT_DEFAULT = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "docs", "etw-coverage.md")

#: analyze_* 函数 -> provider（etw_guard.cpp 的 case 分派是权威来源）
ANALYZER_TO_PROVIDER = {
    "analyze_ti": "Threat-Intelligence",
    "analyze_kproc": "Kernel-Process",
    "analyze_dns": "DNS-Client",
    "analyze_powershell": "PowerShell",
    "analyze_wmi": "WMI-Activity",
    "analyze_dotnet": "DotNETRuntime",
    "analyze_sysmon": "Sysmon",
    "analyze_kfile": "Kernel-File",
    "analyze_kreg": "Kernel-Registry",
}

#: 每个 provider「理论上能看见什么」—— 人写的，基于该 provider 的语义
PROVIDER_SEMANTICS = {
    "Threat-Intelligence": ("进程内存读 / 远程线程 / APC 注入 / 句柄篡改",
                            "只对**签名**杀软开放；未签名构建该 provider 启用会失败"),
    "Kernel-Process": ("进程与线程的创建/终止（含父 PID、命令行）",
                       "只看创建那一刻，看不到进程之后做了什么"),
    "Kernel-File": ("文件创建/重命名（不含写入内容、不含删除）",
                    "**只订阅了 12/30/31 三个 ID**，写入与删除事件没订阅"),
    "Kernel-Registry": ("注册表创建/打开/设值/删除",
                        "只订阅 1/2/5/22，其余键操作看不到"),
    "DNS-Client": ("DNS 查询与响应（域名）", "看不到非 DNS 的 C2（直连 IP、DoH）"),
    "PowerShell": ("脚本块日志（4104）/ 执行（4103）/ 引擎（800）",
                   "只在 PowerShell 引擎启用脚本块日志时才有内容"),
    "WMI-Activity": ("持久化三件套：消费者 / 过滤器 / 绑定（11/22/23）",
                     "**不含 T1047（WMI 创建进程）** —— 那是进程链侧的事"),
    "DotNETRuntime": (".NET 运行时事件（全量保留）", "只覆盖托管程序"),
    "Sysmon": ("进程创建 / 网络 / 镜像加载 / 文件创建（1/3/7/11）",
               "**依赖用户自装 Sysmon**，没装则整个 provider 空转"),
}


def read_text(p: str) -> str:
    with open(p, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def extract_rules(src: str) -> dict[str, list[str]]:
    """按 analyze_* 函数边界切分，收集函数体内的全大写规则名。"""
    # 找所有函数定义起始位置
    starts = [(m.start(), m.group(1))
              for m in re.finditer(r"bool\s+(analyze_[a-z_]+)\s*\(", src)]
    if not starts:
        return {}
    out: dict[str, list[str]] = {}
    for i, (pos, name) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(src)
        body = src[pos:end]
        # 规则名：字符串字面量里的全大写+下划线，且长度够（排除 "true"/"ALL" 这类）
        names = set()
        for m in re.finditer(r'"([A-Z][A-Z0-9_]{5,})"', body):
            v = m.group(1)
            if v in ("UNKNOWN", "FALSE", "TRUE"):
                continue
            names.add(v)
        out[name] = sorted(names)
    return out


def extract_high_value(src: str) -> list[tuple[str, list[int]]]:
    """读 HIGH_VALUE_EVENTS 表：provider -> 事件 ID 列表。"""
    prov_order = re.findall(r"PROV_([A-Z]+)", src)
    out: list[tuple[str, list[int]]] = []
    for m in re.finditer(r"\{\s*PROV_([A-Z]+)\s*,\s*\{([^}]*)\}\s*,\s*(\d+)\s*\}", src):
        prov, ids, cnt = m.group(1), m.group(2), int(m.group(3))
        nums = [int(x) for x in re.findall(r"\d+", ids)]
        nums = nums[:cnt] if cnt else []
        out.append((prov, nums))
    return out


def extract_limits(hsrc: str) -> dict[str, int]:
    out = {}
    for m in re.finditer(r"#define\s+(RATE_LIMIT_[A-Z]+)\s+(\d+)", hsrc):
        out[m.group(1)] = int(m.group(2))
    return out


def extract_define(src: str, name: str) -> int | None:
    m = re.search(rf"#define\s+{name}\s+(\d+)", src)
    return int(m.group(1)) if m else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", default=OUT_DEFAULT)
    args = ap.parse_args(argv)

    rules_src = read_text(RULES_CPP)
    guard_cpp = read_text(GUARD_CPP)
    guard_h = read_text(GUARD_H)

    rules_by_fn = extract_rules(rules_src)
    hv = extract_high_value(guard_cpp)
    limits = extract_limits(guard_h)
    buf = extract_define(guard_cpp, "ETW_MAX_EVENTS")

    prov_ids = {f"PROV_{name.replace('-', '').upper()}": ids for name, ids in hv}
    # PROV 名到显示名
    name_map = {
        "PROV_TI": "Threat-Intelligence", "PROV_KPROC": "Kernel-Process",
        "PROV_DNS": "DNS-Client", "PROV_POWERSHELL": "PowerShell",
        "PROV_WMI": "WMI-Activity", "PROV_DOTNET": "DotNETRuntime",
        "PROV_SYSMON": "Sysmon", "PROV_KFILE": "Kernel-File",
        "PROV_KREG": "Kernel-Registry",
    }
    ids_by_provider: dict[str, list[int]] = {}
    for k, ids in prov_ids.items():
        if k in name_map:
            ids_by_provider[name_map[k]] = ids

    L: list[str] = []
    L.append("# ETW 实时防护 · 覆盖地图")
    L.append("")
    L.append("> 本文由 `tools/gen_etw_coverage.py` 从原生层源码生成，"
             "数据（规则归属、事件 ID、限流值）全部来自代码，不是手抄。")
    L.append("> 改完 `etw_rules.cpp` / `etw_guard.cpp` 后重跑本脚本即可同步。")
    L.append("")
    L.append("## 一、能看见什么")
    L.append("")
    L.append("| Provider | 语义上能看见 | 事件 ID | 规则数 |")
    L.append("|---|---|---|---|")
    total_rules = 0
    for fn, prov in ANALYZER_TO_PROVIDER.items():
        rules = rules_by_fn.get(fn, [])
        total_rules += len(rules)
        sem, _gap = PROVIDER_SEMANTICS.get(prov, ("?", "?"))
        ids = ids_by_provider.get(prov)
        ids_txt = ", ".join(str(i) for i in ids) if ids else "全量"
        L.append(f"| **{prov}** | {sem} | `{ids_txt}` | {len(rules)} |")
    L.append("")
    L.append(f"合计 **{total_rules}** 条 ETW 规则。")
    L.append("")

    L.append("## 二、规则明细（按 Provider）")
    L.append("")
    for fn, prov in ANALYZER_TO_PROVIDER.items():
        rules = rules_by_fn.get(fn, [])
        if not rules:
            continue
        L.append(f"### {prov}（{len(rules)} 条）")
        L.append("")
        L.append("```")
        for i in range(0, len(rules), 4):
            L.append("  ".join(f"{r:30s}" for r in rules[i:i + 4]).rstrip())
        L.append("```")
        L.append("")

    L.append("## 三、会在什么条件下漏掉（重点）")
    L.append("")
    L.append("这一节是这份文档存在的理由 —— 上面写的是能力，这里写的是**边界**。")
    L.append("")
    L.append("### 1. 限流：超过就丢，不重试")
    L.append("")
    L.append("| Provider | 上限 |")
    L.append("|---|---|")
    for prov, key in (("Kernel-File", "RATE_LIMIT_KFILE"),
                      ("Kernel-Process", "RATE_LIMIT_KPROC"),
                      ("DNS-Client", "RATE_LIMIT_DNS"),
                      ("其余 6 个", "RATE_LIMIT_DEFAULT")):
        if key in limits:
            L.append(f"| {prov} | **{limits[key]} 事件/秒** |")
    L.append("")
    L.append("**后果**：解压一个含上千文件的压缩包、批量编译、批量下载 —— "
             "文件事件瞬间打到几百上千/秒，**超过 120/s 的部分全丢**，"
             "丢弃计数累加到 `g_totalDropped`。")
    L.append("")
    L.append("### 2. 命中队列只有 " + (str(buf) if buf else "?") + " 个槽位")
    L.append("")
    L.append("环形缓冲满了走背压丢弃，计数累加到 `g_totalBackpressure`。"
             "**攻击者可以用大量无关事件把队列挤爆**，让自己的恶意事件被背压丢掉。")
    L.append("")
    L.append("### 3. 限流是无差别的 —— 真实命中也会被丢")
    L.append("")
    L.append("`handle_user_event()` 里的顺序是：先跑分析器得出 `hit`，"
             "**再**过滤、**再**限流：")
    L.append("")
    L.append("```cpp")
    L.append("switch (prov) { case PROV_SYSMON: hit = analyze_sysmon(...); ... }  // 先判定")
    L.append("bool highValue = (!hit && etw_is_high_value_event(prov, ev.eventId));")
    L.append("if (!hit && !highValue) return;")
    L.append("if (!etw_rate_check(prov)) return;   // ← 命中事件同样过这道闸")
    L.append("```")
    L.append("")
    L.append("**后果**：某个 provider 一旦打到限流上限，"
             "**连已经判定为命中的事件也会被丢掉**，而且不重试、不落盘。"
             "也就是说「事件洪峰」不只是延迟，而是**直接丢检测结果**。")
    L.append("")
    L.append("这是当前最容易出事的一处：攻击者只要在同 provider 上制造"
             "足够多的无关事件（比如大量文件创建、进程创建），"
             "就能把自己的恶意事件挤到限流之外。")
    L.append("")
    L.append("### 4. 事件 ID 白名单只影响「保留」，不影响「检测」")
    L.append("")
    L.append("`HIGH_VALUE_EVENTS` 容易被误解成「只订阅这些 ID」。实际读代码："
             "分析器是**按 provider 无条件调用**的（`switch (prov)` 不看事件 ID），"
             "白名单只决定「**没命中规则时**这条事件要不要留着做进程链分析」。")
    L.append("")
    L.append("所以白名单里没列出的事件 ID，只要 provider 有发出，规则照样能被触发。"
             "**代价是**：没命中又不在白名单里的事件被直接丢弃（`return`），"
             "进程链/时间线分析因此缺料。")
    L.append("")
    L.append("各 provider 的保留范围：")
    L.append("")
    for fn, prov in ANALYZER_TO_PROVIDER.items():
        gap = PROVIDER_SEMANTICS.get(prov, ("", ""))[1]
        if gap:
            L.append(f"- **{prov}**：{gap}")
    L.append("")
    L.append("### 5. TI 层在未签名构建上是空的")
    L.append("")
    L.append("`Microsoft-Windows-Threat-Intelligence` **只对持有杀毒签名的产品开放**。"
             "未签名 / 自签名的构建里该 provider 启用失败，"
             "`analyze_ti` 的规则（进程注入、远程线程、APC、内存读写）**一条都不会触发**。")
    L.append("")
    L.append("好在这是**可观测**的：状态输出里每个 provider 都有 `enable_ok` 字段")
    L.append("（`etw_guard.cpp` 的 provider 状态 JSON）。**上线前必须查这个字段**，"
             "不能假设 TI 层在工作。")
    L.append("")
    L.append("### 6. 需要管理员权限")
    L.append("")
    L.append("`StartTraceW` + 内核 provider 都需要管理员。"
             "非管理员运行时 ETW 整体不可用，只剩用户态的文件系统监控。")
    L.append("")
    L.append("### 7. Sysmon 是外部依赖")
    L.append("")
    L.append("`Sysmon` provider 只有在用户自己装了 Sysmon 之后才有事件。"
             "它带来的 `DGA_DOMAIN_SYSMON` / `DLL_SIDELOAD_SYSMON` 在裸机上永远不会触发。")
    L.append("")
    L.append("## 四、怎么自查当前机器的实际覆盖")
    L.append("")
    L.append("看 ETW 状态接口，重点四个字段：")
    L.append("")
    L.append("```")
    L.append("providers[].enable_ok      # 每个 provider 是否真的启用成功（TI 重点看这个）")
    L.append("providers[].captured      # 实际捕获量")
    L.append("providers[].suspicious    # 命中量")
    L.append("dropped / backpressure_drops  # 丢了多少（这两个不为 0 说明在漏）")
    L.append("```")
    L.append("")
    L.append("**判读**：`dropped` 持续增长 = 该机器的事件量超出了限流，"
             "要么调上限要么接受漏；`enable_ok=false` 的 provider 那一层等于不存在。")
    L.append("")
    L.append("## 五、明确未覆盖的攻击面")
    L.append("")
    L.append("以下这些**当前架构看不见**，需要单独说明或另想办法：")
    L.append("")
    L.append("- **WMI 创建进程（T1047 / `Win32_Process.Create`）**：WMI provider 只看持久化"
             "三件套（11/22/23），进程创建侧要指望 `Kernel-Process` 能看到父进程是 "
             "`WmiPrvSE.exe` —— 但那需要分析进程链，`analyze_kproc` 里没有这条规则。")
    L.append("- **写入内容**：`Kernel-File` 只有创建/重命名，**看不到写进去什么**。"
             "落地即加密的勒索行为只能靠事后扫描。")
    L.append("- **删除与覆盖**：没订阅删除类事件，`DeleteFile` 行为不可见。")
    L.append("- **非 DNS 的 C2**：直连 IP、DoH/DoT、域前置都绕开 `DNS-Client`。")
    L.append("- **无文件执行的内存载荷**：没有内存扫描触发点（要 TI 层或定期扫）。")
    L.append("- **驱动层**：全部是用户态 ETW，没有 minifilter / 内核回调，"
             "绕过 ETW 的手法（如直接系统调用）完全看不到。")
    L.append("")
    L.append("---")
    L.append("")
    L.append("> 这份地图的作用不是证明覆盖得广，而是让「哪里会漏」变成已知事实，"
             "而不是等出事之后再猜。")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))
    print(f"written {args.output}  ({len(L)} 行, {total_rules} 条规则)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
