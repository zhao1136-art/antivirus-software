"""跨引擎确认 —— YARA 命中后，还必须至少一个**其他引擎**也命中，才允许隔离。

为什么要有这一层
----------------
2026-10-03 那次事故的根因是「**YARA 一家说了算**」：

    EXE_in_LNK 命中 88% 的合法 System32 文件（514/585）
    当时的处置是「YARA 命中即自动隔离」→ 42 个系统文件被搬走

事后加的**置信度分级**（闸门零）只治了「这条规则本身弱」——
它管不住「**一条看起来很强的规则，单独一家误判**」。
这一层补的正是这个：**必须有两个引擎同意**。

哪些引擎有资格"确认"
---------------------
    hash        哈希特征库（signature_manager.lookup）—— 精确命中，与 YARA 正交
    heuristic   启发式（heuristic_engine：脚本/OLE/PDF/PE 头/勒索文本/高熵）
                实测 0/300 误报（PE 与 generic 两条路径都是）

**`ml` 只作参考、不参与确认** —— 这是实测出来的，不是猜的：

    2026-10-17 拿 40 个合法 System32 文件测 ml_scanner.scan_pe：
        SUSPICIOUS 21 (52.5%) + MALICIOUS 4 (10%) = **误报 62.5%**
    理由还都是套话（"PE 文件无导入表或使用动态 API 解析"、
    "包含 10 个 URL，可能是下载器"、"包含 1 个高熵节区(>=7.0)，可能被加壳"）。

    若把它算作"另一个引擎命中"，62.5% 的干净文件都会"确认"，
    这个闸门就形同虚设 —— 等于又回到"一家说了算"。

**刻意不参与**的：云查杀（要联网、有配额）、capa（实测 notepad 要 70 秒）、
沙箱（要真的执行样本）。把慢的/贵的/不准的排除在外，这一层才挂得上实时路径。

判定
----
    confirmed = 至少一个**确认引擎**（hash / heuristic）命中
    **未确认 → 降级为「仅告警」：不弹窗、不隔离**

超时按**未确认**处理（fail-closed）—— 这一层的目的是少杀，
卡住时"不动手"才是对的方向。

**注意**：它只**收紧**处置，不放松。已确认的仍要走后面的闸门
（系统文件复核 → 用户决定/超时）。
"""
from __future__ import annotations

import threading

__all__ = ["cross_check", "CONFIRMING_ENGINES", "ADVISORY_ENGINES",
           "DEFAULT_TIMEOUT"]

#: 有资格"确认"的引擎 —— 命中即可放行到隔离流程
CONFIRMING_ENGINES = ("hash", "heuristic")

#: 只记录、不参与判定的引擎（当前只有 ml，理由见模块文档）
ADVISORY_ENGINES = ("ml",)

#: 超时。特征库首次调用要建索引（实测 notepad 那次 4.2s），留够余量。
DEFAULT_TIMEOUT = 12.0
MAX_READ = 32 * 1024 * 1024
HEADER_64K = 65536

# 启发式作为闸门二「确认引擎」的最低分数。
# 依据：analyze_generic 对纯随机/高熵数据会给出 25~40 分的"可疑"，
# 不足以作为第三方确认；>=60 才说明多个特征同时命中。
HEURISTIC_CONFIRM_SCORE = 60


def _hit_hash(md5: str, sha1: str, sha256: str) -> dict:
    """三态返回：state ∈ hit / miss / unavailable。

    `miss` = 引擎正常跑完，说"没有"；`unavailable` = 引擎**没跑成**。
    这两者以前都只是 hit=False，下游只看布尔就分不清 —— 静默失败审计 P0。
    """
    if not (md5 or sha1 or sha256):
        return {"hit": False, "state": "miss", "detail": "没有可查的哈希"}
    try:
        from engine.signature_manager import get_signature_manager
        sig = get_signature_manager().lookup(md5=md5, sha1=sha1, sha256=sha256)
    except Exception as exc:
        return {"hit": False, "state": "unavailable", "detail": "不可用: %s" % exc}
    if sig:
        return {"hit": True, "state": "hit",
                "detail": "特征库命中 %s" % (sig.get("threat_name") or sig)}
    return {"hit": False, "state": "miss", "detail": "特征库无此哈希"}


def _hit_heuristic(data: bytes, path: str, md5: str, sha256: str, size: int) -> dict:
    """启发式是否可作为闸门二的**确认**信号。

    ⚠️ 门槛必须卡死：只要"有命中"就算确认的话，闸门二形同虚设 ——
    实测一个 40KB 的纯随机文件就能让 analyze_generic 报出"高熵/可疑"，
    于是 YARA 误报被启发式"确认"、进用户决定流程、超时自动隔离。
    所以只有 **heuristic_score >= 60 或 action == "quarantine"** 才算确认；
    其余命中仍记录 detail 供分析，但不计入 confirmed。
    """
    try:
        from engine.heuristic_engine import get_heuristic_engine
    except Exception as exc:
        return {"hit": False, "state": "unavailable", "detail": "不可用: %s" % exc}
    eng = get_heuristic_engine()
    try:
        # 与 local_scanner 同一套分派：PE 走 analyze_pe，其余走 analyze_generic。
        # 不一致的话这一层和实际扫描会得出不同结论。
        if data[:2] == b"MZ":
            r = eng.analyze_pe(data[:64], path, md5, sha256, size)
        else:
            r = eng.analyze_generic(data[:HEADER_64K], path, md5, sha256, size)
    except Exception as exc:
        return {"hit": False, "state": "unavailable", "detail": "异常: %s" % exc}
    if not r:
        return {"hit": False, "state": "miss", "detail": "启发式未命中"}
    reasons = r.get("reasons") or r.get("warnings") or []
    try:
        score = int(r.get("heuristic_score") or 0)
    except (TypeError, ValueError):
        score = 0
    action = str(r.get("action") or "")
    strong = score >= HEURISTIC_CONFIRM_SCORE or action == "quarantine"
    detail = ("启发式%s（分数 %s%s）：%s"
              % ("确认命中" if strong else "弱命中，不计入确认",
                 r.get("heuristic_score", "--"),
                 "，action=quarantine" if action == "quarantine" else "",
                 "；".join(str(x) for x in reasons[:3])))
    return {"hit": bool(strong), "state": ("hit" if strong else "miss"),
            "detail": detail, "score": score}


def _advice_ml(data: bytes, sha256: str) -> dict:
    """ML 的判定只作为**参考信息**记录，不参与 confirmed。

    实测它对合法 System32 文件的误报率是 62.5%（40 个样本里 25 个非 CLEAN），
    当确认信号用会让闸门失效。但它的 reasons 对分析员仍有价值，所以照记。
    """
    try:
        from engine.ml_scanner import scan_pe as ml_scan_pe
    except Exception as exc:
        return {"hit": False, "detail": "不可用: %s" % exc, "advisory": True}
    try:
        r = ml_scan_pe(data, sha256) or {}
    except Exception as exc:
        return {"hit": False, "detail": "异常: %s" % exc, "advisory": True}
    verdict = str(r.get("verdict") or "").upper()
    return {"hit": verdict in ("MALICIOUS", "SUSPICIOUS"),
            "detail": "%s（置信度 %s）—— 仅供参考，不参与确认"
                      % (verdict or "--", r.get("confidence")),
            "advisory": True}


def cross_check(path: str, *, data: bytes | None = None,
                md5: str = "", sha1: str = "", sha256: str = "", size: int = 0,
                timeout: float = DEFAULT_TIMEOUT,
                with_ml: bool = True,
                exclude: tuple = ()) -> dict:
    """YARA 之外找至少一个引擎也命中。

    ``exclude``：**提出该威胁的引擎**，必须排除在确认集合外，
    否则会出现"自己确认自己"—— 比如启发式产出的威胁被启发式自己确认。

    返回::

        {"confirmed": bool,           # True 才允许继续走隔离流程
         "agreeing": ["heuristic"],   # 同意的**确认引擎**（已排除 exclude）
         "engines": {"hash": {...}, "heuristic": {...}, "ml": {...,"advisory":True}},
         "note": str,
         "timed_out": bool}
    """
    out = {"confirmed": False, "agreeing": [], "engines": {},
           "note": "", "timed_out": False}
    if not path:
        out["note"] = "无路径，跳过跨引擎确认"
        return out
    excluded = {str(x).strip().lower() for x in (exclude or ()) if x}

    # ⚠️ 2026-10-31 修复：**哈希（特征库精确命中）不允许被排除**。
    #
    # 原实现把"提出威胁的引擎"一律排除，本意是防"YARA 自己确认自己"。
    # 但 scheduler / realtime_guard 在特征库命中时传的是 exclude=("hash",)，
    # 于是出现逻辑反转：
    #     样本的哈希**正好在特征库里**（23.8 万条，精确匹配、零误判风险）
    #       -> engine="signature" -> exclude=("hash",) -> 只能靠 heuristic 确认
    #       -> P E 启发式上限 70、需三项全中才到 60 -> 几乎必然不够
    #       -> confirmed=False -> **降级为仅告警**
    #     同一个文件如果被 YARA 命中、再借同一份哈希确认 -> 反而放行。
    #
    # 哈希是精确匹配，不存在"自己确认自己"的语义问题；把它排掉等于
    # **惩罚最强的那种证据**。这里无条件允许哈希参与确认。
    if excluded:
        excluded.discard("hash")

    payload: dict = {}
    shared: dict = {}            # 线程间共享缓冲（不参与返回值）
    ml_box: dict = {}            # ML 结果单独存放，不参与 confirmed
    done = threading.Event()

    def work():
        """只跑**参与判定**的引擎（hash / heuristic）—— 它们决定 confirmed。"""
        try:
            payload["hash"] = _hit_hash(md5, sha1, sha256)
            try:
                if data is not None:
                    buf = data
                else:
                    with open(path, "rb") as fh:
                        buf = fh.read(MAX_READ)
            except OSError as exc:
                payload["_error"] = "读取失败: %s" % exc
                return
            shared["buf"] = buf
            payload["heuristic"] = _hit_heuristic(buf, path, md5, sha256,
                                                  size or len(buf))
        except Exception as exc:
            payload["_error"] = "%s: %s" % (type(exc).__name__, exc)
        finally:
            done.set()

    def work_ml():
        """ML 只是**参考信息**，走独立线程，**绝不占用确认预算**。

        2026-10-31：原实现把 _advice_ml 放在同一个 work() 里串行执行。
        实测（notepad.exe，冷启动）：hash 13.09s + heuristic 0.08s + ML 3.59s
        = 16.76s，直接撞破 12s 预算 -> fail-closed -> **即使哈希在库里也判未确认**。
        ML 对 confirmed 没有任何影响，却能把整条链拖到超时，属于纯副作用。
        """
        try:
            while "buf" not in shared and not done.is_set():
                done.wait(0.05)
            buf = shared.get("buf")
            if buf is None:
                return
            ml_box["ml"] = _advice_ml(buf, sha256)
        except Exception as exc:
            ml_box["ml"] = {"hit": False, "advisory": True,
                            "detail": "异常: %s" % exc}

    th = threading.Thread(target=work, daemon=True, name="yutian-crosscheck")
    th.start()
    ml_thread = None
    if with_ml:
        ml_thread = threading.Thread(target=work_ml, daemon=True,
                                     name="yutian-crosscheck-ml")
        ml_thread.start()

    if not done.wait(max(0.1, float(timeout))):
        out["timed_out"] = True
        out["note"] = ("跨引擎确认超时（%.1fs）—— 按未确认处理，只告警不隔离"
                       % timeout)
        # 超时也要如实带上已经拿到的信息，便于排查"为什么没动"
        engines_timeout = {k: v for k, v in payload.items() if not k.startswith("_")}
        for name in CONFIRMING_ENGINES + ADVISORY_ENGINES:
            engines_timeout.setdefault(name, {"hit": False, "detail": "未完成（超时）"})
        out["engines"] = engines_timeout
        out["excluded"] = sorted(excluded)
        return out

    # ML 只再多等一小会儿；拿不到就标"未完成"，**不影响 confirmed**
    if ml_thread is not None:
        ml_thread.join(0.5)

    engines = {k: v for k, v in payload.items() if not k.startswith("_")}
    # ML 结果只放进展示字段，**不参与 confirmed**（见 _advice_ml 文档）
    if ml_box.get("ml"):
        engines["ml"] = ml_box["ml"]
    for name in CONFIRMING_ENGINES + ADVISORY_ENGINES:
        engines.setdefault(name, {"hit": False, "state": "unavailable",
                                  "detail": "未完成（超出参考预算，不影响判定）"})
    out["engines"] = engines
    shared.pop("buf", None)      # 及早释放最多 32MB 的缓冲

    # 三态汇总（静默失败审计 P0）：明确区分「跑了说没有」与「根本没跑成」。
    # 只有疑似未命中的才是 miss；state 缺失按 miss 处理（兼容旧字段）。
    def _state_of(name: str) -> str:
        e = engines.get(name) or {}
        return str(e.get("state") or ("hit" if e.get("hit") else "miss"))

    out["unavailable"] = sorted(k for k in CONFIRMING_ENGINES if _state_of(k) == "unavailable")
    out["states"] = {k: _state_of(k) for k in CONFIRMING_ENGINES + ADVISORY_ENGINES}

    # 只有确认引擎算数；advisory 的 hit 不参与。
    # 并且**排除提出该威胁的那个引擎** —— 否则是自己确认自己。
    # （"hash" 已在入口处被无条件移出 excluded，见上方注释）
    out["agreeing"] = sorted(k for k in CONFIRMING_ENGINES
                             if k not in excluded and engines.get(k, {}).get("hit"))
    out["confirmed"] = bool(out["agreeing"])
    out["excluded"] = sorted(excluded)

    if out["confirmed"]:
        out["note"] = ("跨引擎确认通过：%s 与 YARA 同时命中"
                       % "、".join(out["agreeing"]))
    else:
        detail = "；".join("%s %s" % (k, engines.get(k, {}).get("detail", ""))
                           for k in CONFIRMING_ENGINES if k not in excluded)
        if excluded:
            detail = "（已排除提出威胁的引擎 %s）%s" % ("、".join(sorted(excluded)), detail)
        if out["unavailable"]:
            # 关键区分：不是"确认没通过"，而是"根本没确认成" —— 必须让上层看见
            out["note"] = ("**跨引擎确认未能完成**（%s 不可用）—— 按未确认处理，"
                           "降级为仅告警（%s）"
                           % ("、".join(out["unavailable"]), detail))
        else:
            out["note"] = "**YARA 之外没有其他引擎命中** —— 降级为仅告警（%s）" % detail
    if payload.get("_error"):
        out["note"] += "｜内部错误: %s" % payload["_error"]
    return out
