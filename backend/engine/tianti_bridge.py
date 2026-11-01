"""天体引擎（TianTi）桥接 —— 把沙箱行为分析接进御天的深度分析。

为什么走子进程而不是 import
============================
* 御天打包在 **Python 3.14**；天体引擎面向 **3.12**，且 `dist\\tianti\\tianti.exe`
  是已冻结的自包含产物（2.6 MB，含全部依赖）。子进程调用**零版本冲突**。
* 天体崩了不会拖垮御天主进程。
* 与御天既有的 `native_engine.exe` 子进程模式一致。

⚠️ 安全边界（务必知情）
======================
天体引擎的 `containment` 后端是**受限执行**（受限令牌 + 低完整性 + Job Object +
按程序防火墙 + 超时强杀 + 进程树清理），**不是 VM 隔离**。
它自己的 README 写得很清楚：

    "本机无虚拟化：containment 是「受限执行」而非 VM 隔离，只跑无害样本；
     真实恶意样本需独立 VM。"

所以本桥接**默认 `--static-only`（完全不执行样本）**。要真的跑沙箱，必须由调用方
显式传 `allow_execute=True`（或设环境变量 `YUTIAN_TIANTI_EXECUTE=1`），并且
调用方应当确认：这是用户主动发起的深度分析，而不是扫描热路径里的自动行为。

御天的扫描链路（local_scanner / 闸门二）**不应该**自动调用本模块的沙箱模式。
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import tempfile
import time

# Windows CREATE_NO_WINDOW —— 御天是 GUI 程序，子进程不能弹黑框
_CREATE_NO_WINDOW = 0x08000000

# 默认策略：deep = containment + 注册表 ETW
DEFAULT_POLICY = "deep"
DEFAULT_TIMEOUT = 300          # 单文件上限（沙箱 20s + ETW 解析 + 启动）
STATIC_TIMEOUT = 120           # 纯静态时更快


def _candidates() -> list[str]:
    """按优先级列出 tianti.exe 的位置。"""
    out = []
    env_exe = os.environ.get("YUTIAN_TIANTI_EXE", "").strip()
    if env_exe:
        out.append(env_exe)
    env_home = os.environ.get("YUTIAN_TIANTI_HOME", "").strip()
    if env_home:
        out.append(os.path.join(env_home, "dist", "tianti", "tianti.exe"))
        out.append(os.path.join(env_home, "dist", "御天分析", "tianti", "tianti.exe"))
    # 已知部署位置（可移除盘）：找不到时由 status() 如实报告
    out.append(r"G:\天体引擎\dist\tianti\tianti.exe")
    out.append(r"G:\天体引擎\dist\御天分析\tianti\tianti.exe")
    return out


def find_exe() -> str:
    """返回可用的 tianti.exe 路径；找不到返回空串。"""
    for p in _candidates():
        if p and os.path.isfile(p):
            return p
    which = shutil.which("tianti.exe") or shutil.which("tianti")
    return which or ""


def available() -> bool:
    return bool(find_exe())


def status() -> dict:
    """给 deep_analyzer.engines_status() 用的状态块。"""
    exe = find_exe()
    info = {
        "available": bool(exe),
        "type": "沙箱行为分析",
        "desc": "天体引擎 TianTi —— 沙箱执行 + capa 规则 + 行为检测器（默认仅静态）",
        "exe": exe or None,
        "execute_default": _execute_allowed_by_env(),
    }
    if not exe:
        info["note"] = ("未找到 tianti.exe。设 YUTIAN_TIANTI_HOME 指向天体引擎根目录，"
                        "或 YUTIAN_TIANTI_EXE 指向 exe。")
    return info


def _execute_allowed_by_env() -> bool:
    return os.environ.get("YUTIAN_TIANTI_EXECUTE", "") == "1"


def _parse_result(path: str) -> dict:
    """把 tianti 的 result.json 归一化成御天能用的结构。"""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        j = json.load(fh)
    sm = ((j.get("trace") or {}).get("summary") or {})
    verdict = j.get("verdict") or {}
    extra = j.get("extra") or {}
    trace_extra = ((j.get("trace") or {}).get("extra") or {})
    return {
        "status": "success",
        "engine": "tianti",
        "executed": bool(extra.get("input") == "sandbox"),
        "verdict": str(verdict.get("verdict") or ""),
        "score": float(verdict.get("score") or 0.0),
        "confidence": float(verdict.get("confidence") or 0.0),
        "tactics": list(verdict.get("tactics") or []),
        "techniques": list(verdict.get("techniques") or []),
        "detectors": [
            {"name": h.get("name") or h.get("detector"),
             "severity": h.get("severity"), "score": h.get("score"),
             "evidence": list(h.get("evidence") or [])[:6]}
            for h in (j.get("hits") or [])
        ],
        "capabilities": [
            {"name": m.get("name"), "namespace": m.get("namespace"),
             "attack": list(m.get("attack") or [])}
            for m in (j.get("matches") or [])
        ],
        "event_count": int(sm.get("event_count") or 0),
        "summary": {
            "processes": sm.get("processes"),
            "file_writes": sm.get("file_writes"),
            "reg_sets": sm.get("reg_sets"),
            "net_connects": sm.get("net_connects"),
            "apis": sm.get("apis"),
            "truncated": sm.get("truncated"),
        },
        "etw_registry": trace_extra.get("etw_registry"),
        "policy": extra.get("policy"),
        "backend": (extra.get("backend") or {}).get("backend"),
        "notes": list(j.get("notes") or [])[:6],
        "result_path": path,
    }


def analyze(file_path: str, allow_execute: bool = False,
            policy: str = DEFAULT_POLICY, timeout: int | None = None) -> dict:
    """对一个文件跑天体引擎分析。

    :param allow_execute: **默认 False = 只做静态分析，不执行样本**。
                          置 True 才会进 containment 沙箱实际运行 —— 见模块头的安全边界。
    :param policy: 沙箱策略（仅 allow_execute 时生效）：fast / deep / paranoid
    :returns: 归一化结果；失败时 status="error"/"unavailable" 且带 error 字段。

    返回结构::

        {"status": "success"|"error"|"unavailable", "engine": "tianti",
         "executed": bool, "verdict": "clean|suspicious|malicious",
         "score": float, "confidence": float, "tactics": [...],
         "techniques": [...], "detectors": [...], "capabilities": [...],
         "event_count": int, "summary": {...}, "notes": [...], "error": str}
    """
    exe = find_exe()
    if not exe:
        return {"status": "unavailable", "engine": "tianti",
                "error": "未找到 tianti.exe（设 YUTIAN_TIANTI_HOME 或 YUTIAN_TIANTI_EXE）"}
    if not file_path or not os.path.isfile(file_path):
        return {"status": "error", "engine": "tianti", "error": "文件不存在"}

    execute = bool(allow_execute) or _execute_allowed_by_env()
    outdir = tempfile.mkdtemp(prefix="yutian_tianti_")
    cmd = [exe, "scan", os.path.abspath(file_path),
           "--format", "json", "--out", outdir]
    if not execute:
        cmd.append("--static-only")
    elif policy:
        cmd.extend(["--policy", str(policy)])

    limit = int(timeout or (DEFAULT_TIMEOUT if execute else STATIC_TIMEOUT))
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=limit,
            creationflags=_CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(outdir, ignore_errors=True)
        return {"status": "error", "engine": "tianti", "executed": execute,
                "error": f"天体引擎超时（{limit}s）", "elapsed_ms": int((time.time() - t0) * 1000)}
    except OSError as exc:
        shutil.rmtree(outdir, ignore_errors=True)
        return {"status": "error", "engine": "tianti",
                "error": f"无法启动 tianti.exe: {exc}",
                "elapsed_ms": int((time.time() - t0) * 1000)}

    try:
        hits = sorted(glob.glob(os.path.join(outdir, "**", "*.result.json"), recursive=True))
        if not hits:
            # 失败时把 stderr 尾部带出来，别吞掉
            tail = ((proc.stderr or "") + (proc.stdout or "")).strip().splitlines()
            return {"status": "error", "engine": "tianti", "executed": execute,
                    "error": "天体引擎未产出 result.json",
                    "detail": tail[-5:],
                    "returncode": proc.returncode,
                    "elapsed_ms": int((time.time() - t0) * 1000)}
        res = _parse_result(hits[0])
        res["executed"] = execute
        res["elapsed_ms"] = int((time.time() - t0) * 1000)
        return res
    except Exception as exc:                      # noqa: BLE001 - 桥接层不向调用方抛
        return {"status": "error", "engine": "tianti", "executed": execute,
                "error": f"解析结果失败: {type(exc).__name__}: {exc}",
                "elapsed_ms": int((time.time() - t0) * 1000)}
    finally:
        shutil.rmtree(outdir, ignore_errors=True)
