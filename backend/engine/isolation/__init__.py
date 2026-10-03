"""可插拔沙箱隔离引擎包。

用法：

    from engine.isolation import get_engine
    eng = get_engine("copy")          # 或 get_engine() 取默认/配置里的引擎
    info = eng.prepare(sample_path, task_id)
    exec_path = info["exec_path"]     # 真正要执行的路径（副本）
    caps = eng.capabilities()         # 能力申报 -> 写进报告 isolation.capabilities
    try:
        ...
    finally:
        eng.cleanup()                 # 幂等

引擎选择优先级（get_engine(None) 时）：
    1. data/config_save.json 的 sandbox.isolation_engine（用户在设置里选的）
    2. 环境变量 CAELIRE_SANDBOX_ISOLATION_ENGINE
    3. DEFAULT_ENGINE = "copy"

未知名字**不抛异常**：降级到 none 后端，并在返回实例的 fallback_reason 里
写清原因（调用方负责把它写进报告的 degraded_reason）。
"""
from __future__ import annotations

import os

from .base import IsolationEngine, make_prepare_result, normalize_path
from .copy_engine import CopyEngine
from .none_engine import NoneEngine

#: 引擎名常量
ENGINE_COPY = "copy"
ENGINE_NONE = "none"

#: 默认引擎（copy = 复制式隔离）
DEFAULT_ENGINE = ENGINE_COPY

#: 选择引擎用的环境变量
ENV_ISOLATION_ENGINE = "CAELIRE_SANDBOX_ISOLATION_ENGINE"

#: 注册表：新增后端只需在这里登记一行
_REGISTRY: dict = {
    ENGINE_COPY: CopyEngine,
    ENGINE_NONE: NoneEngine,
}


def available_engines() -> list:
    """已注册的引擎名（排序，便于展示）"""
    return sorted(_REGISTRY)


def register_engine(name: str, engine_cls) -> None:
    """注册一个新后端（名字 -> IsolationEngine 子类）"""
    key = (name or "").strip().lower()
    if not key:
        raise ValueError("引擎名不能为空")
    _REGISTRY[key] = engine_cls


def engine_class(name: str):
    """按名字取引擎类；未知返回 None"""
    return _REGISTRY.get((name or "").strip().lower())


def configured_engine_name() -> str:
    """从用户配置读引擎名（读不到返回空串）"""
    try:
        import persistence  # backend/persistence.py（顶层模块）
        cfg = persistence.load_config_save() or {}
        section = cfg.get("sandbox") or {}
        value = section.get("isolation_engine")
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    except Exception:
        pass
    return ""


def default_engine_name() -> str:
    """默认引擎名：用户配置 > 环境变量 > DEFAULT_ENGINE"""
    name = configured_engine_name()
    if name:
        return name
    env = os.environ.get(ENV_ISOLATION_ENGINE)
    if env and env.strip():
        return env.strip().lower()
    return DEFAULT_ENGINE


def get_engine(name: str | None = None) -> IsolationEngine:
    """引擎工厂

    Args:
        name: 引擎名；None/空 -> default_engine_name()

    Returns:
        IsolationEngine 实例。未知名字返回 NoneEngine，且其 fallback_reason
        说明降级原因（不抛异常 —— 沙箱不该因为配置写错就跑不起来）。
    """
    requested = name.strip().lower() if isinstance(name, str) else ""
    if not requested:
        requested = default_engine_name()
    cls = _REGISTRY.get(requested)
    if cls is None:
        reason = (f"未知的隔离引擎 {requested!r}，可用引擎: "
                  f"{', '.join(available_engines())}；已降级为 {ENGINE_NONE}")
        return NoneEngine(requested_name=requested, fallback_reason=reason)
    return cls(requested_name=requested)


def describe_engines() -> dict:
    """所有引擎的自述（供 /api/v1/sandbox/status 使用）"""
    out = {}
    for name in available_engines():
        try:
            out[name] = get_engine(name).describe()
        except Exception as e:  # 单个引擎自述失败不影响其它
            out[name] = {"engine": name, "error": f"{type(e).__name__}: {e}"}
    return out


__all__ = [
    "IsolationEngine", "CopyEngine", "NoneEngine",
    "make_prepare_result", "normalize_path",
    "get_engine", "available_engines", "register_engine", "engine_class",
    "default_engine_name", "configured_engine_name", "describe_engines",
    "ENGINE_COPY", "ENGINE_NONE", "DEFAULT_ENGINE", "ENV_ISOLATION_ENGINE",
]
