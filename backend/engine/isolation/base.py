"""隔离引擎抽象基类（可插拔沙箱隔离后端）。

为什么要有这一层
----------------
原来 sandbox.py 把"样本在什么文件系统视野里运行"和"资源限制 / 网络阻断 /
Low IL 令牌"揉在一起，只有一种做法（直接在原路径跑）。但"直接在原路径跑"
和"在副本上跑"对分析员的意义完全不同：

    * Low IL 让样本**写**不进用户目录 -> 观测到的 PermissionError 究竟是
      "样本想写但被拦" 还是 "样本本来就不写"，光看行为日志分不清；
    * 复制式隔离下，样本甚至**看不见**真实文件，写落在副本里，
      于是"写成功"和"被拦"才是两件可区分的事。

所以把文件系统视野抽成可插拔后端，并且**强制每个后端申报能力**
（capabilities），把"这个引擎到底改了什么、没改什么"写进报告。

接口契约
--------
    name: str                                  # "copy" | "none" | ...
    prepare(sample_path, task_id) -> dict      # 建隔离环境，返回执行信息
    map_path(real_path) -> str                 # 真实路径 -> 引擎内路径
    capabilities() -> dict                     # 能力申报（必须诚实）
    cleanup() -> None                          # 幂等，必须在 finally 中调用

prepare() 返回值（所有引擎统一，缺省值见 make_prepare_result）：

    {
      "ok": bool,              # False = 引擎不可用，调用方应降级到 none
      "engine": str,
      "sample_path": str,      # 原始样本路径（只作参考，不作为执行路径）
      "exec_path": str,        # 引擎要求真正执行的路径
      "work_dir": str | None,  # 子进程工作目录（lpCurrentDirectory）；
                               #   None = 用调用方自己的低完整性工作目录
      "root_dir": str | None,  # 引擎私有根目录（cleanup 负责删掉）
      "copied_files": int,     # 沙箱内实际落地的文件总数（含样本自身；
                               #   copy 引擎另给 copied_files_in_dir = 同目录部分）
      "copied_bytes": int,     # 落地文件总字节数（含样本）
      "truncated": bool,       # 因为容量上限没复制全，如实上报
      "skipped": [{"path": str, "reason": str}],
      "copy_errors": [{"path": str, "error": str}],
      "notes": [str],
      "capabilities": dict,
      "degraded_reason": str,  # 引擎内部降级原因（空 = 无）
    }

注意：prepare() 失败时**不**自行删目录（调用方可能还要读它的诊断信息），
调用方在降级前应调用 cleanup()。

能力表（capabilities）必须回答"这个引擎真正改了什么"。分析员就是靠它
区分"样本写成功了"和"样本的写被拦了"，所以宁可写 False 也不要吹。
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod


def normalize_path(path: str) -> str:
    """规范化路径用于比较/映射（绝对路径 + 大小写不敏感）"""
    if not path:
        return ""
    try:
        return os.path.normcase(os.path.abspath(path))
    except Exception:
        return os.path.normcase(str(path))


def make_prepare_result(engine_name: str, sample_path: str, **overrides) -> dict:
    """构造 prepare() 的标准返回值（统一缺省值，避免各引擎字段不一致）"""
    result = {
        "ok": False,
        "engine": engine_name,
        "sample_path": sample_path,
        "exec_path": sample_path,
        "work_dir": None,
        "root_dir": None,
        "copied_files": 0,
        "copied_bytes": 0,
        "truncated": False,
        "skipped": [],
        "copy_errors": [],
        "notes": [],
        "capabilities": {},
        "degraded_reason": "",
    }
    if overrides:
        result.update(overrides)
    return result


class IsolationEngine(ABC):
    """隔离引擎抽象基类。

    子类必须实现 prepare / map_path / capabilities / cleanup 四个方法。
    """

    #: 引擎真实名字（"copy" / "none" …）
    name: str = "base"

    def __init__(self, requested_name: str | None = None,
                 fallback_reason: str = ""):
        #: 调用方请求的引擎名；与 name 不同就意味着发生了降级
        self.requested_name = requested_name or self.name
        #: 名字与实现不一致的原因（例如请求了不存在的引擎）
        self.fallback_reason = fallback_reason or ""
        self._cleanup_error = ""

    # ── 必须实现的接口 ──

    @abstractmethod
    def prepare(self, sample_path: str, task_id: str) -> dict:
        """准备隔离环境。返回 make_prepare_result() 形态的字典。"""
        raise NotImplementedError

    @abstractmethod
    def map_path(self, real_path: str) -> str:
        """真实路径 -> 引擎内部路径。

        无法映射时必须**原样返回**真实路径，绝不允许假装已经重定向：
        调用方/分析员据 capabilities()["absolute_path_redirect"] 判断。
        """
        raise NotImplementedError

    @abstractmethod
    def capabilities(self) -> dict:
        """能力申报（必须与真实行为一致）"""
        raise NotImplementedError

    @abstractmethod
    def cleanup(self) -> None:
        """清理隔离环境（幂等，必须在 finally 中调用）"""
        raise NotImplementedError

    # ── 扩展（非接口必需，但 sandbox.py 会用到）──

    @property
    def cleanup_error(self) -> str:
        """上一次 cleanup() 的失败原因（空 = 干净）"""
        return self._cleanup_error

    def scope_note(self) -> str:
        """一句话说明隔离作用范围（写进报告给分析员看）"""
        return ""

    def is_active(self) -> bool:
        """本次分析是否真的改变了文件系统视野（none 返回 False）"""
        return False

    def describe(self) -> dict:
        """引擎自述（用于 /api/v1/sandbox/status 与报告）"""
        return {
            "engine": self.name,
            "requested": self.requested_name,
            "fallback_reason": self.fallback_reason,
            "capabilities": self.capabilities(),
            "scope_note": self.scope_note(),
            "active": self.is_active(),
            "cleanup_error": self._cleanup_error,
        }

    def __repr__(self) -> str:
        return (f"<{type(self).__name__} name={self.name!r} "
                f"requested={self.requested_name!r}>")
