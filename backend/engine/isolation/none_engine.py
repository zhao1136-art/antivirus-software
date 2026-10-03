"""none 后端：空隔离（= 改造前的行为，作对照 / 降级目标）。

它什么都不复制、什么都不重定向，样本直接在原始路径上执行。
真实的文件系统、真实的绝对路径全部在样本视野里 —— 唯一的约束来自
sandbox.py 的 Low IL 令牌（写向上拒绝）和 Job Object / 防火墙。

之所以保留这个后端：
  1. **对照**：同一样本跑 copy 与 none，能看出"哪些行为是隔离造成的"
     （例如 PermissionError）；
  2. **降级**：copy 后端不可用（磁盘满、被杀软拦住、非 Windows）时，
     宁可退到 none 并写明 degraded_reason，也不要静默跳过隔离。
"""
from __future__ import annotations

import os

from .base import IsolationEngine, make_prepare_result


class NoneEngine(IsolationEngine):
    """不复制、不重定向的空后端"""

    name = "none"

    def __init__(self, requested_name: str | None = None,
                 fallback_reason: str = ""):
        super().__init__(requested_name, fallback_reason)
        self._prepared = False

    def prepare(self, sample_path: str, task_id: str) -> dict:
        """不建立任何隔离环境，执行路径就是原始样本路径"""
        sample_path = os.path.abspath(sample_path)
        self._prepared = True
        if not os.path.isfile(sample_path):
            return make_prepare_result(
                self.name, sample_path, ok=False,
                degraded_reason="文件不存在",
                capabilities=self.capabilities(),
            )
        notes = [
            "none 后端不复制样本：样本直接在原始路径执行，"
            "真实文件系统（含它自己所在目录）全部在它的视野里",
        ]
        if self.requested_name not in (self.name, ""):
            notes.append(
                f"调用方请求的引擎是 {self.requested_name!r}，"
                "当前由 none 后端兜底"
            )
        return make_prepare_result(
            self.name, sample_path,
            ok=True,
            exec_path=sample_path,
            work_dir=None,      # None = 用 sandbox.py 自己的低完整性工作目录
            root_dir=None,      # 没有引擎私有目录，cleanup 无需删任何东西
            copied_files=0,
            copied_bytes=0,
            truncated=False,
            notes=notes,
            capabilities=self.capabilities(),
            # 由 get_engine() 判定"请求的引擎不存在"时给出的降级原因，
            # 原样上交，调用方据此写进报告的 degraded_reason（不静默降级）
            degraded_reason=self.fallback_reason,
        )

    def map_path(self, real_path: str) -> str:
        """空后端没有重定向：原样返回（绝不假装映射过）"""
        return real_path

    def capabilities(self) -> dict:
        return {
            "file_copy": False,
            "absolute_path_redirect": False,
            "registry_redirect": False,
            "writable_sandbox": True,   # Low IL 工作目录仍可写
            "coverage": "none_original_path",
            "limitation": ("不复制也不重定向：样本从原始路径运行，真实文件系统"
                           "全部在视野内，只靠 Low IL 拒绝越权写；"
                           "样本被拒绝的写操作会与'本来就不写'混在一起，难以区分"),
            "copy_scope": "none",
            "max_total_bytes": 0,
            "max_files": 0,
            "truncated_capable": False,
        }

    def cleanup(self) -> None:
        """幂等空操作：没有任何引擎私有目录需要删"""
        return None

    def scope_note(self) -> str:
        return ("未做复制式隔离：样本直接在原始路径运行，"
                "它能看到并尝试操作真实的文件系统（越权写由 Low IL 拒绝）。")

    def is_active(self) -> bool:
        return False
