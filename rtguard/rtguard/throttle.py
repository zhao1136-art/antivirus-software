"""
扫描节流 —— 把实时防护的 CPU 占用压在设定上限以内

档位（占**系统总 CPU 容量**的百分比）：

    低  low     5%
    中  medium  10%
    高  high    15%

在 4 核机器上分别是 0.2 / 0.4 / 0.6 个核心。老实现会把自己的 watchdog
刷满 `CPU 使用率过高: 100.0%`，这个控制器就是为了不再出现那种情况。

实现方式：**占空比控制**，不是 PID、也不看瞬时值去追——
每个扫描线程扫完一个文件后补一段睡眠：

    duty   = 目标核数 / 线程数          （单个线程允许的忙碌比例，上限 1.0）
    sleep  = work * (1 - duty) / duty

简单、可预测、不震荡。单文件扫描本身就很快（原生匹配器 337 MB/s），
所以睡眠粒度足够细，占用曲线是平的。

同时记录实际占用，供状态页显示，也让上限是可验证的而不是口头承诺。
"""
from __future__ import annotations

import time

__all__ = ["Throttle", "LEVELS"]

# 档位 -> (占系统容量的比例, 中文名)
LEVELS = {
    "low": (0.05, "低 5%"),
    "medium": (0.10, "中 10%"),
    "high": (0.15, "高 15%"),
}
DEFAULT_LEVEL = "low"


class Throttle:
    def __init__(self, level: str = DEFAULT_LEVEL, cores: int | None = None):
        import os
        self.cores = max(1, int(cores or os.cpu_count() or 1))
        self._level = DEFAULT_LEVEL
        self._fraction = LEVELS[DEFAULT_LEVEL][0]
        self.set_level(level)
        self._window = []          # [(wall_seconds, work_seconds)]
        self._window_span = 20.0
        self._total_work = 0.0     # 累计扫描耗时（CPU 秒）
        self._total_wall = 0.0
        self._last_sample = time.perf_counter()

    # ── 档位 ──
    def set_level(self, level: str) -> str:
        level = (level or "").strip().lower()
        if level not in LEVELS:
            level = DEFAULT_LEVEL
        self._level = level
        self._fraction = LEVELS[level][0]
        return level

    @property
    def level(self) -> str:
        return self._level

    @property
    def label(self) -> str:
        return LEVELS[self._level][1]

    @property
    def fraction(self) -> float:
        """目标占用上限，占系统总容量"""
        return self._fraction

    @property
    def budget_cores(self) -> float:
        """允许使用的核心数上限"""
        return self._fraction * self.cores

    def duty_for(self, workers: int) -> float:
        """单个扫描线程允许的忙碌比例（0~1）"""
        workers = max(1, int(workers))
        return min(1.0, self.budget_cores / workers)

    # ── 每个文件扫完后调用 ──
    def pace(self, work_seconds: float, workers: int):
        """按占空比补眠。work_seconds 是该文件的扫描 CPU 耗时。"""
        duty = self.duty_for(workers)
        self._record(work_seconds)
        if duty >= 1.0 or work_seconds <= 0:
            return 0.0
        # 因为节流本身让占用下降，sleep 用「目标」而非「实测」推算，才能收敛到目标，
        # 但给一个上限，避免单文件极小时 sleep 取值抖动。
        sleep_s = work_seconds * (1.0 - duty) / duty
        sleep_s = max(0.0, min(sleep_s, 5.0))
        if sleep_s > 0:
            time.sleep(sleep_s)
        return sleep_s

    # ── 实测占用（供状态页）──
    def _record(self, work_seconds: float):
        now = time.perf_counter()
        self._window.append((now, work_seconds))
        self._total_work += work_seconds
        cutoff = now - self._window_span
        while self._window and self._window[0][0] < cutoff:
            self._window.pop(0)
        span = now - self._last_sample
        self._total_wall += span
        self._last_sample = now

    def actual_fraction(self) -> float:
        """最近窗口内实际占用 / 系统总容量（0~1）"""
        if not self._window:
            return 0.0
        span = self._window[-1][0] - self._window[0][0]
        if span <= 0.05:
            return 0.0
        work = sum(w for _t, w in self._window)
        return min(1.0, work / span / self.cores)

    def status(self) -> dict:
        return {
            "level": self._level,
            "label": self.label,
            "target_pct": round(self._fraction * 100, 1),
            "actual_pct": round(self.actual_fraction() * 100, 1),
            "cores": self.cores,
            "budget_cores": round(self.budget_cores, 2),
            "total_work_seconds": round(self._total_work, 1),
            "levels": {k: {"label": v[1], "pct": round(v[0] * 100, 1)}
                       for k, v in LEVELS.items()},
        }
