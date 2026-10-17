"""御天 Tkinter UI —— 主题常量与字体解析。

视觉语言对齐两处既有来源，保证新 UI 不是另一套风格：

1. ``backend/frontend/*.html`` 的 CSS 变量（``--bg-primary`` / ``--accent`` 等）
2. ``ai_learning_results/Tkinter_GUI/20260725_dashboard.md`` 记录的暗色 token

Tkinter 的限制（有意接受，不做伪装）
------------------------------------
* 原生控件没有圆角、没有阴影、没有透明度。这里统一用 **1px 描边 + 分层底色**
  模拟卡片边界，而不是去堆 Canvas 假圆角 —— 后者在高 DPI 下会糊。
* ``ttk`` 在 Windows 上由系统主题绘制，``background`` 基本被忽略。所以全量使用
  ``tk`` 原生控件并显式指定 ``bg`` / ``fg``，这是拿到稳定暗色主题的唯一可靠做法。
"""
from __future__ import annotations

import tkinter.font as tkfont

# ── 底色层次（由深到浅：应用 → 侧栏 → 卡片 → 悬停）──
BG_APP = "#07070a"
BG_SIDEBAR = "#0e0e14"
BG_CARD = "#13131c"
BG_HOVER = "#1a1a26"
BG_INPUT = "#0b0b12"

# ── 描边 ──
BORDER = "#252536"
BORDER_LIGHT = "#2f2f44"

# ── 文字（三级灰度构建信息层级）──
TEXT_PRIMARY = "#f4f4f9"
TEXT_SECONDARY = "#8f8fab"
TEXT_MUTED = "#5c5c75"
TEXT_ON_ACCENT = "#04121a"

# ── 语义色 ──
ACCENT = "#00d9c0"
ACCENT_DIM = "#00b099"
DANGER = "#ff4d6d"
WARNING = "#ffcc00"
SUCCESS = "#00d9c0"

# ── 尺寸 ──
SIDEBAR_W = 168
PAD = 16
PAD_S = 8
RADIUS = 0  # Tk 无圆角，保留常量以标明此处是刻意的

# ── 字体 ──
_UI_FAMILY = "Segoe UI"
_MONO_FAMILY = "Consolas"
_resolved = False

# 中文界面优先雅黑，逐级回退
_UI_CANDIDATES = ("Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", "Tahoma")
_MONO_CANDIDATES = ("Cascadia Mono", "Consolas", "Courier New")


def resolve_fonts(root) -> None:
    """在 ``Tk()`` 创建后调用一次，挑选本机真实存在的字族。

    直接写死字族名在缺字体的机器上会静默回退成很难看的默认字体，
    这里显式做一次探测，宁可退到 Segoe UI 也不要用 Tk 默认。
    """
    global _UI_FAMILY, _MONO_FAMILY, _resolved
    if _resolved:
        return
    try:
        available = set(tkfont.families(root))
    except Exception:
        available = set()
    for name in _UI_CANDIDATES:
        if name in available:
            _UI_FAMILY = name
            break
    for name in _MONO_CANDIDATES:
        if name in available:
            _MONO_FAMILY = name
            break
    _resolved = True


def ui_family() -> str:
    return _UI_FAMILY


def mono_family() -> str:
    return _MONO_FAMILY


def font(size: int = 10, weight: str = "normal"):
    """返回 UI 字体的字体元组，可直接喂给 ``font=`` 参数。"""
    return (_UI_FAMILY, size, weight)


def mono(size: int = 9, weight: str = "normal"):
    """等宽字体元组，用于哈希 / 路径 / 日志。"""
    return (_MONO_FAMILY, size, weight)
