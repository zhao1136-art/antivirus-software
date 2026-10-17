"""可复用 Tkinter 组件。

全部基于 ``tk`` 原生控件（不用 ``ttk``）——原因见 :mod:`andun_ui.theme`：
Windows 上 ttk 由系统主题绘制，暗色 ``bg`` 基本不生效。

生命周期约定
------------
凡是自带 ``after`` 循环的组件（:class:`PulseDot`）都实现 ``stop()``，
并且**重写 ``destroy()`` 时自动调用 ``stop()``**。原因是切换页面会销毁整棵
控件树，若不取消定时器，回调会更新已销毁的控件并抛 ``TclError``。
"""
from __future__ import annotations

import tkinter as tk
from typing import Callable

from . import theme as T


# ─────────────────────────────────────────────────────────────
# 容器
# ─────────────────────────────────────────────────────────────

class Card(tk.Frame):
    """1px 描边卡片。

    Tk 没有圆角/阴影，所以用「外层 Frame 填描边色 + 内层 Frame 填卡片色 +
    1px padding」模拟边界。这比 Canvas 画假圆角可靠，高 DPI 下不会糊。
    """

    def __init__(self, parent, padding: int = T.PAD, bg: str = T.BG_CARD, **kw):
        super().__init__(parent, bg=T.BORDER, **kw)
        self._body = tk.Frame(self, bg=bg)
        self._body.pack(fill="both", expand=True, padx=1, pady=1)
        # inner 是调用方真正往里塞东西的容器
        self.inner = tk.Frame(self._body, bg=bg)
        self.inner.pack(fill="both", expand=True, padx=padding, pady=padding)


class ScrollableFrame(tk.Frame):
    """Canvas + Scrollbar + 内层 Frame 的可滚动容器。

    两个易错点（本项目设计笔记里已记录）：
    * 内层 Frame 的 parent 必须是 **canvas**，否则裁剪区域失效；
    * 必须监听 ``<Configure>`` 动态更新 ``scrollregion`` 和内层宽度，
      否则窗口缩放后要么滚不到底，要么内容不跟随变宽。
    """

    def __init__(self, parent, bg: str = T.BG_APP, **kw):
        super().__init__(parent, bg=bg, **kw)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.scrollbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.content = tk.Frame(self.canvas, bg=bg)
        self._window = self.canvas.create_window((0, 0), window=self.content, anchor="nw")

        self.content.bind("<Configure>", self._on_content_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        # 滚轮只在指针悬停时生效，避免"鼠标在别处滚，这里乱动"
        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _on_content_configure(self, _event=None):
        try:
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        except tk.TclError:
            pass

    def _on_canvas_configure(self, event):
        # 内层宽度跟随 canvas，内容才会随窗口变宽
        try:
            self.canvas.itemconfigure(self._window, width=event.width)
        except tk.TclError:
            pass

    def _bind_wheel(self, _event=None):
        self.canvas.bind_all("<MouseWheel>", self._on_wheel)

    def _unbind_wheel(self, _event=None):
        # 注意：unbind_all 会清掉该序列的全部绑定。同一时刻只有一个页面可见，
        # 所以不会互相干扰；若将来同屏出现两个滚动区，需要改成按 widget 绑定。
        self.canvas.unbind_all("<MouseWheel>")

    def _on_wheel(self, event):
        try:
            self.canvas.yview_scroll(int(-event.delta / 120), "units")
        except tk.TclError:
            pass

    def scroll_to_top(self):
        try:
            self.canvas.yview_moveto(0.0)
        except tk.TclError:
            pass

    def destroy(self):
        # 页面销毁时务必摘掉全局滚轮绑定，否则残留下一个页面仍会滚动旧 canvas
        try:
            self.canvas.unbind_all("<MouseWheel>")
        except Exception:
            pass
        super().destroy()


# ─────────────────────────────────────────────────────────────
# 文本与按钮
# ─────────────────────────────────────────────────────────────

def section_title(parent, text: str, bg: str = T.BG_APP) -> tk.Label:
    return tk.Label(parent, text=text, bg=bg, fg=T.TEXT_PRIMARY,
                    font=T.font(13, "bold"), anchor="w")


def muted_label(parent, text: str = "", bg: str = T.BG_APP, size: int = 10,
                fg: str = T.TEXT_SECONDARY, mono: bool = False) -> tk.Label:
    return tk.Label(parent, text=text, bg=bg, fg=fg,
                    font=(T.mono(size) if mono else T.font(size)), anchor="w")


def button(parent, text: str, command: Callable[[], None],
           kind: str = "accent", width: int | None = None) -> tk.Button:
    """统一风格按钮。``kind`` ∈ accent / ghost / danger。"""
    palette = {
        "accent": (T.ACCENT, T.TEXT_ON_ACCENT, T.ACCENT_DIM),
        "ghost": (T.BG_HOVER, T.TEXT_PRIMARY, T.BORDER_LIGHT),
        "danger": (T.DANGER, "#ffffff", "#e03a58"),
    }
    bg, fg, hover = palette.get(kind, palette["accent"])
    btn = tk.Button(parent, text=text, command=command, bg=bg, fg=fg,
                    activebackground=hover, activeforeground=fg,
                    disabledforeground=T.TEXT_MUTED,
                    relief="flat", bd=0, highlightthickness=0,
                    font=T.font(10, "bold"), cursor="hand2",
                    padx=14, pady=6)
    if width:
        btn.configure(width=width)

    # 悬停加深，补上 Tk 缺失的 hover 反馈。
    # 必须检查 state：禁用按钮不该响应悬停，否则会出现"看着能点其实不能点"。
    def _enter(_e):
        try:
            if str(btn.cget("state")) != "disabled":
                btn.configure(bg=hover)
        except tk.TclError:
            pass

    def _leave(_e):
        try:
            if str(btn.cget("state")) != "disabled":
                btn.configure(bg=bg)
        except tk.TclError:
            pass

    btn.bind("<Enter>", _enter)
    btn.bind("<Leave>", _leave)
    return btn


class ToggleSwitch(tk.Button):
    """用 Button 模拟开关。

    不用 ``Checkbutton``：它由系统主题绘制，无法稳定控制暗色配色。
    状态直接编码在按钮文本与底色里（绿=开 / 灰=关）。
    """

    def __init__(self, parent, on_toggle: Callable[[bool], None],
                 initial: bool = True, on_text: str = "● 已开启",
                 off_text: str = "○ 已关闭", width: int = 11):
        self._on_text = on_text
        self._off_text = off_text
        self._state = bool(initial)
        self._on_toggle = on_toggle
        super().__init__(parent, command=self._clicked, relief="flat", bd=0,
                         highlightthickness=0, font=T.font(10, "bold"),
                         cursor="hand2", width=width)
        self._render()

    def _render(self):
        if self._state:
            self.configure(text=self._on_text, bg=T.SUCCESS,
                           fg=T.TEXT_ON_ACCENT, activebackground=T.ACCENT_DIM,
                           activeforeground=T.TEXT_ON_ACCENT)
        else:
            self.configure(text=self._off_text, bg=T.BG_HOVER,
                           fg=T.TEXT_MUTED, activebackground=T.BORDER_LIGHT,
                           activeforeground=T.TEXT_SECONDARY)

    def _clicked(self):
        self.set(not self._state, notify=True)

    def set(self, value: bool, notify: bool = False):
        value = bool(value)
        changed = value != self._state
        self._state = value
        self._render()
        if notify and changed:
            self._on_toggle(value)

    @property
    def state(self) -> bool:
        return self._state


class PulseDot(tk.Canvas):
    """呼吸圆点，用作"防护运行中"的状态指示。

    两色交替 + ``after`` 循环。``stop()`` 幂等，``destroy()`` 自动调用它。
    """

    def __init__(self, parent, color: str = T.ACCENT, size: int = 12,
                 period: int = 800, bg: str = T.BG_CARD):
        super().__init__(parent, width=size, height=size, bg=bg,
                         highlightthickness=0, bd=0)
        self._size = size
        self._color = color
        self._dim = T.ACCENT_DIM if color == T.ACCENT else color
        self._period = period
        self._after_id = None
        self._bright = True
        pad = 1
        self._dot = self.create_oval(pad, pad, size - pad, size - pad,
                                     fill=color, outline="")

    def start(self):
        self.stop()
        self._tick()

    def stop(self):
        if self._after_id is not None:
            try:
                self.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _tick(self):
        if not self.winfo_exists():
            return
        self._bright = not self._bright
        try:
            self.itemconfigure(self._dot, fill=self._color if self._bright else self._dim)
        except tk.TclError:
            return
        try:
            self._after_id = self.after(self._period, self._tick)
        except tk.TclError:
            self._after_id = None

    def destroy(self):
        self.stop()
        super().destroy()


# ─────────────────────────────────────────────────────────────
# 数据展示
# ─────────────────────────────────────────────────────────────

class StatCard(Card):
    """大数字统计卡：数值 + 标签 + 可选副标题。"""

    def __init__(self, parent, label: str, value: str = "--",
                 sub: str = "", accent: str = T.ACCENT):
        super().__init__(parent, padding=14)
        self._value = tk.Label(self.inner, text=value, bg=T.BG_CARD, fg=accent,
                               font=T.font(20, "bold"), anchor="w")
        self._value.pack(fill="x")
        tk.Label(self.inner, text=label, bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(10), anchor="w").pack(fill="x", pady=(4, 0))
        self._sub = tk.Label(self.inner, text=sub, bg=T.BG_CARD, fg=T.TEXT_MUTED,
                             font=T.font(9), anchor="w")
        if sub:
            self._sub.pack(fill="x", pady=(2, 0))

    def set_value(self, value: str, sub: str | None = None):
        try:
            self._value.configure(text=value)
            if sub is not None:
                self._sub.configure(text=sub)
        except tk.TclError:
            pass


class KeyValueRow(tk.Frame):
    """左标签右值的一行，用于设置/详情页。"""

    def __init__(self, parent, key: str, value: str = "--", bg: str = T.BG_CARD,
                 mono_value: bool = False, value_fg: str = T.TEXT_PRIMARY):
        super().__init__(parent, bg=bg)
        tk.Label(self, text=key, bg=bg, fg=T.TEXT_SECONDARY, font=T.font(10),
                 anchor="w", width=16).pack(side="left")
        self._value = tk.Label(self, text=value, bg=bg, fg=value_fg,
                               font=(T.mono(9) if mono_value else T.font(10)),
                               anchor="w", justify="left")
        self._value.pack(side="left", fill="x", expand=True)

    def set_value(self, value: str, fg: str | None = None):
        try:
            self._value.configure(text=value)
            if fg:
                self._value.configure(fg=fg)
        except tk.TclError:
            pass


class StatusLine(tk.Frame):
    """窗口底部状态条：显示最近一次操作的结果或后端连通性。"""

    LEVEL_FG = {
        "info": T.TEXT_SECONDARY,
        "ok": T.SUCCESS,
        "warn": T.WARNING,
        "error": T.DANGER,
    }

    def __init__(self, parent, bg: str = T.BG_SIDEBAR):
        super().__init__(parent, bg=bg, height=26)
        self.pack_propagate(False)
        self._dot = tk.Canvas(self, width=8, height=8, bg=bg,
                              highlightthickness=0, bd=0)
        self._dot.pack(side="left", padx=(T.PAD, 6))
        self._dot_id = self._dot.create_oval(1, 1, 7, 7, fill=T.TEXT_MUTED, outline="")
        self._label = tk.Label(self, text="就绪", bg=bg, fg=T.TEXT_SECONDARY,
                               font=T.font(9), anchor="w")
        self._label.pack(side="left", fill="x", expand=True)

    def set(self, text: str, level: str = "info"):
        fg = self.LEVEL_FG.get(level, T.TEXT_SECONDARY)
        try:
            self._label.configure(text=text, fg=fg)
            self._dot.itemconfigure(self._dot_id, fill=fg)
        except tk.TclError:
            pass


class EmptyHint(tk.Frame):
    """空列表占位：图标字符 + 主文案 + 副文案。"""

    def __init__(self, parent, title: str = "暂无数据", hint: str = "",
                 bg: str = T.BG_CARD, glyph: str = "◌"):
        super().__init__(parent, bg=bg)
        tk.Label(self, text=glyph, bg=bg, fg=T.TEXT_MUTED,
                 font=T.font(28)).pack(pady=(24, 8))
        tk.Label(self, text=title, bg=bg, fg=T.TEXT_SECONDARY,
                 font=T.font(11)).pack()
        if hint:
            tk.Label(self, text=hint, bg=bg, fg=T.TEXT_MUTED,
                     font=T.font(9)).pack(pady=(4, 24))
