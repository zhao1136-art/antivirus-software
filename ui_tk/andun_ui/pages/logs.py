"""日志页：威胁日志与扫描日志合并视图，支持按类型过滤与清空。"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from .. import theme as T
from .. import widgets as W
from ..api import fmt_int, fmt_time, run_async, short_hash
from ..app import Page

REFRESH_MS = 6000

LEVEL_FG = {
    "high": T.DANGER, "critical": T.DANGER,
    "medium": T.WARNING, "low": T.TEXT_SECONDARY,
}

# 过滤键 → 按钮文案
FILTERS = (("all", "全部"), ("threat", "威胁"), ("scan", "扫描"))


class LogsPage(Page):
    key = "logs"
    title = "日志报告"
    glyph = "≡"

    def build(self):
        self._filter = "all"
        self._cache: dict = {"threats": [], "scans": []}

        wrap = tk.Frame(self, bg=T.BG_APP)
        wrap.pack(fill="both", expand=True, padx=22, pady=18)

        head = W.Card(wrap)
        head.pack(fill="x", pady=(0, 14))
        top = tk.Frame(head.inner, bg=T.BG_CARD)
        top.pack(fill="x")
        W.section_title(top, "日志报告", T.BG_CARD).pack(side="left")
        self._count = tk.Label(top, text="", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                               font=T.font(10))
        self._count.pack(side="left", padx=(10, 0))

        actions = tk.Frame(top, bg=T.BG_CARD)
        actions.pack(side="right")
        W.button(actions, "刷新", self.refresh, "ghost").pack(side="left")
        W.button(actions, "清空日志", self._clear, "danger").pack(side="left",
                                                               padx=(8, 0))

        filters = tk.Frame(head.inner, bg=T.BG_CARD)
        filters.pack(fill="x", pady=(12, 0))
        self._filter_buttons: dict[str, tk.Button] = {}
        for key, label in FILTERS:
            # 不用 W.button：它的 hover 回调会把"选中高亮"覆盖成普通底色。
            # 过滤按钮需要 hover 逻辑知道当前是否选中，所以这里自己建。
            btn = tk.Button(filters, text=label, command=lambda k=key: self._set_filter(k),
                            relief="flat", bd=0, highlightthickness=0,
                            font=T.font(10, "bold"), cursor="hand2",
                            padx=14, pady=6)
            btn.pack(side="left", padx=(0, 8))
            btn.bind("<Enter>", lambda _e, k=key: self._hover_filter(k, True))
            btn.bind("<Leave>", lambda _e, k=key: self._hover_filter(k, False))
            self._filter_buttons[key] = btn
        self._paint_filters()

        self._list_card = W.Card(wrap)
        self._list_card.pack(fill="both", expand=True)
        self._host = self._list_card.inner
        W.EmptyHint(self._host, "暂无日志", "扫描或拦截事件会记录在这里",
                    T.BG_CARD, "≡").pack(fill="both", expand=True)

    # ── 过滤 ──

    def _set_filter(self, key: str):
        self._filter = key
        self._paint_filters()
        self._render()

    def _paint_filters(self):
        for key, btn in self._filter_buttons.items():
            try:
                if key == self._filter:
                    btn.configure(bg=T.ACCENT, fg=T.TEXT_ON_ACCENT,
                                  activebackground=T.ACCENT_DIM,
                                  activeforeground=T.TEXT_ON_ACCENT)
                else:
                    btn.configure(bg=T.BG_HOVER, fg=T.TEXT_PRIMARY,
                                  activebackground=T.BORDER_LIGHT,
                                  activeforeground=T.TEXT_PRIMARY)
            except tk.TclError:
                pass

    def _hover_filter(self, key: str, entering: bool):
        """悬停只在未选中时提亮；选中态保持强调色，不被 hover 冲掉。"""
        btn = self._filter_buttons.get(key)
        if btn is None or key == self._filter:
            return
        try:
            btn.configure(bg=T.BORDER_LIGHT if entering else T.BG_HOVER)
        except tk.TclError:
            pass

    # ── 生命周期 ──

    def on_show(self):
        self.refresh()
        self.every(REFRESH_MS, self.refresh)

    def on_hide(self):
        self.cancel_timers()

    def refresh(self):
        run_async(self, self.client.stats_activity, self._apply,
                  lambda exc: self.ctx.say(f"读取日志失败: {exc}", "error"))

    def _apply(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self._count.configure(text="")
            self._clear_host()
            W.EmptyHint(self._host, "无法读取日志", res.error or "后端未连接",
                        T.BG_CARD, "≡").pack(fill="both", expand=True)
            return
        self._cache["threats"] = res.data.get("threats") or []
        self._cache["scans"] = res.data.get("scans") or []
        self._render()

    # ── 渲染 ──

    def _clear_host(self):
        for child in self._host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass

    def _render(self):
        if not self.winfo_exists():
            return
        threats = self._cache["threats"]
        scans = self._cache["scans"]

        self._count.configure(
            text=f"威胁 {fmt_int(len(threats))} · 扫描 {fmt_int(len(scans))}")

        entries: list[tuple[str, dict]] = []
        if self._filter in ("all", "threat"):
            entries += [("threat", t) for t in threats if isinstance(t, dict)]
        if self._filter in ("all", "scan"):
            entries += [("scan", s) for s in scans if isinstance(s, dict)]

        if not entries:
            self._clear_host()
            W.EmptyHint(self._host, "暂无日志", "换个过滤条件，或先运行一次扫描",
                        T.BG_CARD, "≡").pack(fill="both", expand=True)
            return

        # 按时间倒序（时间串是 ISO 前缀，字典序即时序）
        entries.sort(key=lambda kv: str(kv[1].get("timestamp") or ""), reverse=True)

        self._clear_host()
        for kind, item in entries[:300]:
            if kind == "threat":
                self._threat_row(item)
            else:
                self._scan_row(item)

    def _threat_row(self, item: dict):
        level = str(item.get("threat_level") or "medium").lower()
        color = LEVEL_FG.get(level, T.TEXT_SECONDARY)
        action = str(item.get("action") or "ignore")
        action_fg = T.SUCCESS if action == "quarantine" else T.TEXT_MUTED

        row = tk.Frame(self._host, bg=T.BG_HOVER)
        row.pack(fill="x", pady=2)
        pad = tk.Frame(row, bg=T.BG_HOVER)
        pad.pack(fill="x", padx=10, pady=7)

        top = tk.Frame(pad, bg=T.BG_HOVER)
        top.pack(fill="x")
        tk.Label(top, text="⚠", bg=T.BG_HOVER, fg=color,
                 font=T.font(10)).pack(side="left")
        tk.Label(top, text=str(item.get("signature") or "未知威胁"),
                 bg=T.BG_HOVER, fg=T.TEXT_PRIMARY,
                 font=T.font(10, "bold")).pack(side="left", padx=(6, 0))
        tk.Label(top, text=str(item.get("engine") or ""), bg=T.BG_HOVER,
                 fg=T.TEXT_MUTED, font=T.font(9)).pack(side="left", padx=(8, 0))
        tk.Label(top, text=action, bg=T.BG_HOVER, fg=action_fg,
                 font=T.font(9, "bold")).pack(side="left", padx=(8, 0))
        tk.Label(top, text=fmt_time(item.get("timestamp")), bg=T.BG_HOVER,
                 fg=T.TEXT_MUTED, font=T.font(9)).pack(side="right")

        path = str(item.get("path") or "")
        if len(path) > 118:
            path = "…" + path[-117:]
        if path:
            W.muted_label(pad, path, T.BG_HOVER, size=9, mono=True).pack(fill="x",
                                                                       pady=(4, 0))

        details = item.get("details") or {}
        warnings = details.get("warnings") if isinstance(details, dict) else None
        if warnings:
            text = "、".join(str(w) for w in warnings[:4])
            if len(text) > 110:
                text = text[:107] + "…"
            W.muted_label(pad, f"命中: {text}", T.BG_HOVER, size=8,
                          fg=T.TEXT_MUTED).pack(fill="x")

    def _scan_row(self, item: dict):
        event = str(item.get("event") or "scan")
        stats = item.get("stats") if isinstance(item.get("stats"), dict) else {}

        row = tk.Frame(self._host, bg=T.BG_CARD)
        row.pack(fill="x", pady=2)
        pad = tk.Frame(row, bg=T.BG_CARD)
        pad.pack(fill="x", padx=10, pady=6)

        top = tk.Frame(pad, bg=T.BG_CARD)
        top.pack(fill="x")
        tk.Label(top, text="✓", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(10)).pack(side="left")
        tk.Label(top, text=event, bg=T.BG_CARD, fg=T.TEXT_PRIMARY,
                 font=T.font(10)).pack(side="left", padx=(6, 0))

        bits = []
        for key, label in (("files_scanned", "扫描"), ("threats_found", "检出"),
                           ("quarantined", "隔离"), ("duration", "耗时")):
            if key in stats:
                bits.append(f"{label} {fmt_int(stats.get(key))}")
        if bits:
            tk.Label(top, text=" · ".join(bits), bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                     font=T.font(9)).pack(side="left", padx=(10, 0))
        tk.Label(top, text=fmt_time(item.get("timestamp")), bg=T.BG_CARD,
                 fg=T.TEXT_MUTED, font=T.font(9)).pack(side="right")

        task_id = item.get("task_id")
        if task_id:
            W.muted_label(pad, f"任务 {short_hash(str(task_id), 8)}", T.BG_CARD,
                          size=8, mono=True, fg=T.TEXT_MUTED).pack(fill="x")

    # ── 动作 ──

    def _clear(self):
        if not messagebox.askyesno(
                "确认清空",
                "清空全部扫描日志与威胁日志？\n\n"
                "注意：这只清空日志文件，隔离区里的样本不受影响。",
                parent=self.winfo_toplevel()):
            return

        def done(res):
            if res.ok:
                self.ctx.say("日志已清空", "ok")
            else:
                self.ctx.say(f"清空失败: {res.error}", "error")
            self.refresh()

        run_async(self, self.client.logs_clear, done)
