"""历史记录页（病毒记忆）：统计概览 + 家族分布 + 记录检索 + 清空。

后端契约（app.py / history_manager.py）：
* ``GET  /api/v1/history/viruses?limit&keyword&virus_type&engine``
  → 记录列表 ``[{virus_type, file_path, scan_time, sha256, md5, signature,
  threat_level, engine, task_id}]``
* ``GET  /api/v1/history/virus-stats``  → ``{type_count{类型:次数},
  engine_stats{引擎:次数}, total_records, unique_types[]}``
* ``GET  /api/v1/history/virus-types``  → ``{types: [...]}``
* ``GET  /api/v1/history/virus-family?limit=20`` → ``{families[{family,count,ratio}]}``
* ``POST /api/v1/history/clear``        → ``{success}``

注意：这里的"病毒类型"字段 ``virus_type`` 在后端被当作**家族**近似使用
（``get_family_stats`` 直接 GROUP BY virus_type），所以类型分布与家族分布
是同一份数据，页面不再重复渲染两遍。
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from .. import theme as T
from .. import widgets as W
from ..api import fmt_int, fmt_time, run_async, short_hash
from ..app import Page

LEVEL_FG = {"high": T.DANGER, "critical": T.DANGER,
            "medium": T.WARNING, "low": T.TEXT_SECONDARY}

MAX_ROWS = 200


class HistoryPage(Page):
    key = "history"
    title = "历史记录"
    glyph = "⏱"

    def build(self):
        self._keyword = ""
        self._virus_type = ""
        self._engine = ""

        wrap = tk.Frame(self, bg=T.BG_APP)
        wrap.pack(fill="both", expand=True, padx=22, pady=18)

        self._build_stats(wrap)
        self._build_families(wrap)
        self._build_records(wrap)

    # ── 统计 ──

    def _build_stats(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "检出统计", T.BG_CARD).pack(side="left")
        self._total_tag = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                                   font=T.font(10))
        self._total_tag.pack(side="left", padx=(10, 0))
        W.button(head, "刷新", self.refresh, "ghost").pack(side="right")

        grid = tk.Frame(card.inner, bg=T.BG_CARD)
        grid.pack(fill="x", pady=(10, 0))
        grid.columnconfigure(0, weight=1, uniform="st")
        grid.columnconfigure(1, weight=1, uniform="st")

        left = tk.Frame(grid, bg=T.BG_CARD)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        tk.Label(left, text="按检测引擎", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(10, "bold"), anchor="w").pack(fill="x")
        self._engine_host = tk.Frame(left, bg=T.BG_CARD)
        self._engine_host.pack(fill="x", pady=(6, 0))

        right = tk.Frame(grid, bg=T.BG_CARD)
        right.grid(row=0, column=1, sticky="nsew")
        tk.Label(right, text="按病毒类型", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(10, "bold"), anchor="w").pack(fill="x")
        self._type_host = tk.Frame(right, bg=T.BG_CARD)
        self._type_host.pack(fill="x", pady=(6, 0))

    def _apply_stats(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self._total_tag.configure(text="读取失败", fg=T.DANGER)
            return
        d = res.data
        self._total_tag.configure(
            text=f"共 {fmt_int(d.get('total_records'))} 条记录 · "
                 f"{fmt_int(len(d.get('unique_types') or []))} 种类型")
        self._render_count_map(self._engine_host, d.get("engine_stats") or {},
                              "暂无引擎记录")
        self._render_count_map(self._type_host, d.get("type_count") or {},
                              "暂无类型记录")

    def _render_count_map(self, host, mapping: dict, empty_text: str):
        for child in host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not isinstance(mapping, dict) or not mapping:
            W.muted_label(host, empty_text, T.BG_CARD, size=9).pack(anchor="w")
            return
        items = sorted(mapping.items(), key=lambda kv: kv[1], reverse=True)
        top = items[0][1] if items else 1
        for name, count in items[:8]:
            row = tk.Frame(host, bg=T.BG_CARD)
            row.pack(fill="x", pady=1)
            label = str(name or "unknown")
            tk.Label(row, text=label if len(label) <= 22 else label[:21] + "…",
                     bg=T.BG_CARD, fg=T.TEXT_PRIMARY, font=T.font(9), width=22,
                     anchor="w").pack(side="left")
            # 比例条：用两个 Frame 拼，宽度按占比
            bar = tk.Frame(row, bg=T.BG_INPUT, height=8, width=120)
            bar.pack(side="left", padx=(4, 8))
            bar.pack_propagate(False)
            fill = tk.Frame(bar, bg=T.ACCENT, height=8,
                            width=max(2, int(120 * (count / top if top else 0))))
            fill.pack(side="left", fill="y")
            tk.Label(row, text=fmt_int(count), bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                     font=T.font(9), anchor="w").pack(side="left")

    # ── 家族分布 ──

    def _build_families(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "病毒家族分布 Top 10", T.BG_CARD).pack(anchor="w")
        W.muted_label(card.inner,
                      "后端按 virus_type 聚类（与上方「按病毒类型」同源），"
                      "ratio 为该家族占全部记录的比例。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))
        self._family_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._family_host.pack(fill="x")

    def _apply_families(self, res):
        for child in self._family_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._family_host, "读取失败", T.BG_CARD,
                          size=9, fg=T.DANGER).pack(anchor="w")
            return
        fams = res.data.get("families") or []
        if not fams:
            W.muted_label(self._family_host, "暂无家族数据", T.BG_CARD,
                          size=9).pack(anchor="w")
            return
        for item in fams[:10]:
            if not isinstance(item, dict):
                continue
            row = tk.Frame(self._family_host, bg=T.BG_CARD)
            row.pack(fill="x", pady=2)
            name = str(item.get("family") or "unknown")
            tk.Label(row, text=name if len(name) <= 26 else name[:25] + "…",
                     bg=T.BG_CARD, fg=T.TEXT_PRIMARY, font=T.font(10), width=26,
                     anchor="w").pack(side="left")
            bar = tk.Frame(row, bg=T.BG_INPUT, height=10, width=220)
            bar.pack(side="left", padx=(4, 8))
            bar.pack_propagate(False)
            try:
                ratio = float(item.get("ratio") or 0)
            except (TypeError, ValueError):
                ratio = 0.0
            fill = tk.Frame(bar, bg=T.DANGER, height=10,
                            width=max(2, int(220 * min(ratio, 100.0) / 100.0)))
            fill.pack(side="left", fill="y")
            tk.Label(row, text=f"{fmt_int(item.get('count'))} 次"
                               f"　{ratio:.1f}%",
                     bg=T.BG_CARD, fg=T.TEXT_SECONDARY, font=T.font(9),
                     anchor="w").pack(side="left")

    # ── 记录检索 ──

    def _build_records(self, parent):
        card = W.Card(parent)
        card.pack(fill="both", expand=True)
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "检出记录", T.BG_CARD).pack(side="left")
        self._record_count = tk.Label(head, text="", bg=T.BG_CARD,
                                      fg=T.TEXT_SECONDARY, font=T.font(9))
        self._record_count.pack(side="left", padx=(10, 0))
        W.button(head, "清空记录", self._clear, "danger").pack(side="right")

        # 检索条件
        bar = tk.Frame(card.inner, bg=T.BG_CARD)
        bar.pack(fill="x", pady=(10, 0))
        self._kw_var = tk.StringVar()
        entry = tk.Entry(bar, textvariable=self._kw_var, bg=T.BG_INPUT,
                         fg=T.TEXT_PRIMARY, insertbackground=T.ACCENT,
                         relief="flat", bd=0, highlightthickness=1,
                         highlightbackground=T.BORDER, highlightcolor=T.ACCENT,
                         font=T.font(10))
        entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))
        entry.bind("<Return>", lambda _e: self._search())
        W.button(bar, "搜索", self._search, "ghost").pack(side="left")
        W.button(bar, "重置", self._reset_search, "ghost").pack(side="left",
                                                              padx=(8, 0))

        self._filter_tag = W.muted_label(card.inner, "未筛选", T.BG_CARD, size=9)
        self._filter_tag.pack(fill="x", pady=(6, 0))

        self._record_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._record_host.pack(fill="both", expand=True, pady=(10, 0))
        W.muted_label(self._record_host, "暂无记录", T.BG_CARD,
                      size=9).pack(anchor="w")

    def _search(self):
        self._keyword = (self._kw_var.get() or "").strip()
        self._load_records()

    def _reset_search(self):
        self._kw_var.set("")
        self._keyword = ""
        self._virus_type = ""
        self._engine = ""
        self._load_records()

    def _load_records(self):
        bits = []
        if self._keyword:
            bits.append(f"关键词「{self._keyword}」")
        if self._virus_type:
            bits.append(f"类型「{self._virus_type}」")
        if self._engine:
            bits.append(f"引擎「{self._engine}」")
        self._filter_tag.configure(text="筛选：" + "、".join(bits) if bits else "未筛选")
        run_async(self,
                  lambda: self.client.history_viruses(
                      limit=MAX_ROWS, keyword=self._keyword,
                      virus_type=self._virus_type, engine=self._engine),
                  self._apply_records)

    def _apply_records(self, res):
        for child in self._record_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        # 记录接口直接返回 list（不是 dict）
        rows = res.data if res.ok else None
        if not isinstance(rows, list):
            W.muted_label(self._record_host, "无法读取记录", T.BG_CARD,
                          size=9, fg=T.DANGER).pack(anchor="w")
            self._record_count.configure(text="")
            return
        self._record_count.configure(text=f"{fmt_int(len(rows))} 条")
        if not rows:
            W.muted_label(self._record_host, "没有符合条件的记录", T.BG_CARD,
                          size=9).pack(anchor="w")
            return
        for item in rows:
            if isinstance(item, dict):
                self._record_row(item)

    def _record_row(self, item: dict):
        level = str(item.get("threat_level") or "medium").lower()
        color = LEVEL_FG.get(level, T.TEXT_SECONDARY)

        row = tk.Frame(self._record_host, bg=T.BG_HOVER)
        row.pack(fill="x", pady=2)
        pad = tk.Frame(row, bg=T.BG_HOVER)
        pad.pack(fill="x", padx=10, pady=6)

        top = tk.Frame(pad, bg=T.BG_HOVER)
        top.pack(fill="x")
        tk.Label(top, text="●", bg=T.BG_HOVER, fg=color,
                 font=T.font(9)).pack(side="left")
        sig = str(item.get("signature") or "未知")
        tk.Label(top, text=sig if len(sig) <= 46 else sig[:45] + "…",
                 bg=T.BG_HOVER, fg=T.TEXT_PRIMARY,
                 font=T.font(10, "bold")).pack(side="left", padx=(6, 0))
        tk.Label(top, text=f"[{level}] {item.get('engine') or ''}",
                 bg=T.BG_HOVER, fg=T.TEXT_MUTED,
                 font=T.font(9)).pack(side="left", padx=(8, 0))
        tk.Label(top, text=str(item.get("virus_type") or ""), bg=T.BG_HOVER,
                 fg=T.WARNING, font=T.font(9)).pack(side="left", padx=(8, 0))
        tk.Label(top, text=fmt_time(item.get("scan_time")), bg=T.BG_HOVER,
                 fg=T.TEXT_MUTED, font=T.font(9)).pack(side="right")

        path = str(item.get("file_path") or "")
        if len(path) > 112:
            path = "…" + path[-111:]
        if path:
            W.muted_label(pad, path, T.BG_HOVER, size=9, mono=True).pack(fill="x",
                                                                       pady=(4, 0))
        sha = item.get("sha256") or item.get("md5") or ""
        if sha:
            W.muted_label(pad, f"哈希 {short_hash(str(sha), 40)}", T.BG_HOVER,
                          size=8, mono=True, fg=T.TEXT_MUTED).pack(fill="x")

    # ── 动作 ──

    def _clear(self):
        if not messagebox.askyesno(
                "确认清空",
                "清空全部病毒记忆记录？\n\n"
                "这只删历史记录（virus_memory 表），隔离区里的样本不受影响。",
                parent=self.winfo_toplevel()):
            return

        def done(res):
            if res.ok and (not isinstance(res.data, dict)
                           or res.data.get("success", True)):
                self.ctx.say("病毒记忆已清空", "ok")
            else:
                self.ctx.say("清空失败", "error")
            self.refresh()

        run_async(self, self.client.history_clear, done)

    # ── 生命周期 ──

    def on_show(self):
        self.refresh()

    def on_hide(self):
        self.cancel_timers()

    def refresh(self):
        run_async(self, self.client.history_virus_stats, self._apply_stats)
        run_async(self, lambda: self.client.history_virus_family(20),
                  self._apply_families)
        self._load_records()
