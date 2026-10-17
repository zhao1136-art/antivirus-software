"""垃圾清理页：扫描垃圾 → 勾选分类 → 执行清理 + 清理历史。

后端契约（app.py）：
* ``POST /api/v1/clean/scan``            → ``{task_id, status}``
* ``GET  /api/v1/clean/{id}/status``     → ``CleanTask.to_dict()``
* ``POST /api/v1/clean/{id}/cancel``
* ``POST /api/v1/clean/execute``         body ``{category_ids: [...]}``
* ``GET  /api/v1/clean/history?limit=``  → ``{records: [...]}``

扫描结果里每个分类的字段（junk_cleaner._scan_category）：
``{id, name, desc, file_count, total_bytes, size_text, items, skipped}``。
清理**只允许白名单分类**，由后端 CATEGORY_DEFS 校验，前端传未知 id 会被拒。
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from .. import theme as T
from .. import widgets as W
from ..api import fmt_int, fmt_size, fmt_time, run_async
from ..app import Page
from .scan import ProgressBar

POLL_MS = 900


class CleanPage(Page):
    key = "clean"
    title = "垃圾清理"
    glyph = "⌫"

    def build(self):
        self._task_id: str | None = None
        self._running = False
        self._selected: set[str] = set()
        self._cat_vars: dict[str, tk.BooleanVar] = {}
        self._categories: list[dict] = []

        wrap = tk.Frame(self, bg=T.BG_APP)
        wrap.pack(fill="both", expand=True, padx=22, pady=18)

        self._build_actions(wrap)
        self._build_progress(wrap)
        self._build_categories(wrap)
        self._build_history(wrap)

    # ── 操作区 ──

    def _build_actions(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "垃圾清理", T.BG_CARD).pack(side="left")
        self._free_tag = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                                  font=T.font(9))
        self._free_tag.pack(side="right")

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x", pady=(10, 0))
        self._btn_scan = W.button(row, "扫描垃圾", self._start_scan)
        self._btn_scan.pack(side="left")
        self._btn_cancel = W.button(row, "取消扫描", self._cancel, "danger")
        self._btn_cancel.pack(side="left", padx=(8, 0))
        self._btn_cancel.configure(state="disabled", bg=T.BORDER,
                                   fg=T.TEXT_MUTED, cursor="")
        self._btn_clean = W.button(row, "清理选中项", self._execute, "danger")
        self._btn_clean.pack(side="left", padx=(8, 0))
        self._btn_clean.configure(state="disabled", bg=T.BORDER,
                                  fg=T.TEXT_MUTED, cursor="")
        W.button(row, "全选", lambda: self._select_all(True), "ghost").pack(
            side="right")
        W.button(row, "全不选", lambda: self._select_all(False), "ghost").pack(
            side="right", padx=(0, 8))

    # ── 进度 ──

    def _build_progress(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "扫描进度", T.BG_CARD).pack(side="left")
        self._status_tag = tk.Label(head, text="空闲", bg=T.BG_CARD,
                                    fg=T.TEXT_MUTED, font=T.font(10, "bold"))
        self._status_tag.pack(side="left", padx=(10, 0))
        self._pct = tk.Label(head, text="0%", bg=T.BG_CARD, fg=T.ACCENT,
                             font=T.font(12, "bold"))
        self._pct.pack(side="right")

        self._bar = ProgressBar(card.inner)
        self._bar.pack(fill="x", pady=(10, 8))
        self._current = W.muted_label(card.inner, "尚未扫描", T.BG_CARD, size=9,
                                      mono=True)
        self._current.pack(fill="x")

    # ── 分类列表 ──

    def _build_categories(self, parent):
        self._cat_card = W.Card(parent)
        self._cat_card.pack(fill="x", pady=(0, 14))
        W.section_title(self._cat_card.inner, "可清理分类", T.BG_CARD).pack(
            anchor="w", pady=(0, 6))
        W.muted_label(self._cat_card.inner,
                      "勾选要清理的分类，然后点「清理选中项」。"
                      "被占用的文件会自动跳过。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(0, 10))
        self._cat_host = tk.Frame(self._cat_card.inner, bg=T.BG_CARD)
        self._cat_host.pack(fill="x")
        W.muted_label(self._cat_host, "先扫描一次以列出可清理项", T.BG_CARD,
                      size=9).pack(anchor="w")

    # ── 历史 ──

    def _build_history(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 8))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "清理历史", T.BG_CARD).pack(side="left")
        W.button(head, "刷新", self._load_history, "ghost").pack(side="right")
        self._hist_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._hist_host.pack(fill="x", pady=(10, 0))

    # ── 生命周期 ──

    def on_show(self):
        self._load_history()

    def on_hide(self):
        self.cancel_timers()

    # ── 扫描 ──

    def _start_scan(self):
        if self._running:
            self.ctx.say("已有清理扫描在进行中", "warn")
            return
        self._status_tag.configure(text="启动中…", fg=T.TEXT_SECONDARY)

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self._status_tag.configure(text="启动失败", fg=T.DANGER)
                self.ctx.say(f"启动清理扫描失败：{res.error}", "error")
                return
            self._task_id = res.data.get("task_id")
            self._running = True
            self._set_busy(True)
            self._status_tag.configure(text="扫描中", fg=T.ACCENT)
            self.ctx.say("垃圾扫描已启动", "ok")
            self._poll()

        run_async(self, self.client.clean_scan, done)

    def _poll(self):
        if not self._task_id or not self._running:
            return
        run_async(self, lambda: self.client.clean_status(self._task_id),
                  self._apply_status)
        self.every(POLL_MS, self._poll)

    def _apply_status(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self._status_tag.configure(text="查询失败", fg=T.DANGER)
            return
        d = res.data
        status = str(d.get("status") or "").lower()
        try:
            progress = float(d.get("progress") or 0)
        except (TypeError, ValueError):
            progress = 0.0
        self._bar.set(progress)
        self._pct.configure(text=f"{progress:.0f}%")

        label, color = {
            "queued": ("排队中", T.TEXT_SECONDARY),
            "running": ("扫描中", T.ACCENT),
            "completed": ("已完成", T.SUCCESS),
            "cancelled": ("已取消", T.WARNING),
            "failed": ("失败", T.DANGER),
        }.get(status, (status or "未知", T.TEXT_SECONDARY))
        self._status_tag.configure(text=label, fg=color)

        item = str(d.get("current_item") or "")
        if len(item) > 100:
            item = "…" + item[-99:]
        self._current.configure(text=item or "—")

        if status in ("completed", "cancelled", "failed"):
            self._running = False
            self._set_busy(False)
            if status == "failed":
                self.ctx.say(f"扫描失败：{d.get('error')}", "error")
                return
            self._render_result(d.get("result"))

    def _render_result(self, result):
        self._categories = []
        self._cat_vars.clear()
        for child in self._cat_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass

        if not isinstance(result, dict):
            W.muted_label(self._cat_host, "无扫描结果", T.BG_CARD, size=9).pack(
                anchor="w")
            return

        cats = result.get("categories") or []
        total_bytes = result.get("total_bytes") or 0
        total_files = result.get("total_files") or 0
        self._free_tag.configure(
            text=f"共 {fmt_size(total_bytes)} / {fmt_int(total_files)} 个文件")

        if not cats:
            W.muted_label(self._cat_host, "没有发现可清理的垃圾", T.BG_CARD,
                          size=9).pack(anchor="w")
            return

        for cat in cats:
            if not isinstance(cat, dict) or not cat.get("id"):
                continue
            self._categories.append(cat)
            self._category_row(cat)

        # 默认全选（与清理工具惯例一致：用户扫描就是要清）
        self._select_all(True)

    def _category_row(self, cat: dict):
        cid = str(cat["id"])
        size = cat.get("total_bytes") or 0

        row = tk.Frame(self._cat_host, bg=T.BG_HOVER)
        row.pack(fill="x", pady=2)
        pad = tk.Frame(row, bg=T.BG_HOVER)
        pad.pack(fill="x", padx=10, pady=7)

        var = tk.BooleanVar(value=False)
        self._cat_vars[cid] = var
        chk = tk.Checkbutton(
            pad, variable=var, command=lambda c=cid: self._on_toggle(c),
            bg=T.BG_HOVER, fg=T.TEXT_PRIMARY, activebackground=T.BG_HOVER,
            activeforeground=T.TEXT_PRIMARY, selectcolor=T.BG_INPUT,
            highlightthickness=0, bd=0, font=T.font(10, "bold"),
            anchor="w", text=str(cat.get("name") or cid))
        chk.pack(side="left")

        tk.Label(pad, text=fmt_size(size), bg=T.BG_HOVER, fg=T.ACCENT,
                 font=T.font(10, "bold")).pack(side="right")
        detail = f"{fmt_int(cat.get('file_count'))} 个文件"
        skipped = cat.get("skipped")
        if skipped:
            detail += f"（跳过 {fmt_int(skipped)}）"
        tk.Label(pad, text=detail, bg=T.BG_HOVER, fg=T.TEXT_SECONDARY,
                 font=T.font(9)).pack(side="right", padx=(0, 12))

        desc = str(cat.get("desc") or "")
        if desc:
            W.muted_label(pad, desc, T.BG_HOVER, size=9).pack(side="left",
                                                             padx=(10, 0))

    def _on_toggle(self, cid: str):
        var = self._cat_vars.get(cid)
        if var is None:
            return
        if var.get():
            self._selected.add(cid)
        else:
            self._selected.discard(cid)
        self._sync_clean_button()

    def _select_all(self, value: bool):
        self._selected.clear()
        for cid, var in self._cat_vars.items():
            var.set(value)
            if value:
                self._selected.add(cid)
        self._sync_clean_button()

    def _sync_clean_button(self):
        enabled = bool(self._selected) and not self._running
        try:
            if enabled:
                self._btn_clean.configure(state="normal", bg=T.DANGER,
                                          fg="#ffffff", cursor="hand2")
            else:
                self._btn_clean.configure(state="disabled", bg=T.BORDER,
                                          fg=T.TEXT_MUTED, cursor="")
        except tk.TclError:
            pass

    def _set_busy(self, busy: bool):
        try:
            if busy:
                self._btn_scan.configure(state="disabled", bg=T.BORDER,
                                         fg=T.TEXT_MUTED)
                self._btn_cancel.configure(state="normal", bg=T.DANGER,
                                           fg="#ffffff", cursor="hand2")
            else:
                self._btn_scan.configure(state="normal", bg=T.ACCENT,
                                         fg=T.TEXT_ON_ACCENT)
                self._btn_cancel.configure(state="disabled", bg=T.BORDER,
                                           fg=T.TEXT_MUTED, cursor="")
        except tk.TclError:
            pass
        self._sync_clean_button()

    def _cancel(self):
        if not self._task_id or not self._running:
            return
        run_async(self, lambda: self.client.clean_cancel(self._task_id),
                  lambda res: self.ctx.say(
                      "已请求取消" if res.ok else f"取消失败：{res.error}",
                      "warn" if res.ok else "error"))

    # ── 执行清理 ──

    def _execute(self):
        ids = sorted(self._selected)
        if not ids:
            self.ctx.say("请先勾选要清理的分类", "warn")
            return
        names = "、".join(str(c.get("name") or c.get("id"))
                         for c in self._categories if str(c.get("id")) in ids)
        if not messagebox.askyesno(
                "确认清理",
                f"将清理以下分类，删除的文件不可恢复：\n\n{names}\n\n继续？",
                parent=self.winfo_toplevel()):
            return

        self.ctx.say("正在清理…", "info")

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self.ctx.say(f"清理失败：{res.error}", "error")
                return
            d = res.data
            if not d.get("success"):
                self.ctx.say(f"清理失败：{d.get('error') or '未知原因'}", "error")
                return
            freed = d.get("freed_text") or fmt_size(d.get("freed_bytes"))
            files = d.get("cleaned_files")
            failed = d.get("failed") or []
            tip = f"已清理 {fmt_int(files)} 个文件，释放 {freed}"
            if failed:
                tip += f"，{len(failed)} 项跳过"
            if d.get("cancelled"):
                tip += "（中途取消）"
            self.ctx.say(tip, "ok" if not d.get("cancelled") else "warn")
            self._free_tag.configure(text=f"上次清理释放 {freed}")
            # 清理后分类数据已过时，重新扫描一次
            self._start_scan()
            self._load_history()

        run_async(self, lambda: self.client.clean_execute(ids), done)

    # ── 历史 ──

    def _load_history(self):
        run_async(self, lambda: self.client.clean_history(20),
                  self._apply_history)

    def _apply_history(self, res):
        for child in self._hist_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._hist_host, "无法读取清理历史", T.BG_CARD,
                          size=9).pack(anchor="w")
            return
        records = res.data.get("records") or []
        if not records:
            W.muted_label(self._hist_host, "暂无清理记录", T.BG_CARD,
                          size=9).pack(anchor="w")
            return
        for rec in records[:20]:
            if not isinstance(rec, dict):
                continue
            row = tk.Frame(self._hist_host, bg=T.BG_CARD)
            row.pack(fill="x", pady=2)
            when = rec.get("time") or rec.get("timestamp") or ""
            freed = rec.get("freed_text") or fmt_size(rec.get("freed_bytes"))
            files = rec.get("cleaned_files")
            tk.Label(row, text=fmt_time(str(when)), bg=T.BG_CARD,
                     fg=T.TEXT_MUTED, font=T.font(9), width=12,
                     anchor="w").pack(side="left")
            tk.Label(row, text=f"释放 {freed}", bg=T.BG_CARD, fg=T.ACCENT,
                     font=T.font(9, "bold"), anchor="w").pack(side="left")
            tk.Label(row, text=f"· {fmt_int(files)} 个文件", bg=T.BG_CARD,
                     fg=T.TEXT_SECONDARY, font=T.font(9), anchor="w").pack(
                side="left", padx=(8, 0))
            cats = rec.get("categories")
            if isinstance(cats, list) and cats:
                names = "、".join(str(c.get("name") or c.get("id") or c)
                                  for c in cats[:4] if c)
                tk.Label(row, text=f"· {names}", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                         font=T.font(9), anchor="w").pack(side="left",
                                                          padx=(8, 0))
