"""隔离区页：列出被隔离文件，支持单个/批量还原与永久删除。

危险操作（永久删除）一律二次确认——``messagebox`` 是模态的，所以调用点
必须在主线程（UI 回调里），不能放到后台线程。
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from .. import theme as T
from .. import widgets as W
from ..api import fmt_int, fmt_size, fmt_time, run_async, short_hash
from ..app import Page

LEVEL_FG = {
    "high": T.DANGER, "critical": T.DANGER,
    "medium": T.WARNING, "low": T.TEXT_SECONDARY,
}


class QuarantinePage(Page):
    key = "quarantine"
    title = "隔离区"
    glyph = "▣"

    def build(self):
        wrap = tk.Frame(self, bg=T.BG_APP)
        wrap.pack(fill="both", expand=True, padx=22, pady=18)

        head = W.Card(wrap)
        head.pack(fill="x", pady=(0, 14))
        top = tk.Frame(head.inner, bg=T.BG_CARD)
        top.pack(fill="x")
        W.section_title(top, "隔离区", T.BG_CARD).pack(side="left")
        self._count = tk.Label(top, text="", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                               font=T.font(10))
        self._count.pack(side="left", padx=(10, 0))

        btns = tk.Frame(top, bg=T.BG_CARD)
        btns.pack(side="right")
        W.button(btns, "刷新", self.refresh, "ghost").pack(side="left")
        W.button(btns, "全部还原", self._restore_all, "ghost").pack(side="left",
                                                                padx=(8, 0))
        W.button(btns, "全部删除", self._delete_all, "danger").pack(side="left",
                                                                 padx=(8, 0))

        W.muted_label(head.inner,
                      "隔离文件保存在 %LOCALAPPDATA%\\Andun\\data\\quarantine，"
                      "内容经异或混淆，还原时会恢复原始路径。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(10, 0))

        self._list_card = W.Card(wrap)
        self._list_card.pack(fill="both", expand=True)
        self._list_host = self._list_card.inner
        self._render_empty()

    # ── 渲染 ──

    def _render_empty(self, title: str = "隔离区为空", hint: str = "被隔离的文件会显示在这里"):
        for child in self._list_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        W.EmptyHint(self._list_host, title, hint, T.BG_CARD, "▣").pack(fill="both",
                                                                     expand=True)

    def on_show(self):
        self.refresh()

    def on_hide(self):
        self.cancel_timers()

    def refresh(self):
        run_async(self, self.client.quarantine_list, self._apply,
                  lambda exc: self.ctx.say(f"读取隔离区失败: {exc}", "error"))

    def _apply(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self._count.configure(text="")
            self._render_empty("无法读取隔离区", res.error or "后端未连接")
            return

        items = res.data.get("items") or []
        total = res.data.get("total", len(items))
        self._count.configure(text=f"共 {fmt_int(total)} 个文件")

        if not items:
            self._render_empty()
            return

        for child in self._list_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        for item in items:
            if isinstance(item, dict):
                self._row(item)

    def _row(self, item: dict):
        qid = str(item.get("id") or "")
        level = str(item.get("threat_level") or "medium").lower()
        color = LEVEL_FG.get(level, T.TEXT_SECONDARY)

        row = tk.Frame(self._list_host, bg=T.BG_HOVER)
        row.pack(fill="x", pady=3)
        pad = tk.Frame(row, bg=T.BG_HOVER)
        pad.pack(fill="x", padx=12, pady=9)

        top = tk.Frame(pad, bg=T.BG_HOVER)
        top.pack(fill="x")
        tk.Label(top, text="●", bg=T.BG_HOVER, fg=color,
                 font=T.font(10)).pack(side="left")
        tk.Label(top, text=str(item.get("threat_name") or "未知威胁"),
                 bg=T.BG_HOVER, fg=T.TEXT_PRIMARY,
                 font=T.font(10, "bold")).pack(side="left", padx=(6, 0))
        tk.Label(top, text=f"[{level}]", bg=T.BG_HOVER, fg=T.TEXT_MUTED,
                 font=T.font(9)).pack(side="left", padx=(8, 0))
        tk.Label(top, text=fmt_size(item.get("file_size")), bg=T.BG_HOVER,
                 fg=T.TEXT_MUTED, font=T.font(9)).pack(side="left", padx=(8, 0))
        tk.Label(top, text=fmt_time(item.get("quarantined_at")), bg=T.BG_HOVER,
                 fg=T.TEXT_MUTED, font=T.font(9)).pack(side="left", padx=(8, 0))
        if not item.get("file_exists", True):
            tk.Label(top, text="文件缺失", bg=T.BG_HOVER, fg=T.DANGER,
                     font=T.font(9, "bold")).pack(side="left", padx=(8, 0))

        actions = tk.Frame(top, bg=T.BG_HOVER)
        actions.pack(side="right")
        W.button(actions, "还原", lambda q=qid: self._restore(q), "ghost").pack(
            side="left")
        W.button(actions, "这是误报",
                 lambda q=qid, it=item: self._report_fp(q, it),
                 "ghost").pack(side="left", padx=(6, 0))
        W.button(actions, "删除", lambda q=qid: self._delete(q), "danger").pack(
            side="left", padx=(6, 0))

        path = str(item.get("original_path") or "")
        if len(path) > 110:
            path = "…" + path[-109:]
        W.muted_label(pad, path or "（原始路径未知）", T.BG_HOVER, size=9,
                      mono=True).pack(fill="x", pady=(5, 0))

        sha = item.get("file_hash") or ""
        if sha:
            W.muted_label(pad, f"哈希 {short_hash(sha, 40)}", T.BG_HOVER, size=8,
                          mono=True, fg=T.TEXT_MUTED).pack(fill="x")

    # ── 动作 ──

    def _report_fp(self, qid: str, item: dict):
        """上报「这是误报」。

        这不是给用户的安慰按钮 —— 上报的记录会带上隔离当时的完整上下文
        （目录类别、是否系统路径、扩展名、哪个威胁名/等级），
        汇总后用来复核 YARA 规则的「有效鉴别力」：哪些规则专挑系统文件下手。
        """
        if not qid:
            return
        name = str(item.get("threat_name") or "未知威胁")
        path = str(item.get("original_path") or "（原始路径未知）")
        if not messagebox.askyesno(
                "上报误报",
                "确认把这条判定上报为误报吗？\n\n"
                f"威胁名：{name}\n"
                f"文件：{path}\n\n"
                "上报内容：隔离记录 + 文件所在目录类别 + 扩展名 + 大小。\n"
                "**不会上传文件内容。**\n\n"
                "上报后建议再点「还原」把文件取回来。",
                parent=self):
            return

        def done(res):
            if res is None or not res.ok:
                self.ctx.say(
                    f"误报上报失败：{res.error if res else '无响应'}", "error")
                return
            d = res.data if isinstance(res.data, dict) else {}
            cat = d.get("dir_category") or "?"
            sysflag = "系统目录" if d.get("is_system_path") else cat
            self.ctx.say(f"已上报误报（{sysflag}）—— 用于改进规则鉴别力", "ok")

        run_async(self, lambda: self.client.quarantine_report_fp(qid), done)

    def _restore(self, qid: str):
        if not qid:
            return

        def done(res):
            data = res.data if isinstance(res.data, dict) else {}
            if res.ok and data.get("success", res.ok):
                self.ctx.say("已还原该文件", "ok")
            else:
                self.ctx.say(f"还原失败: {data.get('error') or res.error}", "error")
            self.refresh()

        run_async(self, lambda: self.client.quarantine_restore(qid), done)

    def _delete(self, qid: str):
        if not qid:
            return
        if not messagebox.askyesno("确认删除",
                                   "永久删除该隔离文件？此操作不可撤销。",
                                   parent=self.winfo_toplevel()):
            return

        def done(res):
            data = res.data if isinstance(res.data, dict) else {}
            if res.ok and data.get("success", res.ok):
                self.ctx.say("已永久删除", "ok")
            else:
                self.ctx.say(f"删除失败: {data.get('error') or res.error}", "error")
            self.refresh()

        run_async(self, lambda: self.client.quarantine_delete(qid), done)

    def _restore_all(self):
        if not messagebox.askyesno("确认还原",
                                   "还原隔离区内所有文件到原始路径？",
                                   parent=self.winfo_toplevel()):
            return

        def done(res):
            data = res.data if isinstance(res.data, dict) else {}
            if res.ok:
                self.ctx.say(f"已还原 {data.get('restored', 0)}/"
                             f"{data.get('total', 0)} 个文件", "ok")
            else:
                self.ctx.say(f"批量还原失败: {res.error}", "error")
            self.refresh()

        run_async(self, self.client.quarantine_restore_all, done)

    def _delete_all(self):
        if not messagebox.askyesno(
                "确认删除",
                "永久删除隔离区内所有文件？此操作不可撤销，"
                "删除后将无法再还原这些样本。", parent=self.winfo_toplevel()):
            return

        def done(res):
            data = res.data if isinstance(res.data, dict) else {}
            if res.ok:
                self.ctx.say(f"已删除 {data.get('deleted', data.get('total', 0))} 个文件",
                             "ok")
            else:
                self.ctx.say(f"批量删除失败: {res.error}", "error")
            self.refresh()

        run_async(self, self.client.quarantine_delete_all, done)
