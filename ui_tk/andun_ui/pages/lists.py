"""名单管理页：文件白名单（信任的文件/哈希）+ 进程黑名单/白名单。

这两套名单原先**都没有界面**：
  * ``/api/v1/whitelist``（4 条路由）是孤儿接口 —— 两个前端都没调用过
  * ``/api/v1/process-guard/lists|blacklist-add|blacklist-remove|whitelist-add``
    只在工具页里有个总开关，名单本身看不到也改不了

接口（backend/app.py）：
    GET  /api/v1/whitelist                   {paths:[{path,note,added}],
                                              hashes:[{hash,path,note,added}],
                                              processes:[], publishers:[]}
    POST /api/v1/whitelist/add               {category:"paths"|"hashes", value, note}
    POST /api/v1/whitelist/remove            {category, value}
    POST /api/v1/whitelist/check             {path, hash} -> {whitelisted}
    GET  /api/v1/process-guard/lists         {blacklist:[名字], whitelist:[名字]}
    POST /api/v1/process-guard/blacklist-add|blacklist-remove|whitelist-add|whitelist-remove  {name}

注意：``whitelist/add`` 的 ``category`` **只认 paths / hashes**，传别的值后端
会返回 ``{"error": ...}``（不是 500，所以要看 body 而不是状态码）。
"""
from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox

from .. import theme as T
from .. import widgets as W
from ..api import fmt_basename, fmt_time, run_async
from ..app import Page

REFRESH_MS = 12000


class ListsPage(Page):
    key = "lists"
    title = "名单管理"
    glyph = "☰"

    def build(self):
        root = W.ScrollableFrame(self, bg=T.BG_APP)
        root.pack(fill="both", expand=True)
        pad = tk.Frame(root.content, bg=T.BG_APP)
        pad.pack(fill="both", expand=True, padx=22, pady=18)
        self._scroll = root

        self._wl = {"paths": [], "hashes": []}
        self._proc = {"blacklist": [], "whitelist": []}

        self._build_whitelist(pad)
        self._build_process(pad)

    # ══ 文件白名单 ══

    def _build_whitelist(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "文件白名单（信任的文件）", T.BG_CARD).pack(side="left")
        self._wl_tag = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                                font=T.font(10))
        self._wl_tag.pack(side="left", padx=(10, 0))
        W.button(head, "刷新", self._load_whitelist, "ghost").pack(side="right")

        W.muted_label(
            card.inner,
            "白名单里的文件**不再被判为威胁**。按路径信任只认那一个位置；"
            "按哈希信任则换目录、改名都一样放行（哈希由后端计算）。",
            T.BG_CARD, size=9).pack(fill="x", pady=(8, 10))

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x")
        W.button(row, "信任文件（按路径）…",
                 lambda: self._pick_trust("paths")).pack(side="left")
        W.button(row, "信任文件（按哈希）…",
                 lambda: self._pick_trust("hashes"), "ghost").pack(side="left",
                                                                   padx=(8, 0))

        row2 = tk.Frame(card.inner, bg=T.BG_CARD)
        row2.pack(fill="x", pady=(8, 0))
        self._path_entry = tk.Entry(row2, bg=T.BG_INPUT, fg=T.TEXT_PRIMARY,
                                    insertbackground=T.TEXT_PRIMARY,
                                    relief="flat", font=T.mono(9))
        self._path_entry.pack(side="left", fill="x", expand=True, ipady=4)
        W.button(row2, "手工添加此路径", self._add_path_manual, "ghost").pack(
            side="left", padx=(8, 0))

        self._wl_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._wl_host.pack(fill="x", pady=(10, 0))

    def _pick_trust(self, category: str):
        try:
            path = filedialog.askopenfilename(
                title=("选择要按路径信任的文件" if category == "paths"
                       else "选择要按哈希信任的文件"))
        except Exception as exc:
            self.ctx.say(f"打开文件选择器失败：{exc}", "error")
            return
        if path:
            self._trust(category, path)

    def _add_path_manual(self):
        value = self._path_entry.get().strip()
        if not value:
            self.ctx.say("请先填一个路径", "warn")
            return
        self._trust("paths", value)

    def _trust(self, category: str, value: str):
        def done(res):
            if res is None or not res.ok:
                self.ctx.say(f"加入白名单失败：{res.error if res else '无响应'}",
                             "error")
                return
            # add 的失败是以 {"error": ...} 放在 body 里的，不是 HTTP 错误码，
            # 所以这里还要再看一眼 body。
            data = res.data if isinstance(res.data, dict) else {}
            if data.get("error"):
                self.ctx.say(f"加入白名单失败：{data['error']}", "error")
                return
            self.ctx.say("已加入白名单", "ok")
            if category == "paths":
                self._path_entry.delete(0, "end")
            self._load_whitelist()
        run_async(self, lambda: self.client.whitelist_add(category, value), done)

    def _load_whitelist(self):
        def done(res):
            if res is None or not res.ok or not isinstance(res.data, dict):
                self._wl_tag.configure(text="读取失败", fg=T.DANGER)
                return
            d = res.data
            self._wl = {
                "paths": d.get("paths") if isinstance(d.get("paths"), list) else [],
                "hashes": d.get("hashes") if isinstance(d.get("hashes"), list) else [],
            }
            n = len(self._wl["paths"]) + len(self._wl["hashes"])
            self._wl_tag.configure(text=f"{n} 项", fg=T.TEXT_SECONDARY)
            self._render_whitelist()
        run_async(self, self.client.whitelist, done)

    def _render_whitelist(self):
        for child in self._wl_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        total = 0
        for entry in self._wl["paths"][:40]:
            if not isinstance(entry, dict):
                continue
            path = entry.get("path") or ""
            self._wl_row(path, entry.get("note") or "", "paths", path)
            total += 1
        for entry in self._wl["hashes"][:40]:
            if not isinstance(entry, dict):
                continue
            h = entry.get("hash") or ""
            path = entry.get("path") or ""
            label = f"{h[:16]}…　{fmt_basename(path, 40)}" if h else fmt_basename(path, 56)
            self._wl_row(label, entry.get("note") or "", "hashes", h or path)
            total += 1
        if not total:
            W.muted_label(self._wl_host, "白名单为空。", T.BG_CARD,
                          size=9).pack(anchor="w")

    def _wl_row(self, label: str, note: str, category: str, value: str):
        row = tk.Frame(self._wl_host, bg=T.BG_HOVER)
        row.pack(fill="x", pady=2)
        box = tk.Frame(row, bg=T.BG_HOVER)
        box.pack(side="left", fill="x", expand=True, padx=8, pady=5)
        tk.Label(box, text=label, bg=T.BG_HOVER, fg=T.TEXT_PRIMARY, font=T.mono(9),
                 anchor="w").pack(fill="x")
        if note:
            tk.Label(box, text=note, bg=T.BG_HOVER, fg=T.TEXT_MUTED,
                     font=T.font(9), anchor="w").pack(fill="x")
        W.button(row, "移除",
                 lambda c=category, v=value, l=label: self._remove_wl(c, v, l),
                 "ghost").pack(side="right", padx=6)

    def _remove_wl(self, category: str, value: str, label: str):
        if not messagebox.askyesno("确认移除",
                                   f"从白名单移除这一项？\n\n{label}",
                                   parent=self):
            return

        def done(res):
            if res is None or not res.ok:
                self.ctx.say(f"移除失败：{res.error if res else '无响应'}", "error")
                return
            self.ctx.say("已移除", "ok")
            self._load_whitelist()
        run_async(self, lambda: self.client.whitelist_remove(category, value), done)

    # ══ 进程黑白名单 ══

    def _build_process(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "进程黑名单 / 白名单", T.BG_CARD).pack(side="left")
        self._proc_tag = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                                  font=T.font(10))
        self._proc_tag.pack(side="left", padx=(10, 0))
        W.button(head, "刷新", self._load_process, "ghost").pack(side="right")

        W.muted_label(
            card.inner,
            "填**进程名**（如 notepad.exe），不是完整路径。黑名单=拦截该进程，"
            "白名单=放行。两边互斥：加进一边会自动从另一边摘掉。",
            T.BG_CARD, size=9).pack(fill="x", pady=(8, 10))

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x")
        self._proc_entry = tk.Entry(row, bg=T.BG_INPUT, fg=T.TEXT_PRIMARY,
                                    insertbackground=T.TEXT_PRIMARY,
                                    relief="flat", font=T.mono(9))
        self._proc_entry.pack(side="left", fill="x", expand=True, ipady=4)
        W.button(row, "加入黑名单", lambda: self._proc_change("blacklist"), "danger").pack(
            side="left", padx=(8, 0))
        W.button(row, "加入白名单", lambda: self._proc_change("whitelist"), "ghost").pack(
            side="left", padx=(8, 0))

        cols = tk.Frame(card.inner, bg=T.BG_CARD)
        cols.pack(fill="x", pady=(12, 0))
        self._black_col = self._proc_column(cols, "黑名单（拦截）", T.DANGER)
        self._white_col = self._proc_column(cols, "白名单（放行）", T.SUCCESS)

    def _proc_column(self, parent, title: str, color: str):
        col = tk.Frame(parent, bg=T.BG_CARD)
        col.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(col, text=title, bg=T.BG_CARD, fg=color,
                 font=T.font(10, "bold"), anchor="w").pack(fill="x")
        host = tk.Frame(col, bg=T.BG_CARD)
        host.pack(fill="x", pady=(6, 0))
        return host

    def _proc_change(self, target: str):
        name = self._proc_entry.get().strip()
        if not name:
            self.ctx.say("请先填进程名，例如 notepad.exe", "warn")
            return
        call = (self.client.process_blacklist_add if target == "blacklist"
                else self.client.process_whitelist_add)

        def done(res):
            if res is None or not res.ok:
                self.ctx.say(f"添加失败：{res.error if res else '无响应'}", "error")
                return
            self.ctx.say(("已加入黑名单" if target == "blacklist" else "已加入白名单"),
                         "ok")
            self._proc_entry.delete(0, "end")
            self._load_process()
        run_async(self, lambda: call(name), done)

    def _load_process(self):
        def done(res):
            if res is None or not res.ok or not isinstance(res.data, dict):
                self._proc_tag.configure(text="读取失败", fg=T.DANGER)
                return
            d = res.data
            self._proc = {
                "blacklist": d.get("blacklist") if isinstance(d.get("blacklist"), list) else [],
                "whitelist": d.get("whitelist") if isinstance(d.get("whitelist"), list) else [],
            }
            self._proc_tag.configure(
                text=f"黑 {len(self._proc['blacklist'])} / 白 {len(self._proc['whitelist'])}",
                fg=T.TEXT_SECONDARY)
            self._render_process()
        run_async(self, self.client.process_lists, done)

    def _render_process(self):
        for host, key in ((self._black_col, "blacklist"), (self._white_col, "whitelist")):
            for child in host.winfo_children():
                try:
                    child.destroy()
                except Exception:
                    pass
            names = self._proc[key]
            if not names:
                W.muted_label(host, "（空）", T.BG_CARD, size=9).pack(anchor="w")
                continue
            for name in names[:40]:
                row = tk.Frame(host, bg=T.BG_HOVER)
                row.pack(fill="x", pady=2)
                tk.Label(row, text=str(name), bg=T.BG_HOVER, fg=T.TEXT_PRIMARY,
                         font=T.mono(9), anchor="w").pack(side="left", padx=8, pady=4)
                W.button(row, "移除",
                         lambda n=name, k=key: self._proc_remove(k, n),
                         "ghost").pack(side="right", padx=4)

    def _proc_remove(self, key: str, name: str):
        call = (self.client.process_blacklist_remove if key == "blacklist"
                else self.client.process_whitelist_remove)

        def done(res):
            if res is None or not res.ok:
                self.ctx.say(f"移除失败：{res.error if res else '无响应'}", "error")
                return
            self.ctx.say("已移除", "ok")
            self._load_process()
        run_async(self, lambda: call(name), done)

    # ══ 生命周期 ══

    def refresh(self):
        self._load_whitelist()
        self._load_process()

    def on_show(self):
        self.refresh()
        self.every(REFRESH_MS, self.refresh)

    def on_hide(self):
        self.cancel_timers()
