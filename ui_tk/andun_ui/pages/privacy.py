"""隐私防护页：隐私痕迹扫描/清理、敏感文件管理、敏感文件访问记录。

**开关不在这里。** 隐私保护的开关已经在「安全工具 → 增强防护 → 隐私保护」
那张卡片里（见 ``pages/tools.py`` 的 ``_guard_rows``）。本页不重复做开关，
只把开关背后的**操作**露出来 —— 否则这几个接口就永远没有入口：

    GET  /api/v1/privacy/stats                    {enabled, trace_count, trace_types[]}
    GET  /api/v1/privacy/scan                     {traces: [...], ...}
    POST /api/v1/privacy/clean                    {categories: [...]}
    GET  /api/v1/privacy/access-log               {logs: [...]}
    GET  /api/v1/privacy/sensitive-files          {files: [{path}]}
    POST /api/v1/privacy/sensitive-files          {path}
    POST /api/v1/privacy/sensitive-files/delete   {id|path}

渲染对返回结构做了防御：``traces`` / ``logs`` 的**元素形状后端没有承诺**，
所以下面按"取得到就取、取不到就退回字符串"的方式显示，不假设字段名。
"""
from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox

from .. import theme as T
from .. import widgets as W
from ..api import fmt_basename, fmt_int, fmt_time, run_async
from ..app import Page

REFRESH_MS = 8000


def _row_text(item) -> str:
    """把 traces/logs 里的一项渲染成一行文字。结构未知，逐级回退。"""
    if isinstance(item, str):
        return item
    if not isinstance(item, dict):
        return str(item)
    for key in ("detail", "path", "file", "name", "type", "action", "time"):
        val = item.get(key)
        if val:
            if key in ("path", "file"):
                return fmt_basename(val, 62)
            if key == "time":
                return f"{fmt_time(val)}　{item.get('action') or item.get('type') or ''}".rstrip()
            return str(val)
    return str(item)[:120]


class PrivacyPage(Page):
    key = "privacy"
    title = "隐私防护"
    glyph = "❖"

    def build(self):
        root = W.ScrollableFrame(self, bg=T.BG_APP)
        root.pack(fill="both", expand=True)
        pad = tk.Frame(root.content, bg=T.BG_APP)
        pad.pack(fill="both", expand=True, padx=22, pady=18)
        self._scroll = root

        self._build_overview(pad)
        self._build_traces(pad)
        self._build_sensitive(pad)
        self._build_access(pad)

    # ── 概览 ──

    def _build_overview(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "隐私防护", T.BG_CARD).pack(side="left")
        self._state_tag = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                                   font=T.font(10, "bold"))
        self._state_tag.pack(side="left", padx=(10, 0))
        W.button(head, "刷新", self.refresh, "ghost").pack(side="right")

        self.kv_traces = W.KeyValueRow(card.inner, "隐私痕迹")
        self.kv_types = W.KeyValueRow(card.inner, "痕迹类型")
        for row in (self.kv_traces, self.kv_types):
            row.pack(fill="x", pady=3)

        W.muted_label(
            card.inner,
            "开关在「安全工具 → 增强防护 → 隐私保护」那张卡片里，本页不重复做开关；"
            "这里只做开关背后的操作。",
            T.BG_CARD, size=9).pack(fill="x", pady=(8, 0))

    # ── 痕迹扫描 / 清理 ──

    def _build_traces(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "隐私痕迹", T.BG_CARD).pack(side="left")
        self._trace_tag = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                                   font=T.font(10))
        self._trace_tag.pack(side="left", padx=(10, 0))
        btns = tk.Frame(head, bg=T.BG_CARD)
        btns.pack(side="right")
        self._scan_btn = W.button(btns, "扫描痕迹", self._scan, "accent")
        self._scan_btn.pack(side="left")
        self._clean_btn = W.button(btns, "清理痕迹", self._clean, "danger")
        self._clean_btn.pack(side="left", padx=(8, 0))

        self._trace_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._trace_host.pack(fill="x", pady=(10, 0))
        self._trace_empty = W.muted_label(
            self._trace_host, "点「扫描痕迹」看看当前有多少隐私残留。",
            T.BG_CARD, size=9)
        self._trace_empty.pack(anchor="w")

    def _scan(self):
        self._scan_btn.configure(state="disabled", text="扫描中…")

        def done(res):
            self._scan_btn.configure(state="normal", text="扫描痕迹")
            if res is None or not res.ok or not isinstance(res.data, dict):
                self._trace_tag.configure(text="扫描失败", fg=T.DANGER)
                self.ctx.say(f"隐私痕迹扫描失败：{res.error if res else '无响应'}",
                             "error")
                return
            d = res.data
            # 后端可能把结果放在 traces / trace_types / items 里，逐个试。
            items = d.get("traces")
            if not isinstance(items, list):
                items = d.get("items") if isinstance(d.get("items"), list) else []
            types = d.get("trace_types") if isinstance(d.get("trace_types"), list) else []
            self._trace_tag.configure(text=f"共 {len(items)} 项", fg=T.TEXT_SECONDARY)
            self._render_traces(items, types)
            self.ctx.say(f"隐私痕迹扫描完成：{len(items)} 项", "ok")

        run_async(self, self.client.privacy_scan, done)

    def _render_traces(self, items: list, types: list):
        for child in self._trace_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not items and not types:
            W.muted_label(self._trace_host, "没有发现隐私痕迹。", T.BG_CARD,
                          size=9).pack(anchor="w")
            return
        shown = 0
        for item in types[:12]:
            tk.Label(self._trace_host, text=f"· {_row_text(item)}", bg=T.BG_CARD,
                     fg=T.TEXT_SECONDARY, font=T.font(9), anchor="w",
                     justify="left", wraplength=820).pack(fill="x", pady=1)
            shown += 1
        for item in items[:14]:
            tk.Label(self._trace_host, text=f"· {_row_text(item)}", bg=T.BG_CARD,
                     fg=T.TEXT_SECONDARY, font=T.font(9), anchor="w",
                     justify="left", wraplength=820).pack(fill="x", pady=1)
            shown += 1
        if len(items) + len(types) > shown:
            W.muted_label(self._trace_host,
                          f"（仅显示前 {shown} 项，共 {len(items) + len(types)} 项）",
                          T.BG_CARD, size=9).pack(anchor="w", pady=(4, 0))

    def _clean(self):
        if not messagebox.askyesno(
                "确认清理",
                "将清理扫描到的隐私痕迹（浏览器缓存/最近文档/剪贴板记录等）。\n\n"
                "这一步会真正删除这些记录，确定继续吗？",
                parent=self):
            return

        def done(res):
            if res is None or not res.ok:
                self.ctx.say(f"清理失败：{res.error if res else '无响应'}", "error")
                return
            self.ctx.say("隐私痕迹已清理", "ok")
            self.refresh()
            self._scan()

        run_async(self, lambda: self.client.privacy_clean(), done)

    # ── 敏感文件 ──

    def _build_sensitive(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "受保护的敏感文件", T.BG_CARD).pack(side="left")
        self._file_tag = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                                  font=T.font(10))
        self._file_tag.pack(side="left", padx=(10, 0))
        btns = tk.Frame(head, bg=T.BG_CARD)
        btns.pack(side="right")
        W.button(btns, "添加文件…", self._add_file, "accent").pack(side="left")
        W.button(btns, "刷新", self._load_files, "ghost").pack(side="left", padx=(8, 0))

        W.muted_label(card.inner,
                      "列入清单的文件被访问时会记录下来（见下方访问记录）。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(8, 0))
        self._file_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._file_host.pack(fill="x", pady=(8, 0))

    def _load_files(self):
        def done(res):
            if res is None or not res.ok or not isinstance(res.data, dict):
                self._file_tag.configure(text="读取失败", fg=T.DANGER)
                return
            files = res.data.get("files")
            files = files if isinstance(files, list) else []
            self._file_tag.configure(text=f"{len(files)} 个", fg=T.TEXT_SECONDARY)
            self._render_files(files)
        run_async(self, self.client.privacy_sensitive_files, done)

    def _render_files(self, files: list):
        for child in self._file_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not files:
            W.muted_label(self._file_host, "还没有添加敏感文件。", T.BG_CARD,
                          size=9).pack(anchor="w")
            return
        for item in files[:30]:
            path = item.get("path") if isinstance(item, dict) else str(item)
            if not path:
                continue
            row = tk.Frame(self._file_host, bg=T.BG_HOVER)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=fmt_basename(path, 58), bg=T.BG_HOVER,
                     fg=T.TEXT_PRIMARY, font=T.font(9), anchor="w").pack(
                side="left", padx=8, pady=5)
            W.button(row, "移除", lambda p=path: self._remove_file(p), "ghost").pack(
                side="right", padx=6)

    def _add_file(self):
        try:
            path = filedialog.askopenfilename(title="选择要保护的敏感文件")
        except Exception as exc:
            self.ctx.say(f"打开文件选择器失败：{exc}", "error")
            return
        if not path:
            return

        def done(res):
            if res is None or not res.ok:
                self.ctx.say(f"添加失败：{res.error if res else '无响应'}", "error")
                return
            self.ctx.say("已加入敏感文件清单", "ok")
            self._load_files()
        run_async(self, lambda: self.client.privacy_sensitive_add(path), done)

    def _remove_file(self, path: str):
        if not messagebox.askyesno("确认移除",
                                   f"从敏感文件清单里移除？\n\n{path}",
                                   parent=self):
            return

        def done(res):
            if res is None or not res.ok:
                self.ctx.say(f"移除失败：{res.error if res else '无响应'}", "error")
                return
            self.ctx.say("已移除", "ok")
            self._load_files()
        run_async(self, lambda: self.client.privacy_sensitive_delete(path), done)

    # ── 访问记录 ──

    def _build_access(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "敏感文件访问记录", T.BG_CARD).pack(side="left")
        self._access_tag = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                                    font=T.font(10))
        self._access_tag.pack(side="left", padx=(10, 0))
        W.button(head, "刷新", self._load_access, "ghost").pack(side="right")
        self._access_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._access_host.pack(fill="x", pady=(10, 0))

    def _load_access(self):
        def done(res):
            if res is None or not res.ok or not isinstance(res.data, dict):
                self._access_tag.configure(text="读取失败", fg=T.DANGER)
                return
            logs = res.data.get("logs")
            logs = logs if isinstance(logs, list) else []
            self._access_tag.configure(text=f"{len(logs)} 条", fg=T.TEXT_SECONDARY)
            for child in self._access_host.winfo_children():
                try:
                    child.destroy()
                except Exception:
                    pass
            if not logs:
                W.muted_label(self._access_host, "暂无访问记录。", T.BG_CARD,
                              size=9).pack(anchor="w")
                return
            for item in logs[:30]:
                tk.Label(self._access_host, text=f"· {_row_text(item)}",
                         bg=T.BG_CARD, fg=T.TEXT_SECONDARY, font=T.font(9),
                         anchor="w", justify="left", wraplength=820).pack(
                    fill="x", pady=1)
        run_async(self, self.client.privacy_access_log, done)

    # ── 生命周期 ──

    def refresh(self):
        def done(res):
            d = res.data if (res is not None and res.ok and isinstance(res.data, dict)) else None
            if not d:
                self._state_tag.configure(text="读取失败", fg=T.DANGER)
                return
            on = bool(d.get("enabled"))
            self._state_tag.configure(text="已开启" if on else "已关闭",
                                      fg=T.SUCCESS if on else T.TEXT_MUTED)
            self.kv_traces.set_value(fmt_int(d.get("trace_count")))
            types = d.get("trace_types")
            n = len(types) if isinstance(types, list) else 0
            self.kv_types.set_value(fmt_int(n))
        run_async(self, self.client.privacy_stats, done)

    def on_show(self):
        self.refresh()
        self._load_files()
        self._load_access()
        self.every(REFRESH_MS, self.refresh)

    def on_hide(self):
        self.cancel_timers()
