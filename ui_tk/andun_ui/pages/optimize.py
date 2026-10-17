"""电脑优化页：系统体检 + 启动项管理 + 服务启动类型 + 内存释放 + 一键优化。

后端契约（app.py / system_optimizer.py）：
* ``GET  /api/v1/optimize/overview`` → ``{score, checks[{id,name,status,detail}],
  disk{}, memory{}, temp{}, startup_count, pending_reboot}``
* ``GET  /api/v1/optimize/startup``  → ``{items[{item_id,type,name,source,status,detail}]}``
* ``POST /api/v1/optimize/startup/toggle`` body ``{item_id, action: disable|enable}``
* ``GET  /api/v1/optimize/services`` → ``{readonly[], manageable[],
  readonly_count, manageable_count}``，条目 ``{name,display,state,start_type,image_path}``
* ``POST /api/v1/optimize/services/toggle`` body ``{name, action: auto|manual|disabled}``
* ``POST /api/v1/optimize/memory``     → ``{success, released_bytes, released_text, processed}``
* ``POST /api/v1/optimize/one-click``  → ``{success, clean{}, memory{}, recommendations[]}``

注意：**只有 manageable 里的第三方服务可改**，系统服务由后端拒绝
（``系统关键服务不可修改``）。UI 里系统服务只读展示，不显示修改按钮。
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from .. import theme as T
from .. import widgets as W
from ..api import fmt_int, fmt_size, run_async
from ..app import Page

CHECK_FG = {"ok": T.SUCCESS, "warn": T.WARNING, "danger": T.DANGER}
CHECK_TEXT = {"ok": "正常", "warn": "注意", "danger": "严重"}

SERVICE_ACTIONS = (("auto", "自动"), ("manual", "手动"), ("disabled", "禁用"))

# 服务列表可能几百条，先渲染这么多，其余用"展开更多"按钮
SERVICE_PAGE = 40


class OptimizePage(Page):
    key = "optimize"
    title = "电脑优化"
    glyph = "⚡"

    def build(self):
        self._service_offset = 0
        self._manageable: list[dict] = []

        root = W.ScrollableFrame(self, bg=T.BG_APP)
        root.pack(fill="both", expand=True)
        pad = tk.Frame(root.content, bg=T.BG_APP)
        pad.pack(fill="both", expand=True, padx=22, pady=18)

        self._build_score(pad)
        self._build_quick_actions(pad)
        self._build_startup(pad)
        self._build_services(pad)

    # ── 体检 ──

    def _build_score(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        inner = card.inner

        left = tk.Frame(inner, bg=T.BG_CARD)
        left.pack(side="left", padx=(4, 20))
        self._score = tk.Label(left, text="--", bg=T.BG_CARD, fg=T.ACCENT,
                               font=T.font(40, "bold"))
        self._score.pack()
        tk.Label(left, text="健康评分", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(9)).pack()

        right = tk.Frame(inner, bg=T.BG_CARD)
        right.pack(side="left", fill="both", expand=True)
        head = tk.Frame(right, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "系统体检", T.BG_CARD).pack(side="left")
        W.button(head, "重新体检", self.refresh_overview, "ghost").pack(side="right")
        self._checks_host = tk.Frame(right, bg=T.BG_CARD)
        self._checks_host.pack(fill="x", pady=(8, 0))
        W.muted_label(self._checks_host, "点「重新体检」开始", T.BG_CARD,
                      size=9).pack(anchor="w")

    def refresh_overview(self):
        run_async(self, self.client.optimize_overview, self._apply_overview,
                  lambda exc: self.ctx.say(f"体检失败: {exc}", "error"))

    def _apply_overview(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self._score.configure(text="--", fg=T.TEXT_MUTED)
            return
        d = res.data
        if d.get("cancelled"):
            return
        try:
            score = int(d.get("score") or 0)
        except (TypeError, ValueError):
            score = 0
        color = (T.SUCCESS if score >= 85 else
                 T.WARNING if score >= 60 else T.DANGER)
        self._score.configure(text=str(score), fg=color)

        for child in self._checks_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass

        checks = d.get("checks") or []
        if not checks:
            W.muted_label(self._checks_host, "无体检项", T.BG_CARD,
                          size=9).pack(anchor="w")
            return
        for item in checks:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or "").lower()
            row = tk.Frame(self._checks_host, bg=T.BG_CARD)
            row.pack(fill="x", pady=2)
            tk.Label(row, text="●", bg=T.BG_CARD,
                     fg=CHECK_FG.get(status, T.TEXT_MUTED),
                     font=T.font(10)).pack(side="left")
            tk.Label(row, text=str(item.get("name") or ""), bg=T.BG_CARD,
                     fg=T.TEXT_PRIMARY, font=T.font(10), width=10,
                     anchor="w").pack(side="left", padx=(6, 0))
            tk.Label(row, text=CHECK_TEXT.get(status, status), bg=T.BG_CARD,
                     fg=CHECK_FG.get(status, T.TEXT_MUTED),
                     font=T.font(9, "bold"), width=5,
                     anchor="w").pack(side="left")
            detail = str(item.get("detail") or "")
            if len(detail) > 76:
                detail = detail[:75] + "…"
            tk.Label(row, text=detail, bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                     font=T.font(9), anchor="w").pack(side="left", padx=(6, 0))

    # ── 快速动作 ──

    def _build_quick_actions(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "快速优化", T.BG_CARD).pack(anchor="w")
        W.muted_label(card.inner,
                      "一键优化 = 临时垃圾清理 + 内存释放 + 启动项建议。"
                      "内存释放通过收缩进程工作集实现，不结束任何进程。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))
        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x")
        self._btn_oneclick = W.button(row, "一键优化", self._one_click)
        self._btn_oneclick.pack(side="left")
        self._btn_memory = W.button(row, "释放内存", self._release_memory, "ghost")
        self._btn_memory.pack(side="left", padx=(8, 0))
        self._quick_result = tk.Label(card.inner, text="", bg=T.BG_CARD,
                                      fg=T.TEXT_SECONDARY, font=T.font(10),
                                      anchor="w", justify="left", wraplength=760)
        self._quick_result.pack(fill="x", pady=(10, 0))

    def _one_click(self):
        self._quick_result.configure(text="正在优化…", fg=T.TEXT_SECONDARY)
        self._set_quick_busy(True)

        def done(res):
            self._set_quick_busy(False)
            if not res.ok or not isinstance(res.data, dict):
                self._quick_result.configure(text=f"优化失败：{res.error}",
                                             fg=T.DANGER)
                return
            d = res.data
            clean = d.get("clean") if isinstance(d.get("clean"), dict) else {}
            mem = d.get("memory") if isinstance(d.get("memory"), dict) else {}
            recs = d.get("recommendations") or []
            lines = [
                f"垃圾清理　释放 {clean.get('freed_text') or fmt_size(clean.get('freed_bytes'))}"
                f"（{fmt_int(clean.get('cleaned_files'))} 个文件）",
                f"内存释放　回收 {mem.get('released_text') or fmt_size(mem.get('released_bytes'))}"
                f"（处理 {fmt_int(mem.get('processed'))} 个进程）",
            ]
            if recs:
                lines.append("建议：")
                for r in recs[:8]:
                    lines.append(f"· {r}")
            self._quick_result.configure(text="\n".join(lines), fg=T.TEXT_PRIMARY)
            self.ctx.say("一键优化完成", "ok")
            self.refresh_overview()
            self._load_startup()

        run_async(self, self.client.optimize_one_click, done)

    def _release_memory(self):
        self._quick_result.configure(text="正在释放内存…", fg=T.TEXT_SECONDARY)
        self._set_quick_busy(True)

        def done(res):
            self._set_quick_busy(False)
            if not res.ok or not isinstance(res.data, dict):
                self._quick_result.configure(text=f"释放失败：{res.error}", fg=T.DANGER)
                return
            d = res.data
            if not d.get("success"):
                self._quick_result.configure(
                    text=f"释放失败：{d.get('error') or '未知原因'}", fg=T.DANGER)
                return
            text = (f"已收缩 {fmt_int(d.get('processed'))} 个进程工作集，"
                    f"回收 {d.get('released_text') or fmt_size(d.get('released_bytes'))}")
            self._quick_result.configure(text=text, fg=T.TEXT_PRIMARY)
            self.ctx.say(text, "ok")

        run_async(self, self.client.optimize_memory, done)

    def _set_quick_busy(self, busy: bool):
        for btn in (self._btn_oneclick, self._btn_memory):
            try:
                if busy:
                    btn.configure(state="disabled", bg=T.BORDER, fg=T.TEXT_MUTED)
                else:
                    btn.configure(state="normal")
            except tk.TclError:
                pass
        try:
            if not busy:
                self._btn_oneclick.configure(bg=T.ACCENT, fg=T.TEXT_ON_ACCENT)
                self._btn_memory.configure(bg=T.BG_HOVER, fg=T.TEXT_PRIMARY)
        except tk.TclError:
            pass

    # ── 启动项 ──

    def _build_startup(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "启动项", T.BG_CARD).pack(side="left")
        self._startup_count = tk.Label(head, text="", bg=T.BG_CARD,
                                       fg=T.TEXT_SECONDARY, font=T.font(9))
        self._startup_count.pack(side="left", padx=(10, 0))
        W.button(head, "刷新", self._load_startup, "ghost").pack(side="right")
        W.muted_label(card.inner,
                      "禁用是可逆的：原值会备份，随时可以「启用」还原。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))
        self._startup_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._startup_host.pack(fill="x")

    def _load_startup(self):
        run_async(self, self.client.optimize_startup, self._apply_startup)

    def _apply_startup(self, res):
        for child in self._startup_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._startup_host, "无法读取启动项", T.BG_CARD,
                          size=9, fg=T.DANGER).pack(anchor="w")
            return
        items = res.data.get("items") or []
        enabled = sum(1 for i in items
                      if isinstance(i, dict) and i.get("status") == "enabled")
        self._startup_count.configure(text=f"启用 {enabled} / 共 {len(items)}")
        if not items:
            W.muted_label(self._startup_host, "未发现启动项", T.BG_CARD,
                          size=9).pack(anchor="w")
            return
        for item in items:
            if isinstance(item, dict):
                self._startup_row(item)

    def _startup_row(self, item: dict):
        item_id = str(item.get("item_id") or "")
        status = str(item.get("status") or "enabled")
        is_disabled = status == "disabled"

        row = tk.Frame(self._startup_host, bg=T.BG_CARD)
        row.pack(fill="x", pady=2)
        dot = tk.Label(row, text="●", bg=T.BG_CARD,
                       fg=T.TEXT_MUTED if is_disabled else T.SUCCESS,
                       font=T.font(9))
        dot.pack(side="left")
        box = tk.Frame(row, bg=T.BG_CARD)
        box.pack(side="left", fill="x", expand=True, padx=(6, 8))
        name = str(item.get("name") or "")
        tk.Label(box, text=name if len(name) <= 60 else name[:59] + "…",
                 bg=T.BG_CARD, fg=T.TEXT_PRIMARY if not is_disabled else T.TEXT_MUTED,
                 font=T.font(10), anchor="w").pack(fill="x")
        src = str(item.get("source") or item.get("detail") or "")
        if len(src) > 88:
            src = "…" + src[-87:]
        tk.Label(box, text=src, bg=T.BG_CARD, fg=T.TEXT_MUTED,
                 font=T.mono(8), anchor="w").pack(fill="x")

        action = "enable" if is_disabled else "disable"
        label = "启用" if is_disabled else "禁用"
        W.button(row, label,
                 lambda i=item_id, a=action: self._toggle_startup(i, a, name),
                 "ghost" if is_disabled else "danger").pack(side="right")

    def _toggle_startup(self, item_id: str, action: str, name: str):
        if not item_id:
            return
        if action == "disable" and not messagebox.askyesno(
                "确认禁用",
                f"禁用启动项「{name}」？\n\n原值会被备份，可随时启用还原。",
                parent=self.winfo_toplevel()):
            return

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self.ctx.say(f"操作失败：{res.error}", "error")
                return
            d = res.data
            if d.get("success"):
                self.ctx.say(str(d.get("message") or "操作完成"), "ok")
            else:
                self.ctx.say(f"操作失败：{d.get('error') or '未知原因'}", "error")
            self._load_startup()

        run_async(self, lambda: self.client.optimize_startup_toggle(item_id, action),
                  done)

    # ── 服务 ──

    def _build_services(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 8))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "第三方服务", T.BG_CARD).pack(side="left")
        self._service_count = tk.Label(head, text="", bg=T.BG_CARD,
                                       fg=T.TEXT_SECONDARY, font=T.font(9))
        self._service_count.pack(side="left", padx=(10, 0))
        W.button(head, "刷新", self._load_services, "ghost").pack(side="right")
        W.muted_label(card.inner,
                      "只列出可管理的第三方服务；系统服务由后端拒绝修改，"
                      "因此这里不展示。改成「禁用」会停止该服务自启。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))
        self._service_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._service_host.pack(fill="x")
        self._service_more = W.button(card.inner, "显示更多…",
                                      self._show_more_services, "ghost")

    def _load_services(self):
        run_async(self, self.client.optimize_services, self._apply_services)

    def _apply_services(self, res):
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._service_host, "无法读取服务列表", T.BG_CARD,
                          size=9, fg=T.DANGER).pack(anchor="w")
            return
        self._manageable = [s for s in (res.data.get("manageable") or [])
                            if isinstance(s, dict)]
        self._service_count.configure(
            text=f"可管理 {fmt_int(res.data.get('manageable_count', len(self._manageable)))}"
                 f" / 系统只读 {fmt_int(res.data.get('readonly_count'))}")
        self._service_offset = 0
        self._render_services()

    def _render_services(self):
        for child in self._service_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        end = self._service_offset + SERVICE_PAGE
        for svc in self._manageable[self._service_offset:end]:
            self._service_row(svc)
        self._service_offset = min(end, len(self._manageable))

        try:
            if self._service_offset < len(self._manageable):
                self._service_more.pack(anchor="w", pady=(8, 0))
            else:
                self._service_more.pack_forget()
        except tk.TclError:
            pass

    def _show_more_services(self):
        self._render_services()

    def _service_row(self, svc: dict):
        name = str(svc.get("name") or "")
        start_type = str(svc.get("start_type") or "").lower()

        row = tk.Frame(self._service_host, bg=T.BG_CARD)
        row.pack(fill="x", pady=2)
        box = tk.Frame(row, bg=T.BG_CARD)
        box.pack(side="left", fill="x", expand=True)
        display = str(svc.get("display") or name)
        tk.Label(box, text=display if len(display) <= 48 else display[:47] + "…",
                 bg=T.BG_CARD, fg=T.TEXT_PRIMARY, font=T.font(10),
                 anchor="w").pack(fill="x")

        state = str(svc.get("state") or "")
        detail = f"{name} · {state} · 启动类型 {start_type or '未知'}"
        tk.Label(box, text=detail, bg=T.BG_CARD, fg=T.TEXT_MUTED,
                 font=T.mono(8), anchor="w").pack(fill="x")

        # 只在第三方服务上给修改入口；已经是目标类型的按钮压暗
        btns = tk.Frame(row, bg=T.BG_CARD)
        btns.pack(side="right")
        for action, label in SERVICE_ACTIONS:
            kind = "ghost"
            btn = W.button(btns, label,
                           lambda n=name, a=action: self._toggle_service(n, a),
                           kind)
            if start_type == action:
                btn.configure(bg=T.ACCENT, fg=T.TEXT_ON_ACCENT)
            btn.pack(side="left", padx=(4, 0))

    def _toggle_service(self, name: str, action: str):
        if not name:
            return
        label = dict(SERVICE_ACTIONS).get(action, action)
        if action == "disabled" and not messagebox.askyesno(
                "确认修改服务",
                f"把服务「{name}」的启动类型改为「{label}」？\n\n"
                "禁用第三方服务可能影响对应软件的正常使用。",
                parent=self.winfo_toplevel()):
            return

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self.ctx.say(f"修改失败：{res.error}", "error")
                return
            d = res.data
            if d.get("success"):
                self.ctx.say(str(d.get("message") or f"已设置为 {label}"), "ok")
            else:
                self.ctx.say(f"修改失败：{d.get('error') or '未知原因'}", "error")
            self._load_services()

        run_async(self, lambda: self.client.optimize_service_toggle(name, action),
                  done)

    # ── 生命周期 ──

    def on_show(self):
        self.refresh_overview()
        self._load_startup()
        self._load_services()

    def on_hide(self):
        self.cancel_timers()
