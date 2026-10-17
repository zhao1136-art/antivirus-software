"""自定义规则页：规则列表（启停/删除）+ 新增 + 模板套用 + 导入导出。

后端契约（app.py / custom_rules.py）：
* ``GET  /api/v1/rules/list?rule_type=`` → ``{rules: [...]}``
* ``POST /api/v1/rules/add``    body ``{rule_type, action, pattern, description}``
  → ``{ok, rule}``；注意 ``rule`` 是**新建规则的 id**，参数非法时为 ``None``
* ``POST /api/v1/rules/remove`` body ``{rule_id}`` → ``{ok}``
* ``POST /api/v1/rules/toggle`` body ``{rule_id, enabled}`` → ``{ok}``
* ``GET  /api/v1/rules/templates`` → ``{templates: [...]}``
* ``GET  /api/v1/rules/export``    → ``{rules: [...]}``
* ``POST /api/v1/rules/import``    body ``{rules: [...]}`` → ``{ok}``

取值域（custom_rules.RULE_TYPES / ACTIONS）：
类型 ``file / process / registry / network / handle``，动作 ``allow / block / ask``。
规则字段 ``{id, type, action, pattern, description, enabled, created_at}``。
"""
from __future__ import annotations

import json
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox

from .. import theme as T
from .. import widgets as W
from ..api import run_async
from ..app import Page

TYPE_LABELS = {
    "file": "文件",
    "process": "进程",
    "registry": "注册表",
    "network": "网络",
    "handle": "句柄",
}
ACTION_LABELS = {"allow": "允许", "block": "阻止", "ask": "询问"}
ACTION_FG = {"allow": T.SUCCESS, "block": T.DANGER, "ask": T.WARNING}

TYPE_VALUES = tuple(TYPE_LABELS.keys())
ACTION_VALUES = tuple(ACTION_LABELS.keys())


def _fmt_created(value) -> str:
    """``created_at`` 是 ``time.time()`` 的浮点秒，不是 ISO 串。

    直接喂给 ``fmt_time()``（按 ISO 解析）会原样吐出一串 epoch 数字，
    所以这里先按数值时间戳转本地时间。
    """
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value)).strftime("%m-%d %H:%M")
        text = str(value)
        if text.replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(text)).strftime("%m-%d %H:%M")
        return text[:16]
    except (ValueError, OSError, OverflowError):
        return str(value)[:16]


def dark_option(parent, variable, values, labels, width=10):
    """深色下拉框。

    ``tk.OptionMenu`` 的弹出菜单是独立的 ``Menu``，必须单独设色，
    否则会在暗色界面里弹出一个亮色菜单。
    """
    menu = tk.Menu(parent, tearoff=0, bg=T.BG_CARD, fg=T.TEXT_PRIMARY,
                   activebackground=T.ACCENT, activeforeground=T.TEXT_ON_ACCENT,
                   bd=0, relief="flat")
    for value in values:
        menu.add_command(label=labels.get(value, value),
                         command=lambda v=value: variable.set(v))
    btn = tk.Menubutton(parent, textvariable=variable, menu=menu, width=width,
                        bg=T.BG_INPUT, fg=T.TEXT_PRIMARY,
                        activebackground=T.BG_HOVER, activeforeground=T.TEXT_PRIMARY,
                        relief="flat", bd=0, highlightthickness=1,
                        highlightbackground=T.BORDER, font=T.font(10),
                        cursor="hand2", padx=8, pady=4, anchor="w")
    return btn


class RulesPage(Page):
    key = "rules"
    title = "规则管理"
    glyph = "✓"

    def build(self):
        self._rules: list[dict] = []

        root = W.ScrollableFrame(self, bg=T.BG_APP)
        root.pack(fill="both", expand=True)
        pad = tk.Frame(root.content, bg=T.BG_APP)
        pad.pack(fill="both", expand=True, padx=22, pady=18)

        self._build_add(pad)
        self._build_templates(pad)
        self._build_list(pad)

    # ── 新增规则 ──

    def _build_add(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "新增规则", T.BG_CARD).pack(anchor="w")
        W.muted_label(card.inner,
                      "模式支持 * 通配符。动作「阻止」会直接拦截匹配对象，"
                      "「询问」会挂起等待决定，请谨慎使用阻止。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))

        form = tk.Frame(card.inner, bg=T.BG_CARD)
        form.pack(fill="x")

        row1 = tk.Frame(form, bg=T.BG_CARD)
        row1.pack(fill="x", pady=(0, 8))
        self._type_var = tk.StringVar(value="file")
        tk.Label(row1, text="类型", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(9), width=6, anchor="w").pack(side="left")
        dark_option(row1, self._type_var, TYPE_VALUES, TYPE_LABELS).pack(side="left")
        self._action_var = tk.StringVar(value="block")
        tk.Label(row1, text="动作", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(9), width=6, anchor="w").pack(side="left", padx=(16, 0))
        dark_option(row1, self._action_var, ACTION_VALUES, ACTION_LABELS).pack(
            side="left")

        row2 = tk.Frame(form, bg=T.BG_CARD)
        row2.pack(fill="x", pady=(0, 8))
        tk.Label(row2, text="匹配模式", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(9), anchor="w").pack(side="left")
        self._pattern_var = tk.StringVar()
        tk.Entry(row2, textvariable=self._pattern_var, bg=T.BG_INPUT,
                 fg=T.TEXT_PRIMARY, insertbackground=T.ACCENT, relief="flat",
                 bd=0, highlightthickness=1, highlightbackground=T.BORDER,
                 highlightcolor=T.ACCENT, font=T.mono(10)).pack(
            side="left", fill="x", expand=True, ipady=5, padx=(8, 0))
        self._pattern_var.trace_add("write", lambda *_: self._update_preview())

        row3 = tk.Frame(form, bg=T.BG_CARD)
        row3.pack(fill="x", pady=(0, 8))
        tk.Label(row3, text="描述", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(9), anchor="w").pack(side="left")
        self._desc_var = tk.StringVar()
        tk.Entry(row3, textvariable=self._desc_var, bg=T.BG_INPUT,
                 fg=T.TEXT_PRIMARY, insertbackground=T.ACCENT, relief="flat",
                 bd=0, highlightthickness=1, highlightbackground=T.BORDER,
                 highlightcolor=T.ACCENT, font=T.font(10)).pack(
            side="left", fill="x", expand=True, ipady=5, padx=(8, 0))

        row4 = tk.Frame(form, bg=T.BG_CARD)
        row4.pack(fill="x")
        W.button(row4, "添加规则", self._add_rule).pack(side="left")
        self._preview = W.muted_label(row4, "", T.BG_CARD, size=9, mono=True)
        self._preview.pack(side="left", padx=(12, 0))

    def _update_preview(self):
        pattern = (self._pattern_var.get() or "").strip()
        if not pattern:
            self._preview.configure(text="")
            return
        text = (f"{TYPE_LABELS.get(self._type_var.get(), '?')} · "
                f"{ACTION_LABELS.get(self._action_var.get(), '?')} · {pattern}")
        if len(text) > 80:
            text = text[:79] + "…"
        self._preview.configure(text=text)

    def _add_rule(self):
        rule_type = self._type_var.get()
        action = self._action_var.get()
        pattern = (self._pattern_var.get() or "").strip()
        if not pattern:
            self.ctx.say("匹配模式不能为空", "warn")
            return
        desc = (self._desc_var.get() or "").strip()
        if action == "block" and not messagebox.askyesno(
                "确认新增阻止规则",
                f"新增「阻止」规则：{pattern}\n\n"
                "阻止规则会直接拦截匹配对象，写错可能影响正常软件。继续？",
                parent=self.winfo_toplevel()):
            return

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self.ctx.say(f"添加失败：{res.error}", "error")
                return
            if not res.data.get("ok") or res.data.get("rule") is None:
                # 后端参数校验失败时 add_rule 返回 None，不会抛异常
                self.ctx.say("添加失败：参数未通过后端校验"
                             "（类型/动作/模式需符合取值域）", "error")
                return
            self.ctx.say(f"已添加规则 #{res.data.get('rule')}", "ok")
            self._pattern_var.set("")
            self._desc_var.set("")
            self._load_rules()

        run_async(self, lambda: self.client.rules_add(rule_type, action, pattern, desc),
                  done)

    # ── 模板 ──

    def _build_templates(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "预设模板", T.BG_CARD).pack(side="left")
        W.button(head, "刷新", self._load_templates, "ghost").pack(side="right")
        W.muted_label(card.inner,
                      "点「套用」会把模板内容填进上方表单，确认无误后再点添加。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))
        self._tpl_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._tpl_host.pack(fill="x")
        W.muted_label(self._tpl_host, "未加载", T.BG_CARD, size=9).pack(anchor="w")

    def _load_templates(self):
        run_async(self, self.client.rules_templates, self._apply_templates)

    def _apply_templates(self, res):
        for child in self._tpl_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._tpl_host, "无法读取模板", T.BG_CARD,
                          size=9, fg=T.DANGER).pack(anchor="w")
            return
        tpls = res.data.get("templates") or []
        if not tpls:
            W.muted_label(self._tpl_host, "无预设模板", T.BG_CARD,
                          size=9).pack(anchor="w")
            return
        for tpl in tpls[:12]:
            if not isinstance(tpl, dict):
                continue
            row = tk.Frame(self._tpl_host, bg=T.BG_HOVER)
            row.pack(fill="x", pady=2)
            pad = tk.Frame(row, bg=T.BG_HOVER)
            pad.pack(fill="x", padx=10, pady=6)

            rtype = str(tpl.get("type") or tpl.get("rule_type") or "")
            action = str(tpl.get("action") or "")
            pattern = str(tpl.get("pattern") or "")
            name = str(tpl.get("name") or tpl.get("description") or pattern)

            top = tk.Frame(pad, bg=T.BG_HOVER)
            top.pack(fill="x")
            tk.Label(top, text=name if len(name) <= 50 else name[:49] + "…",
                     bg=T.BG_HOVER, fg=T.TEXT_PRIMARY,
                     font=T.font(10, "bold")).pack(side="left")
            tk.Label(top, text=f"{TYPE_LABELS.get(rtype, rtype)} · "
                               f"{ACTION_LABELS.get(action, action)}",
                     bg=T.BG_HOVER, fg=ACTION_FG.get(action, T.TEXT_SECONDARY),
                     font=T.font(9)).pack(side="left", padx=(8, 0))
            W.button(top, "套用",
                     lambda t=tpl: self._apply_template(t), "ghost").pack(side="right")
            if pattern:
                W.muted_label(pad, pattern, T.BG_HOVER, size=9,
                              mono=True).pack(fill="x", pady=(4, 0))

    def _apply_template(self, tpl: dict):
        rtype = str(tpl.get("type") or tpl.get("rule_type") or "file")
        action = str(tpl.get("action") or "block")
        if rtype in TYPE_VALUES:
            self._type_var.set(rtype)
        if action in ACTION_VALUES:
            self._action_var.set(action)
        self._pattern_var.set(str(tpl.get("pattern") or ""))
        self._desc_var.set(str(tpl.get("name") or tpl.get("description") or ""))
        self._update_preview()
        self.ctx.say("模板已填入表单，确认后点「添加规则」", "info")

    # ── 规则列表 ──

    def _build_list(self, parent):
        card = W.Card(parent)
        card.pack(fill="both", expand=True)
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "规则列表", T.BG_CARD).pack(side="left")
        self._count = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                               font=T.font(9))
        self._count.pack(side="left", padx=(10, 0))

        btns = tk.Frame(head, bg=T.BG_CARD)
        btns.pack(side="right")
        W.button(btns, "导出…", self._export, "ghost").pack(side="left")
        W.button(btns, "导入…", self._import, "ghost").pack(side="left", padx=(8, 0))
        W.button(btns, "刷新", self._load_rules, "ghost").pack(side="left",
                                                             padx=(8, 0))

        # 类型过滤
        filt = tk.Frame(card.inner, bg=T.BG_CARD)
        filt.pack(fill="x", pady=(10, 0))
        tk.Label(filt, text="筛选类型", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(9)).pack(side="left")
        self._filter_var = tk.StringVar(value="all")
        labels = {"all": "全部"}
        labels.update(TYPE_LABELS)
        dark_option(filt, self._filter_var, ("all",) + TYPE_VALUES, labels,
                    width=8).pack(side="left", padx=(8, 0))
        W.button(filt, "应用", self._load_rules, "ghost").pack(side="left",
                                                             padx=(8, 0))

        self._list_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._list_host.pack(fill="both", expand=True, pady=(10, 0))

    def _load_rules(self):
        value = self._filter_var.get()
        rule_type = None if value == "all" else value

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self._render_rules([])
                return
            rules = res.data.get("rules") or []
            self._render_rules([r for r in rules if isinstance(r, dict)])

        run_async(self, lambda: self.client.rules_list(rule_type), done)

    def _render_rules(self, rules: list[dict]):
        self._rules = rules
        for child in self._list_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        enabled = sum(1 for r in rules if r.get("enabled"))
        self._count.configure(text=f"共 {len(rules)} 条 · 启用 {enabled}")

        if not rules:
            W.EmptyHint(self._list_host, "暂无自定义规则",
                        "可套用上方模板，或手动新增一条", T.BG_CARD,
                        "✓").pack(fill="both", expand=True)
            return
        for rule in rules:
            self._rule_row(rule)

    def _rule_row(self, rule: dict):
        rid = rule.get("id")
        rtype = str(rule.get("type") or "")
        action = str(rule.get("action") or "")
        is_on = bool(rule.get("enabled"))

        row = tk.Frame(self._list_host, bg=T.BG_HOVER)
        row.pack(fill="x", pady=2)
        pad = tk.Frame(row, bg=T.BG_HOVER)
        pad.pack(fill="x", padx=10, pady=7)

        top = tk.Frame(pad, bg=T.BG_HOVER)
        top.pack(fill="x")
        tk.Label(top, text=f"#{rid}", bg=T.BG_HOVER, fg=T.TEXT_MUTED,
                 font=T.mono(9), width=6, anchor="w").pack(side="left")
        tk.Label(top, text=TYPE_LABELS.get(rtype, rtype), bg=T.BG_HOVER,
                 fg=T.TEXT_SECONDARY, font=T.font(9), width=7,
                 anchor="w").pack(side="left")
        tk.Label(top, text=ACTION_LABELS.get(action, action), bg=T.BG_HOVER,
                 fg=ACTION_FG.get(action, T.TEXT_SECONDARY),
                 font=T.font(9, "bold"), width=5, anchor="w").pack(side="left")
        pattern = str(rule.get("pattern") or "")
        if len(pattern) > 52:
            pattern = pattern[:51] + "…"
        tk.Label(top, text=pattern, bg=T.BG_HOVER, fg=T.TEXT_PRIMARY,
                 font=T.mono(9), anchor="w").pack(side="left", padx=(6, 0))

        actions = tk.Frame(top, bg=T.BG_HOVER)
        actions.pack(side="right")
        W.button(actions, "停用" if is_on else "启用",
                 lambda i=rid, v=is_on: self._toggle_rule(i, v),
                 "ghost" if is_on else "accent").pack(side="left")
        W.button(actions, "删除", lambda i=rid: self._remove_rule(i),
                 "danger").pack(side="left", padx=(6, 0))

        desc = str(rule.get("description") or "")
        created = rule.get("created_at")
        bits = []
        if desc:
            bits.append(desc)
        if created is not None:
            bits.append(f"创建 {_fmt_created(created)}")
        if not is_on:
            bits.append("已停用")
        if bits:
            text = " · ".join(bits)
            if len(text) > 104:
                text = text[:103] + "…"
            W.muted_label(pad, text, T.BG_HOVER, size=9,
                          fg=T.TEXT_MUTED).pack(fill="x", pady=(4, 0))

    def _toggle_rule(self, rule_id, current: bool):
        if rule_id is None:
            return

        def done(res):
            ok = res.ok and isinstance(res.data, dict) and res.data.get("ok", True)
            self.ctx.say(f"规则 #{rule_id} 已{'停用' if current else '启用'}"
                         if ok else f"操作失败：{res.error}",
                         "ok" if ok else "error")
            self._load_rules()

        run_async(self, lambda: self.client.rules_toggle(int(rule_id), not current),
                  done)

    def _remove_rule(self, rule_id):
        if rule_id is None:
            return
        if not messagebox.askyesno("确认删除",
                                   f"删除规则 #{rule_id}？此操作不可撤销。",
                                   parent=self.winfo_toplevel()):
            return

        def done(res):
            ok = res.ok and isinstance(res.data, dict) and res.data.get("ok", True)
            self.ctx.say(f"已删除规则 #{rule_id}" if ok
                         else f"删除失败：{res.error}", "ok" if ok else "error")
            self._load_rules()

        run_async(self, lambda: self.client.rules_remove(int(rule_id)), done)

    # ── 导入 / 导出 ──

    def _export(self):
        if not self._rules:
            self.ctx.say("当前没有规则可导出", "warn")
            return
        try:
            path = filedialog.asksaveasfilename(
                title="导出规则", defaultextension=".json",
                initialfile="andun_rules.json",
                filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")])
        except Exception as exc:
            self.ctx.say(f"打开保存对话框失败：{exc}", "error")
            return
        if not path:
            return

        def done(res):
            rules = None
            if res.ok and isinstance(res.data, dict):
                rules = res.data.get("rules")
            if not isinstance(rules, list):
                # 导出接口不可用时退回本地已加载的规则，保证功能可用
                rules = self._rules
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(rules, fh, ensure_ascii=False, indent=2)
            except OSError as exc:
                self.ctx.say(f"写入失败：{exc}", "error")
                return
            self.ctx.say(f"已导出 {len(rules)} 条规则到 {path}", "ok")

        run_async(self, self.client.rules_export, done)

    def _import(self):
        try:
            path = filedialog.askopenfilename(
                title="导入规则", filetypes=[("JSON 文件", "*.json"),
                                            ("所有文件", "*.*")])
        except Exception as exc:
            self.ctx.say(f"打开文件对话框失败：{exc}", "error")
            return
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            self.ctx.say(f"读取失败（需为 JSON 数组）：{exc}", "error")
            return
        if isinstance(data, dict):
            data = data.get("rules")
        if not isinstance(data, list) or not data:
            self.ctx.say("文件里没有可导入的规则数组", "warn")
            return
        if not messagebox.askyesno(
                "确认导入",
                f"从文件导入 {len(data)} 条规则？\n\n"
                "导入的规则会追加到现有规则中。",
                parent=self.winfo_toplevel()):
            return

        def done(res):
            if res.ok:
                self.ctx.say(f"已导入 {len(data)} 条规则", "ok")
            else:
                self.ctx.say(f"导入失败：{res.error}", "error")
            self._load_rules()

        run_async(self, lambda: self.client.rules_import(data), done)

    # ── 生命周期 ──

    def on_show(self):
        self._load_rules()
        self._load_templates()

    def on_hide(self):
        self.cancel_timers()
