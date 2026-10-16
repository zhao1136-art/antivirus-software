"""安全工具页：交互式检测 + 网络急救 + 漏洞修复 + U 盘管控 + 防护开关。

接口选取原则
------------
只使用 ``backend/app.py`` 里**真实存在**的路由。原 ``tools.html`` 引用了
``/api/v1/rules/stats``、``/api/v1/sandbox/stats``、``/api/v1/recovery/stats``、
``/api/v1/privacy/stats``、``/api/v1/honeypot/*``、``/api/v1/camera/*``、
``/api/v1/browser-guard/*`` —— 这些在 app.py 中**都不存在**，照抄只会做出
一按就 404 的按钮，所以此处一律不实现。

有意不做的功能
--------------
**反 Rootkit 扫描**：``jobs`` 里有 ``rootkit-scan`` 这个 kind，但
``ISSUES.md`` 2.1 明确记载 ``anti_rootkit.scan()`` 会因结构体布局错误触发
``0xC0000005`` 访问违例，**try/except 抓不到，直接杀死解释器**。
也就是说这个按钮一点就会把整个后端进程带走 —— 绝不能放进 UI。
"""
from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox

from .. import theme as T
from .. import widgets as W
from ..api import fmt_basename, fmt_int, fmt_size, run_async
from ..app import Page

LEVEL_FG = {
    "safe": T.SUCCESS,
    "suspicious": T.WARNING,
    "malicious": T.DANGER,
}
LEVEL_TEXT = {
    "safe": "安全",
    # 沙箱的 verdict 用的是 clean / suspicious / malicious / unknown 这套词，
    # 和这里原有的 safe 不是一回事 —— 之前 clean 和 unknown 都没映射，界面上
    # 直接显示英文原文。补上。
    "clean": "未检出",
    "suspicious": "可疑",
    "malicious": "恶意",
    # ⚠️ 后端在"非 PE / 分析失败 / 只看到超时"时返回 unknown。
    #    **绝不能显示成"安全"** —— 分析不出来不等于没有威胁。
    "unknown": "未知（未能分析）",
}


class Indicator(tk.Frame):
    """一个"指示灯 + 名称"的小格子，用于网络状态五项检查。"""

    def __init__(self, parent, name: str, bg: str = T.BG_CARD):
        super().__init__(parent, bg=bg)
        dot = tk.Canvas(self, width=10, height=10, bg=bg,
                        highlightthickness=0, bd=0)
        dot.pack(side="left")
        self._dot_id = dot.create_oval(1, 1, 9, 9, fill=T.TEXT_MUTED, outline="")
        self._canvas = dot
        tk.Label(self, text=name, bg=bg, fg=T.TEXT_SECONDARY,
                 font=T.font(10)).pack(side="left", padx=(6, 0))

    def set(self, ok):
        """``ok`` 为 True/False/None（None = 未知/未检测）。"""
        color = T.TEXT_MUTED if ok is None else (T.SUCCESS if ok else T.DANGER)
        try:
            self._canvas.itemconfigure(self._dot_id, fill=color)
        except tk.TclError:
            pass


class ToolsPage(Page):
    key = "tools"
    title = "安全工具"
    glyph = "⚒"

    def build(self):
        self._vuln_job: str | None = None
        self._vuln_running = False
        self._sandbox_job: str | None = None
        self._sandbox_running = False

        root = W.ScrollableFrame(self, bg=T.BG_APP)
        root.pack(fill="both", expand=True)
        pad = tk.Frame(root.content, bg=T.BG_APP)
        pad.pack(fill="both", expand=True, padx=22, pady=18)

        # 交互式工具在前（最常用），扫描/开关类在后
        self._build_url_tool(pad)
        self._build_url_lists(pad)
        self._build_mail_tool(pad)
        self._build_cloud_sample(pad)
        self._build_sandbox(pad)
        self._build_network(pad)
        self._build_vulnfix(pad)
        self._build_download_guard(pad)
        self._build_usb(pad)
        self._build_switches(pad)

    # ─────────────────────────────────────────────────────────
    # 交互工具 1：网址安全检查
    # ─────────────────────────────────────────────────────────

    def _build_url_tool(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "网址安全检查", T.BG_CARD).pack(anchor="w")
        W.muted_label(card.inner,
                      "查一条 URL 或域名是否命中恶意域名库 / 内置库 / 火绒网址库。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x")
        self._url_var = tk.StringVar()
        entry = tk.Entry(row, textvariable=self._url_var, bg=T.BG_INPUT,
                         fg=T.TEXT_PRIMARY, insertbackground=T.ACCENT,
                         relief="flat", bd=0, highlightthickness=1,
                         highlightbackground=T.BORDER, highlightcolor=T.ACCENT,
                         font=T.mono(10))
        entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 10))
        entry.bind("<Return>", lambda _e: self._check_url())
        W.button(row, "检测", self._check_url).pack(side="left")

        self._url_result = tk.Frame(card.inner, bg=T.BG_CARD)
        self._url_result.pack(fill="x", pady=(10, 0))
        self._url_verdict = tk.Label(self._url_result, text="", bg=T.BG_CARD,
                                     fg=T.TEXT_MUTED, font=T.font(11, "bold"),
                                     anchor="w", justify="left")
        self._url_verdict.pack(fill="x")

    def _check_url(self):
        target = (self._url_var.get() or "").strip()
        if not target:
            self.ctx.say("请输入要检测的网址或域名", "warn")
            return
        self._url_verdict.configure(text="检测中…", fg=T.TEXT_SECONDARY)

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self._url_verdict.configure(text=f"检测失败：{res.error}", fg=T.DANGER)
                return
            d = res.data
            level = str(d.get("level") or "safe").lower()
            color = LEVEL_FG.get(level, T.TEXT_SECONDARY)
            host = d.get("host") or target
            reason = d.get("reason") or ""
            parts = [f"{LEVEL_TEXT.get(level, level)} · {host}"]
            if reason:
                parts.append(reason)
            families = d.get("families") or []
            if families:
                parts.append("家族: " + "、".join(str(f) for f in families[:4]))
            if d.get("in_blocked"):
                parts.append("已在本地阻断名单")
            self._url_verdict.configure(text=" — ".join(parts), fg=color)
            self.ctx.say(f"网址检测结果：{LEVEL_TEXT.get(level, level)}",
                         "ok" if level == "safe" else "warn")

        run_async(self, lambda: self.client.urlguard_check(target), done)

    # ─────────────────────────────────────────────────────────
    # 网址防护：阻断名单 / hosts 同步 / 白名单
    # ─────────────────────────────────────────────────────────

    def _build_url_lists(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "网址名单管理", T.BG_CARD).pack(side="left")
        self._url_hosts_tag = tk.Label(head, text="", bg=T.BG_CARD,
                                       fg=T.TEXT_MUTED, font=T.font(9))
        self._url_hosts_tag.pack(side="right")

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x", pady=(10, 0))
        self._url_manage_var = tk.StringVar()
        entry = tk.Entry(row, textvariable=self._url_manage_var, bg=T.BG_INPUT,
                         fg=T.TEXT_PRIMARY, insertbackground=T.ACCENT,
                         relief="flat", bd=0, highlightthickness=1,
                         highlightbackground=T.BORDER, highlightcolor=T.ACCENT,
                         font=T.mono(10))
        entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 10))
        entry.bind("<Return>", lambda _e: self._block_domain())
        W.button(row, "加入阻断", self._block_domain, "danger").pack(side="left")
        W.button(row, "加入白名单", self._whitelist_add, "ghost").pack(
            side="left", padx=(8, 0))

        btns = tk.Frame(card.inner, bg=T.BG_CARD)
        btns.pack(fill="x", pady=(10, 0))
        W.button(btns, "刷新名单", self._refresh_url_lists, "ghost").pack(side="left")
        self._hosts_btn = W.button(btns, "写入 hosts", self._hosts_sync, "ghost")
        self._hosts_btn.pack(side="left", padx=(8, 0))

        # 两个名单并排展示
        cols = tk.Frame(card.inner, bg=T.BG_CARD)
        cols.pack(fill="x", pady=(12, 0))
        cols.columnconfigure(0, weight=1, uniform="url")
        cols.columnconfigure(1, weight=1, uniform="url")

        left = tk.Frame(cols, bg=T.BG_CARD)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self._blocked_count = tk.Label(left, text="阻断名单", bg=T.BG_CARD,
                                       fg=T.TEXT_SECONDARY, font=T.font(10, "bold"),
                                       anchor="w")
        self._blocked_count.pack(fill="x")
        self._blocked_host = tk.Frame(left, bg=T.BG_CARD)
        self._blocked_host.pack(fill="x", pady=(6, 0))

        right = tk.Frame(cols, bg=T.BG_CARD)
        right.grid(row=0, column=1, sticky="nsew")
        self._white_count = tk.Label(right, text="访问白名单", bg=T.BG_CARD,
                                     fg=T.TEXT_SECONDARY, font=T.font(10, "bold"),
                                     anchor="w")
        self._white_count.pack(fill="x")
        self._white_host = tk.Frame(right, bg=T.BG_CARD)
        self._white_host.pack(fill="x", pady=(6, 0))

        W.muted_label(card.inner,
                      "「写入 hosts」会把阻断名单落到系统 hosts 文件；"
                      "改动 hosts 属于系统级操作，可再点一次撤销。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(10, 0))

    def _refresh_url_lists(self):
        run_async(self, self.client.urlguard_blocked, self._apply_blocked)
        run_async(self, self.client.urlguard_whitelist, self._apply_whitelist)
        run_async(self, self.client.urlguard_status, self._apply_urlguard_status)

    def _apply_urlguard_status(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        applied = res.data.get("hosts_applied")
        if applied is None:
            self._url_hosts_tag.configure(text="")
            return
        self._url_hosts_tag.configure(
            text="hosts 已应用" if applied else "hosts 未应用",
            fg=T.SUCCESS if applied else T.TEXT_MUTED)

    def _apply_blocked(self, res):
        for child in self._blocked_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._blocked_host, "读取失败", T.BG_CARD, size=9,
                          fg=T.DANGER).pack(anchor="w")
            return
        items = res.data.get("blocked") or []
        self._blocked_count.configure(text=f"阻断名单（{len(items)}）")
        if not items:
            W.muted_label(self._blocked_host, "空", T.BG_CARD, size=9).pack(anchor="w")
            return
        for item in items[:12]:
            self._list_line(self._blocked_host, str(item),
                            lambda v=str(item): self._unblock(v))

    def _apply_whitelist(self, res):
        for child in self._white_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._white_host, "读取失败", T.BG_CARD, size=9,
                          fg=T.DANGER).pack(anchor="w")
            return
        items = res.data.get("whitelist") or []
        self._white_count.configure(text=f"访问白名单（{len(items)}）")
        if not items:
            W.muted_label(self._white_host, "空", T.BG_CARD, size=9).pack(anchor="w")
            return
        for item in items[:12]:
            self._list_line(self._white_host, str(item),
                            lambda v=str(item): self._whitelist_remove(v))

    def _list_line(self, parent, text: str, on_remove):
        row = tk.Frame(parent, bg=T.BG_HOVER)
        row.pack(fill="x", pady=1)
        shown = text if len(text) <= 42 else text[:41] + "…"
        tk.Label(row, text=shown, bg=T.BG_HOVER, fg=T.TEXT_PRIMARY,
                 font=T.mono(9), anchor="w").pack(side="left", fill="x",
                                                  expand=True, padx=(8, 4), pady=4)
        btn = tk.Button(row, text="×", command=on_remove, bg=T.BG_HOVER,
                        fg=T.DANGER, activebackground=T.BORDER_LIGHT,
                        activeforeground=T.DANGER, relief="flat", bd=0,
                        highlightthickness=0, font=T.font(10, "bold"),
                        cursor="hand2", padx=8)
        btn.pack(side="right")

    def _domain_input(self) -> str:
        value = (self._url_manage_var.get() or "").strip()
        if not value:
            self.ctx.say("请先输入域名或网址", "warn")
        return value

    def _block_domain(self):
        target = self._domain_input()
        if not target:
            return

        def done(res):
            if res.ok:
                self.ctx.say(f"已加入阻断名单：{target}", "ok")
                self._url_manage_var.set("")
            else:
                self.ctx.say(f"加入失败：{res.error}", "error")
            self._refresh_url_lists()

        run_async(self, lambda: self.client.urlguard_block(target), done)

    def _unblock(self, target: str):
        def done(res):
            self.ctx.say(f"已移出阻断名单：{target}" if res.ok
                         else f"移除失败：{res.error}", "ok" if res.ok else "error")
            self._refresh_url_lists()

        run_async(self, lambda: self.client.urlguard_unblock(target), done)

    def _whitelist_add(self):
        target = self._domain_input()
        if not target:
            return

        def done(res):
            if res.ok:
                self.ctx.say(f"已加入白名单：{target}", "ok")
                self._url_manage_var.set("")
            else:
                self.ctx.say(f"加入白名单失败：{res.error}", "error")
            self._refresh_url_lists()

        run_async(self, lambda: self.client.urlguard_whitelist_add(target), done)

    def _whitelist_remove(self, target: str):
        def done(res):
            self.ctx.say(f"已移出白名单：{target}" if res.ok
                         else f"移除失败：{res.error}", "ok" if res.ok else "error")
            self._refresh_url_lists()

        run_async(self, lambda: self.client.urlguard_whitelist_remove(target), done)

    def _hosts_sync(self):
        # 目标状态取反：当前已应用就清除，否则写入
        currently = "已应用" in (self._url_hosts_tag.cget("text") or "")
        target = not currently
        action = "清除 hosts 阻断" if currently else "把阻断名单写入 hosts"
        if not messagebox.askyesno("确认", f"将要{action}，继续？",
                                   parent=self.winfo_toplevel()):
            return

        def done(res):
            if res.ok:
                self.ctx.say(f"{action}完成", "ok")
            else:
                self.ctx.say(f"{action}失败：{res.error}", "error")
            self._refresh_url_lists()

        run_async(self, lambda: self.client.urlguard_hosts_sync(target), done)

    # ─────────────────────────────────────────────────────────
    # 交互工具 2：邮件/文本钓鱼检测
    # ─────────────────────────────────────────────────────────

    def _build_mail_tool(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "邮件 / 文本钓鱼检测", T.BG_CARD).pack(anchor="w")
        W.muted_label(card.inner,
                      "粘贴邮件正文，检测钓鱼话术、可疑链接与高危附件名。"
                      "纯本地启发式，不上传内容。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))

        self._mail_text = tk.Text(card.inner, height=5, bg=T.BG_INPUT,
                                  fg=T.TEXT_PRIMARY, insertbackground=T.ACCENT,
                                  relief="flat", bd=0, highlightthickness=1,
                                  highlightbackground=T.BORDER,
                                  highlightcolor=T.ACCENT,
                                  font=T.font(10), wrap="word", padx=8, pady=6)
        self._mail_text.pack(fill="x")

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x", pady=(10, 0))
        W.button(row, "检测文本", self._check_mail).pack(side="left")
        W.button(row, "清空", lambda: self._mail_text.delete("1.0", "end"),
                 "ghost").pack(side="left", padx=(8, 0))

        self._mail_result = tk.Label(card.inner, text="", bg=T.BG_CARD,
                                     fg=T.TEXT_MUTED, font=T.font(10),
                                     anchor="w", justify="left", wraplength=760)
        self._mail_result.pack(fill="x", pady=(10, 0))

    def _check_mail(self):
        try:
            text = self._mail_text.get("1.0", "end").strip()
        except tk.TclError:
            return
        if not text:
            self.ctx.say("请先粘贴要检测的文本", "warn")
            return
        self._mail_result.configure(text="检测中…", fg=T.TEXT_SECONDARY)

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self._mail_result.configure(text=f"检测失败：{res.error}", fg=T.DANGER)
                return
            d = res.data
            risk = str(d.get("risk") or "safe").lower()
            color = LEVEL_FG.get(risk, T.TEXT_SECONDARY)
            alerts = d.get("alerts") or []
            lines = [f"风险等级：{LEVEL_TEXT.get(risk, risk)}"
                     f"　链接 {fmt_int(d.get('url_count'))} 条"
                     f"　命中 {fmt_int(len(alerts))} 项"]
            for a in alerts[:6]:
                if isinstance(a, dict):
                    lines.append(f"· [{a.get('level', '')}] {a.get('detail', '')}")
            if not alerts:
                lines.append("未发现钓鱼特征。")
            self._mail_result.configure(text="\n".join(lines), fg=color)
            self.ctx.say(f"文本检测：{LEVEL_TEXT.get(risk, risk)}",
                         "ok" if risk == "safe" else "warn")

        run_async(self, lambda: self.client.mail_guard_scan_text(text), done)

    # ─────────────────────────────────────────────────────────
    # 云样本多引擎比对（multipart 上传）
    # ─────────────────────────────────────────────────────────

    def _build_cloud_sample(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "云样本多引擎比对", T.BG_CARD).pack(anchor="w")
        W.muted_label(card.inner,
                      "选一个本地文件上传：本地算 SHA256/MD5，再拿哈希去云端多引擎比对。"
                      "上传的是文件内容，请只提交你确实想研判的样本。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x")
        W.button(row, "选择文件并研判…", self._cloud_submit).pack(side="left")
        self._cloud_tag = tk.Label(row, text="未提交", bg=T.BG_CARD,
                                   fg=T.TEXT_MUTED, font=T.font(9))
        self._cloud_tag.pack(side="left", padx=(10, 0))

        self._cloud_result = tk.Label(card.inner, text="", bg=T.BG_CARD,
                                      fg=T.TEXT_SECONDARY, font=T.mono(9),
                                      anchor="w", justify="left", wraplength=760)
        self._cloud_result.pack(fill="x", pady=(10, 0))

    def _cloud_submit(self):
        try:
            path = filedialog.askopenfilename(title="选择要研判的样本文件")
        except Exception as exc:
            self.ctx.say(f"打开文件选择器失败：{exc}", "error")
            return
        if not path:
            return
        self._cloud_tag.configure(text="上传中…", fg=T.TEXT_SECONDARY)
        self._cloud_result.configure(text="")

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self._cloud_tag.configure(text="提交失败", fg=T.DANGER)
                self._cloud_result.configure(text=str(res.error or ""), fg=T.DANGER)
                return
            d = res.data
            known = d.get("known")
            lookup = d.get("lookup") if isinstance(d.get("lookup"), dict) else {}
            verdict = str(lookup.get("verdict") or ("unknown" if not known else ""))
            color = LEVEL_FG.get(verdict, T.TEXT_SECONDARY)
            self._cloud_tag.configure(
                text=("已命中云端记录" if known else "云端无记录"),
                fg=T.SUCCESS if known else T.WARNING)

            lines = [
                f"文件　{fmt_basename(d.get('filename'))}",
                f"大小　{fmt_size(d.get('size_bytes'))}",
                f"SHA256　{d.get('sha256') or '--'}",
                f"MD5　{d.get('md5') or '--'}",
                f"研判　{LEVEL_TEXT.get(verdict, verdict or '未知')}",
            ]
            engines = lookup.get("engines") or lookup.get("sources")
            if engines:
                lines.append(f"引擎　{engines}")
            reason = lookup.get("reason") or lookup.get("detail")
            if reason:
                lines.append(f"说明　{reason}")
            self._cloud_result.configure(text="\n".join(lines), fg=color)
            self.ctx.say(f"云研判完成：{LEVEL_TEXT.get(verdict, verdict or '未知')}",
                         "ok" if verdict == "clean" else "warn")

        run_async(self, lambda: self.client.cloud_sample_submit(path), done)

    # ─────────────────────────────────────────────────────────
    # 沙箱分析（走 jobs，可取消）
    # ─────────────────────────────────────────────────────────

    def _build_sandbox(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "沙箱分析", T.BG_CARD).pack(side="left")
        self._sandbox_tag = tk.Label(head, text="未分析", bg=T.BG_CARD,
                                     fg=T.TEXT_MUTED, font=T.font(10, "bold"))
        self._sandbox_tag.pack(side="left", padx=(10, 0))
        W.muted_label(card.inner,
                      "在受限 Job Object 里运行样本并观察行为。样本会真的被执行，"
                      "请只在隔离环境下提交。分析可取消。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x")
        self._sandbox_btn = W.button(row, "选择文件并分析…", self._sandbox_start)
        self._sandbox_btn.pack(side="left")
        self._sandbox_cancel_btn = W.button(row, "取消", self._sandbox_cancel, "danger")
        self._sandbox_cancel_btn.pack(side="left", padx=(8, 0))
        self._sandbox_cancel_btn.configure(state="disabled", bg=T.BORDER,
                                           fg=T.TEXT_MUTED, cursor="")

        self._sandbox_result = tk.Label(card.inner, text="", bg=T.BG_CARD,
                                        fg=T.TEXT_SECONDARY, font=T.font(10),
                                        anchor="w", justify="left", wraplength=760)
        self._sandbox_result.pack(fill="x", pady=(10, 0))

    def _sandbox_start(self):
        if self._sandbox_running:
            self.ctx.say("沙箱分析已在进行中", "warn")
            return
        try:
            path = filedialog.askopenfilename(title="选择要分析的可疑文件")
        except Exception as exc:
            self.ctx.say(f"打开文件选择器失败：{exc}", "error")
            return
        if not path:
            return
        if not messagebox.askyesno(
                "确认执行样本",
                "沙箱会真实运行该文件。\n\n"
                "请确认这是隔离环境，且你接受样本在本机执行的风险。继续？",
                parent=self.winfo_toplevel()):
            return
        self._sandbox_tag.configure(text="提交中…", fg=T.TEXT_SECONDARY)
        self._sandbox_result.configure(text="")

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self._sandbox_tag.configure(text="提交失败", fg=T.DANGER)
                self.ctx.say(f"沙箱任务提交失败：{res.error}", "error")
                return
            self._sandbox_job = res.data.get("task_id")
            self._sandbox_running = True
            self._set_sandbox_busy(True)
            self.ctx.say("沙箱分析已启动", "ok")
            self._sandbox_poll()

        run_async(self, lambda: self.client.sandbox_analyze_job(path), done)

    def _sandbox_poll(self):
        # 与漏洞扫描同理：用标志位自停，不碰 cancel_timers（会误杀其他周期任务）
        if not self._sandbox_job or not self._sandbox_running:
            return
        run_async(self, lambda: self.client.job_status(self._sandbox_job),
                  self._sandbox_apply)
        self.every(1200, self._sandbox_poll)

    def _sandbox_apply(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        d = res.data
        status = str(d.get("status") or "").lower()
        progress = d.get("progress")
        label = {"queued": "排队中", "running": "分析中", "completed": "已完成",
                 "cancelled": "已取消", "failed": "失败"}.get(status, status)
        if isinstance(progress, (int, float)) and status == "running":
            label = f"{label} {progress:.0f}%"
        color = {"completed": T.SUCCESS, "failed": T.DANGER,
                 "cancelled": T.WARNING}.get(status, T.ACCENT)
        self._sandbox_tag.configure(text=label, fg=color)
        current = d.get("current")
        if current and status == "running":
            self._sandbox_result.configure(text=str(current)[:120], fg=T.TEXT_SECONDARY)

        if status in ("completed", "cancelled", "failed"):
            self._sandbox_running = False
            self._set_sandbox_busy(False)
            if status == "failed":
                self.ctx.say(f"沙箱分析失败：{d.get('error')}", "error")
                self._sandbox_result.configure(text=str(d.get("error") or ""),
                                               fg=T.DANGER)
            elif status == "cancelled":
                self.ctx.say("沙箱分析已取消", "warn")
            else:
                self._apply_sandbox_report(d.get("result"))

    def _apply_sandbox_report(self, result):
        if not isinstance(result, dict):
            return
        verdict = str(result.get("verdict") or "unknown").lower()
        color = {"clean": T.SUCCESS, "malicious": T.DANGER,
                 "suspicious": T.WARNING}.get(verdict, T.TEXT_SECONDARY)
        behaviors = result.get("behaviors") or []
        indicators = result.get("risk_indicators") or []
        lines = [
            f"判定　{LEVEL_TEXT.get(verdict, verdict)}"
            f"　风险分 {result.get('risk_score', '--')}"
            f"　置信度 {result.get('confidence', '--')}",
            f"文件　{result.get('file_name') or '--'}"
            f"　耗时 {result.get('elapsed_sec', '--')}s",
        ]
        for item in behaviors[:6]:
            if isinstance(item, dict):
                lines.append(f"· 行为 {item.get('type') or item.get('name') or ''}"
                             f" {item.get('detail') or ''}".rstrip())
            else:
                lines.append(f"· 行为 {item}")
        for item in indicators[:6]:
            lines.append(f"· 指标 {item}")

        # ── 隔离状态 ──
        # 这一段是沙箱报告里最容易被忽略、却最影响结论可信度的部分：
        # 报告写着 engine=copy，很容易让人以为"样本的写被重定向了"。实际上
        # copy 只隔离**样本自身及其同目录**，它对 C:\Windows\... 的绝对引用照旧
        # 打到真实系统。所以 absolute_path_redirect / limitation 必须显式展示。
        iso = result.get("isolation") if isinstance(result.get("isolation"), dict) else {}
        if iso:
            lines.append(f"· 隔离引擎 {iso.get('engine') or 'none'}"
                         f"　完整性 {iso.get('integrity_level') or '--'}"
                         f"　网络{'已阻断' if iso.get('network_blocked') else '未阻断'}")
            if iso.get("firewall_rule_removed") is False:
                lines.append("· **防火墙规则未清理，可能仍留在系统上**")
            caps = iso.get("capabilities") if isinstance(iso.get("capabilities"), dict) else {}
            if caps.get("absolute_path_redirect") is False:
                lines.append("· 绝对路径重定向　不支持（**这是限制，不是特性**）")
            if caps.get("registry_redirect") is False:
                lines.append("· 注册表重定向　不支持")
            if caps.get("coverage"):
                lines.append(f"· 隔离范围　{caps.get('coverage')}")
            if caps.get("limitation"):
                lines.append(f"· 能力限制（原文）　{caps.get('limitation')}")
            for note in (iso.get("engine_notes") or [])[:3]:
                lines.append(f"· 引擎说明　{note}")
            if iso.get("degraded_reason"):
                lines.append(f"· **隔离降级：{iso.get('degraded_reason')}**"
                             "（隔离不完整，结论可信度下降）")

        # ── 内存镜像扫描 ──
        mem = result.get("memory_scan") if isinstance(result.get("memory_scan"), dict) else {}
        if mem:
            if not mem.get("ok"):
                # 未覆盖 ≠ 安全。必须显示原因，且不能让人误以为"内存没问题"。
                lines.append(f"· 内存镜像　未覆盖（{mem.get('error') or '未执行'}）"
                             "　— **不能据此认定安全**")
            else:
                hits = mem.get("hits") or []
                lines.append(f"· 内存镜像　模块 {mem.get('modules_read')}"
                             f"/{mem.get('modules_total')}"
                             f"　扫描 {fmt_size(mem.get('scanned_bytes'))}"
                             f"　耗时 {mem.get('elapsed_ms')}ms"
                             f"　命中 {len(hits)}")
                if mem.get("truncated"):
                    lines.append("· 内存镜像　**超出上限被截断，未扫完**")
                if mem.get("interpretation"):
                    lines.append(f"· 内存结论　{mem.get('interpretation')}")
                for h in hits[:4]:
                    if isinstance(h, dict):
                        lines.append(f"　· 内存命中 {h.get('rule')}"
                                     f"（置信度 {h.get('confidence')}，"
                                     f"模块 {h.get('_module') or h.get('module')}）")

        # 注意：判断"没看到行为"不能用 len(lines) —— 上面刚追加了隔离/内存两项，
        # 会把本来就不足两行的报告顶到两行以上，提示就再也不出现了。
        if not behaviors and not indicators:
            lines.append("未观察到明显可疑行为。")
        self._sandbox_result.configure(text="\n".join(lines), fg=color)
        self.ctx.say(f"沙箱判定：{LEVEL_TEXT.get(verdict, verdict)}",
                     "ok" if verdict == "clean" else "warn")

    def _sandbox_cancel(self):
        if not self._sandbox_job or not self._sandbox_running:
            return
        run_async(self, lambda: self.client.job_cancel(self._sandbox_job),
                  lambda res: self.ctx.say(
                      "已请求取消" if res.ok else f"取消失败：{res.error}",
                      "warn" if res.ok else "error"))

    def _set_sandbox_busy(self, busy: bool):
        try:
            if busy:
                self._sandbox_btn.configure(state="disabled", bg=T.BORDER,
                                            fg=T.TEXT_MUTED)
                self._sandbox_cancel_btn.configure(state="normal", bg=T.DANGER,
                                                   fg="#ffffff", cursor="hand2")
            else:
                self._sandbox_btn.configure(state="normal", bg=T.ACCENT,
                                            fg=T.TEXT_ON_ACCENT)
                self._sandbox_cancel_btn.configure(state="disabled", bg=T.BORDER,
                                                   fg=T.TEXT_MUTED, cursor="")
        except tk.TclError:
            pass

    # ─────────────────────────────────────────────────────────
    # 下载防护
    # ─────────────────────────────────────────────────────────

    def _build_download_guard(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "下载防护", T.BG_CARD).pack(side="left")
        self._dl_stats = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                                  font=T.font(9))
        self._dl_stats.pack(side="right")

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x", pady=(10, 0))
        box = tk.Frame(row, bg=T.BG_CARD)
        box.pack(side="left", fill="x", expand=True)
        tk.Label(box, text="监控下载目录，新文件落地即扫描",
                 bg=T.BG_CARD, fg=T.TEXT_MUTED, font=T.font(9),
                 anchor="w").pack(fill="x")
        self._dl_switch = W.ToggleSwitch(row, on_toggle=self._dl_toggle,
                                         initial=False)
        self._dl_switch.pack(side="right")

        # 监控目录
        dirs_row = tk.Frame(card.inner, bg=T.BG_CARD)
        dirs_row.pack(fill="x", pady=(12, 0))
        self._dl_dirs = W.KeyValueRow(card.inner, "监控目录")
        self._dl_dirs.pack(fill="x", pady=(10, 0))
        btns = tk.Frame(card.inner, bg=T.BG_CARD)
        btns.pack(fill="x", pady=(8, 0))
        W.button(btns, "添加目录…", self._dl_add_dir, "ghost").pack(side="left")
        W.button(btns, "刷新", self._refresh_download, "ghost").pack(
            side="left", padx=(8, 0))

    def _refresh_download(self):
        run_async(self, self.client.download_guard_stats, self._apply_download)
        run_async(self, self.client.download_guard_dirs, self._apply_dl_dirs)

    def _apply_download(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        d = res.data
        self._dl_switch.set(bool(d.get("enabled")), notify=False)
        self._dl_stats.configure(
            text=f"已扫描 {fmt_int(d.get('scan_count'))} · "
                 f"检出 {fmt_int(d.get('threat_count'))}")

    def _apply_dl_dirs(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        dirs = res.data.get("dirs") or []
        self._dl_dirs.set_value("；".join(str(x) for x in dirs) if dirs else "无")

    def _dl_toggle(self, enabled: bool):
        def done(res):
            if res.ok:
                self.ctx.say(f"下载防护已{'开启' if enabled else '关闭'}", "ok")
            else:
                self._dl_switch.set(not enabled, notify=False)
                self.ctx.say(f"切换失败：{res.error}", "error")
            self._refresh_download()

        run_async(self, lambda: self.client.download_guard_toggle(enabled), done)

    def _dl_add_dir(self):
        try:
            path = filedialog.askdirectory(title="选择要监控的下载目录")
        except Exception as exc:
            self.ctx.say(f"打开目录选择器失败：{exc}", "error")
            return
        if not path:
            return

        def done(res):
            if res.ok and (not isinstance(res.data, dict)
                           or res.data.get("success", True)):
                self.ctx.say(f"已添加监控目录：{path}", "ok")
            else:
                self.ctx.say("添加目录失败", "error")
            self._refresh_download()

        run_async(self, lambda: self.client.download_guard_dir_add(path), done)

    # ─────────────────────────────────────────────────────────
    # 网络急救
    # ─────────────────────────────────────────────────────────

    def _build_network(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "网络急救", T.BG_CARD).pack(side="left")
        self._net_hint = tk.Label(head, text="尚未检查", bg=T.BG_CARD,
                                  fg=T.TEXT_MUTED, font=T.font(9))
        self._net_hint.pack(side="right")

        ind = tk.Frame(card.inner, bg=T.BG_CARD)
        ind.pack(fill="x", pady=(10, 10))
        self._net_inds = {}
        for key, label in (("dns_ok", "DNS 解析"), ("ping_ok", "外网 Ping"),
                           ("internet_ok", "互联网"), ("hosts_ok", "HOSTS"),
                           ("lsp_ok", "LSP/Winsock")):
            item = Indicator(ind, label)
            item.pack(side="left", padx=(0, 18))
            self._net_inds[key] = item

        btns = tk.Frame(card.inner, bg=T.BG_CARD)
        btns.pack(fill="x")
        W.button(btns, "检查网络", self._net_check, "ghost").pack(side="left")
        W.button(btns, "修复 HOSTS", lambda: self._net_repair("hosts"),
                 "ghost").pack(side="left", padx=(8, 0))
        W.button(btns, "刷新 DNS", lambda: self._net_repair("dns"),
                 "ghost").pack(side="left", padx=(8, 0))
        W.button(btns, "重置 LSP", lambda: self._net_repair("lsp"),
                 "ghost").pack(side="left", padx=(8, 0))
        W.button(btns, "一键断网急救", lambda: self._net_repair("all"),
                 "danger").pack(side="left", padx=(8, 0))

        self._net_details = W.muted_label(card.inner, "", T.BG_CARD, size=9)
        self._net_details.pack(fill="x", pady=(10, 0))

    def _net_check(self):
        self._net_hint.configure(text="检查中…", fg=T.TEXT_SECONDARY)

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self._net_hint.configure(text=f"检查失败：{res.error}", fg=T.DANGER)
                return
            d = res.data
            for key, item in self._net_inds.items():
                if key in d:
                    item.set(bool(d[key]))
            ok_count = sum(1 for k in self._net_inds if d.get(k))
            total = len(self._net_inds)
            color = T.SUCCESS if ok_count == total else T.WARNING
            self._net_hint.configure(text=f"{ok_count}/{total} 项正常", fg=color)

            details = d.get("details") or []
            text = " · ".join(str(x) for x in details[:6])
            if len(text) > 150:
                text = text[:147] + "…"
            self._net_details.configure(text=text)

        run_async(self, self.client.network_check, done)

    def _net_repair(self, kind: str):
        names = {"all": "一键断网急救", "hosts": "修复 HOSTS",
                 "dns": "刷新 DNS 缓存", "lsp": "重置 Winsock/LSP"}
        if kind in ("all", "lsp"):
            # LSP 重置会改系统网络栈，属于需要重启才完全生效的操作，先确认
            if not messagebox.askyesno(
                    names[kind],
                    f"执行「{names[kind]}」？\n\n"
                    "该操作会修改系统网络配置，通常需要重启后完全生效。",
                    parent=self.winfo_toplevel()):
                return
        self.ctx.say(f"正在执行：{names[kind]}…", "info")

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self.ctx.say(f"{names[kind]}失败：{res.error}", "error")
                return
            d = res.data
            if kind == "all":
                ok = d.get("success")
                sub = d.get("results") or {}
                detail = "、".join(
                    f"{k}:{'成功' if isinstance(v, dict) and v.get('success') else '失败'}"
                    for k, v in sub.items())
                self.ctx.say(f"一键急救{'成功' if ok else '部分失败'}（{detail}）",
                             "ok" if ok else "warn")
            else:
                ok = d.get("success")
                msg = d.get("message") or d.get("detail") or ""
                self.ctx.say(f"{names[kind]}{'成功' if ok else '失败'}"
                             f"{('：' + str(msg)) if msg else ''}",
                             "ok" if ok else "warn")
            self._net_check()

        run_async(self, lambda: self.client.network_repair(kind), done)

    # ─────────────────────────────────────────────────────────
    # 系统漏洞修复
    # ─────────────────────────────────────────────────────────

    def _build_vulnfix(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "系统漏洞修复", T.BG_CARD).pack(side="left")
        self._vuln_tag = tk.Label(head, text="未扫描", bg=T.BG_CARD,
                                  fg=T.TEXT_MUTED, font=T.font(10, "bold"))
        self._vuln_tag.pack(side="left", padx=(10, 0))

        self._vuln_installed = W.KeyValueRow(card.inner, "已装补丁")
        self._vuln_missing = W.KeyValueRow(card.inner, "缺失补丁")
        self._vuln_time = W.KeyValueRow(card.inner, "上次扫描")
        for row in (self._vuln_installed, self._vuln_missing, self._vuln_time):
            row.pack(fill="x", pady=3)

        btns = tk.Frame(card.inner, bg=T.BG_CARD)
        btns.pack(fill="x", pady=(10, 0))
        self._vuln_scan_btn = W.button(btns, "扫描系统漏洞", self._vuln_scan)
        self._vuln_scan_btn.pack(side="left")
        self._vuln_cancel_btn = W.button(btns, "取消", self._vuln_cancel, "danger")
        self._vuln_cancel_btn.pack(side="left", padx=(8, 0))
        self._vuln_cancel_btn.configure(state="disabled", bg=T.BORDER,
                                        fg=T.TEXT_MUTED, cursor="")
        W.button(btns, "打开系统更新", self._vuln_open_update,
                 "ghost").pack(side="left", padx=(8, 0))

        W.muted_label(card.inner,
                      "只做检测与引导：不会擅自下载安装补丁，"
                      "「打开系统更新」仅唤起 Windows 更新设置页。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(10, 0))

    def _vuln_scan(self):
        if self._vuln_running:
            self.ctx.say("漏洞扫描已在进行中", "warn")
            return
        self._vuln_tag.configure(text="启动中…", fg=T.TEXT_SECONDARY)

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self._vuln_tag.configure(text="启动失败", fg=T.DANGER)
                self.ctx.say(f"启动漏洞扫描失败：{res.error}", "error")
                return
            self._vuln_job = res.data.get("task_id")
            self._vuln_running = True
            self._set_vuln_busy(True)
            self.ctx.say("漏洞扫描已启动", "ok")
            self._vuln_poll()

        run_async(self, lambda: self.client.job_create("vulnfix-scan"), done)

    def _vuln_poll(self):
        # 用标志位自停，**不要**调 cancel_timers()：那会把 on_show 注册的
        # 10 秒增强防护刷新也一起取消掉，漏洞扫描跑完后面板就再也不更新了。
        if not self._vuln_job or not self._vuln_running:
            return
        run_async(self, lambda: self.client.job_status(self._vuln_job),
                  self._vuln_apply)
        self.every(1000, self._vuln_poll)

    def _vuln_apply(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        d = res.data
        status = str(d.get("status") or "").lower()
        progress = d.get("progress")
        current = d.get("current") or ""
        label = {"queued": "排队中", "running": "扫描中", "completed": "已完成",
                 "cancelled": "已取消", "failed": "失败"}.get(status, status)
        if isinstance(progress, (int, float)) and status == "running":
            label = f"{label} {progress:.0f}%"
        color = {"completed": T.SUCCESS, "failed": T.DANGER,
                 "cancelled": T.WARNING}.get(status, T.ACCENT)
        self._vuln_tag.configure(text=label, fg=color)
        if current:
            self._vuln_time.set_value(str(current)[:70])

        if status in ("completed", "cancelled", "failed"):
            # 停掉轮询即可，其余周期性任务（增强防护面板）继续保留
            self._vuln_running = False
            self._set_vuln_busy(False)
            if status == "failed":
                self.ctx.say(f"漏洞扫描失败：{d.get('error')}", "error")
            elif status == "cancelled":
                self.ctx.say("漏洞扫描已取消", "warn")
            else:
                self._apply_vuln_report(d.get("result"))

    def _apply_vuln_report(self, result):
        if not isinstance(result, dict):
            return
        if result.get("cancelled"):
            self.ctx.say("漏洞扫描已取消", "warn")
            return
        installed = result.get("installed_count", 0)
        missing = result.get("missing_count", 0)
        all_patched = result.get("all_patched")
        self._vuln_installed.set_value(fmt_int(installed))
        self._vuln_missing.set_value(fmt_int(missing),
                                     None if not missing else T.WARNING)
        self._vuln_time.set_value(str(result.get("scan_time") or "--"))
        if all_patched:
            self.ctx.say(f"漏洞扫描完成：已装 {installed} 个补丁，无缺失项", "ok")
        else:
            critical = result.get("critical_missing") or []
            extra = f"（含高危 {len(critical)} 项）" if critical else ""
            self.ctx.say(f"漏洞扫描完成：缺失 {missing} 项{extra}", "warn")

    def _vuln_cancel(self):
        if not self._vuln_job or not self._vuln_running:
            return
        run_async(self, lambda: self.client.job_cancel(self._vuln_job),
                  lambda res: self.ctx.say(
                      "已请求取消" if res.ok else f"取消失败：{res.error}",
                      "warn" if res.ok else "error"))

    def _set_vuln_busy(self, busy: bool):
        try:
            if busy:
                self._vuln_scan_btn.configure(state="disabled", bg=T.BORDER,
                                              fg=T.TEXT_MUTED)
                self._vuln_cancel_btn.configure(state="normal", bg=T.DANGER,
                                                fg="#ffffff", cursor="hand2")
            else:
                self._vuln_scan_btn.configure(state="normal", bg=T.ACCENT,
                                              fg=T.TEXT_ON_ACCENT)
                self._vuln_cancel_btn.configure(state="disabled", bg=T.BORDER,
                                                fg=T.TEXT_MUTED, cursor="")
        except tk.TclError:
            pass

    def _vuln_open_update(self):
        def done(res):
            if res.ok and isinstance(res.data, dict) and res.data.get("ok"):
                self.ctx.say(res.data.get("msg") or "已打开系统更新", "ok")
            elif res.ok and isinstance(res.data, dict):
                self.ctx.say(res.data.get("msg") or "无法打开系统更新", "warn")
            else:
                self.ctx.say(f"打开系统更新失败：{res.error}", "error")

        run_async(self, self.client.vulnfix_open_update, done)

    # ─────────────────────────────────────────────────────────
    # U 盘与外设
    # ─────────────────────────────────────────────────────────

    def _build_usb(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "U 盘与外设管控", T.BG_CARD).pack(anchor="w")

        self._usb_drives = W.KeyValueRow(card.inner, "可移动盘")
        self._usb_immune = W.KeyValueRow(card.inner, "已免疫")
        self._usb_drives.pack(fill="x", pady=3)
        self._usb_immune.pack(fill="x", pady=3)

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x", pady=(10, 0))
        W.button(row, "一键免疫可移动盘", self._usb_immunize).pack(side="left")

        tk.Frame(card.inner, bg=T.BORDER, height=1).pack(fill="x", pady=12)

        self._usb_autorun = self._switch_row(
            card.inner, "禁用自动播放", "阻止 U 盘插入时自动运行",
            self._set_autorun)
        self._usb_storage = self._switch_row(
            card.inner, "禁用 USB 存储设备", "外设管控：需要管理员权限",
            self._set_usb_storage)

        W.muted_label(card.inner,
                      "「禁用 USB 存储设备」会阻断所有 U 盘读写，属高强度管控，"
                      "请确认没有正在使用的外接存储。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(10, 0))

    def _switch_row(self, parent, name: str, desc: str, on_toggle):
        row = tk.Frame(parent, bg=T.BG_CARD)
        row.pack(fill="x", pady=5)
        box = tk.Frame(row, bg=T.BG_CARD)
        box.pack(side="left", fill="x", expand=True)
        tk.Label(box, text=name, bg=T.BG_CARD, fg=T.TEXT_PRIMARY,
                 font=T.font(10, "bold"), anchor="w").pack(fill="x")
        tk.Label(box, text=desc, bg=T.BG_CARD, fg=T.TEXT_MUTED,
                 font=T.font(9), anchor="w").pack(fill="x")
        sw = W.ToggleSwitch(row, on_toggle=on_toggle, initial=False,
                            on_text="● 已启用", off_text="○ 已停用")
        sw.pack(side="right")
        return sw

    def _apply_usb(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        d = res.data
        drives = d.get("removable_drives") or []
        immune = d.get("immunized_drives") or []
        self._usb_drives.set_value("、".join(str(x) for x in drives) if drives else "未检测到")
        self._usb_immune.set_value("、".join(str(x) for x in immune) if immune else "无")

        # autorun_enabled=True 表示"自动播放开着"，所以开关的"已启用"对应禁用自动播放
        autorun_on = d.get("autorun_enabled")
        if autorun_on is not None:
            self._usb_autorun.set(not bool(autorun_on), notify=False)
        storage_on = d.get("usb_storage_enabled")
        if storage_on is not None:
            self._usb_storage.set(not bool(storage_on), notify=False)

    def _usb_immunize(self):
        def done(res):
            if res.ok and isinstance(res.data, dict):
                ok = res.data.get("success", True)
                done_list = res.data.get("immunized") or res.data.get("drives") or []
                msg = res.data.get("message") or ""
                if done_list:
                    self.ctx.say(f"已免疫 {len(done_list)} 个盘", "ok" if ok else "warn")
                else:
                    self.ctx.say(msg or ("免疫完成" if ok else "免疫失败"),
                                 "ok" if ok else "warn")
            else:
                self.ctx.say(f"免疫失败：{res.error}", "error")
            self._refresh_usb()

        run_async(self, lambda: self.client.usb_guard_immunize(), done)

    def _set_autorun(self, enabled: bool):
        self._toggle_usb(self._usb_autorun, enabled,
                         lambda: self.client.usb_guard_autorun(enabled),
                         "禁用自动播放")

    def _set_usb_storage(self, enabled: bool):
        if enabled and not messagebox.askyesno(
                "确认阻断 USB 存储",
                "禁用 USB 存储设备会阻断所有 U 盘的读写。\n\n确定继续？",
                parent=self.winfo_toplevel()):
            self._usb_storage.set(False, notify=False)
            return
        self._toggle_usb(self._usb_storage, enabled,
                         lambda: self.client.usb_guard_usb_storage(enabled),
                         "禁用 USB 存储")

    def _toggle_usb(self, switch, enabled: bool, work, name: str):
        def done(res):
            if res.ok:
                self.ctx.say(f"{name}：已{'启用' if enabled else '停用'}", "ok")
            else:
                switch.set(not enabled, notify=False)   # 回滚 UI
                self.ctx.say(f"{name}设置失败：{res.error}", "error")
            self._refresh_usb()

        run_async(self, work, done)

    # ─────────────────────────────────────────────────────────
    # 四个开关型防护
    # ─────────────────────────────────────────────────────────

    def _build_switches(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 8))
        W.section_title(card.inner, "增强防护", T.BG_CARD).pack(anchor="w",
                                                          pady=(0, 4))
        W.muted_label(card.inner,
                      "这八个防护后端的开关接口都收普通 {enabled}（不是 ToggleRequest），"
                      "因此不需要 module 字段。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(0, 10))

        # (键, 名称, 说明, 状态取法, 开关回调)
        self._guard_rows = [
            ("adblock", "弹窗拦截", "拦截软件弹窗与广告窗口",
             lambda d: f"累计拦截 {fmt_int(d.get('blocked_total'))} 次",
             self.client.adblock_toggle),
            ("registry_guard", "注册表监控", "监控关键注册表键的篡改",
             lambda d: f"累计拦截 {fmt_int(d.get('blocked_total'))} · "
                       f"监控键 {fmt_int(d.get('monitored_keys_count'))} 个",
             self.client.registry_guard_toggle),
            ("behavior_block", "高危行为阻断", "阻断危险命令行与进程行为",
             lambda d: f"累计拦截 {fmt_int(d.get('blocked_total'))} · "
                       f"监控命令 {fmt_int(d.get('monitored_commands'))} 条",
             self.client.behavior_block_toggle),
            ("process_guard", "进程拦截", "按黑白名单拦截进程启动",
             lambda d: f"累计拦截 {fmt_int(d.get('blocked_total'))} · "
                       f"黑名单 {fmt_int(d.get('blacklist_size'))}",
             self.client.process_guard_toggle),
            # ── tools.html 剩余四张卡 ──
            ("honeypot", "勒索诱捕", "布设诱饵文件，被加密即触发告警",
             lambda d: f"诱饵 {fmt_int(d.get('catch_count'))} 个",
             self.client.honeypot_toggle),
            ("browser_guard", "浏览器保护", "监控浏览器配置与主页劫持",
             lambda d: f"发现问题 {fmt_int(d.get('blocked_count'))} 项",
             self.client.browser_guard_toggle),
            ("camera", "摄像头保护", "监控摄像头占用，支持进程白名单",
             lambda d: f"记录 {fmt_int(d.get('blocked_count'))} · "
                       f"白名单 {fmt_int(len(d.get('whitelist') or []))}",
             self.client.camera_toggle),
            ("privacy", "隐私保护", "监控敏感文件访问、清理隐私痕迹",
             lambda d: f"痕迹 {fmt_int(d.get('trace_count'))} · "
                       f"类型 {fmt_int(len(d.get('trace_types') or []))}",
             self.client.privacy_toggle),
        ]

        self._guard_switches: dict[str, W.ToggleSwitch] = {}
        self._guard_stats: dict[str, tk.Label] = {}

        for key, name, desc, stat_fn, toggle in self._guard_rows:
            row = tk.Frame(card.inner, bg=T.BG_CARD)
            row.pack(fill="x", pady=6)
            box = tk.Frame(row, bg=T.BG_CARD)
            box.pack(side="left", fill="x", expand=True)
            tk.Label(box, text=name, bg=T.BG_CARD, fg=T.TEXT_PRIMARY,
                     font=T.font(10, "bold"), anchor="w").pack(fill="x")
            tk.Label(box, text=desc, bg=T.BG_CARD, fg=T.TEXT_MUTED,
                     font=T.font(9), anchor="w").pack(fill="x")
            stat = tk.Label(box, text="", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                            font=T.font(9), anchor="w")
            stat.pack(fill="x")
            self._guard_stats[key] = stat

            sw = W.ToggleSwitch(
                row, on_toggle=lambda v, k=key, t=toggle: self._toggle_guard(k, v, t),
                initial=False)
            sw.pack(side="right")
            self._guard_switches[key] = sw

        self._guard_stat_fns = {k: fn for k, _n, _d, fn, _t in self._guard_rows}

    def _toggle_guard(self, key: str, enabled: bool, toggle):
        name = next((n for k, n, _d, _f, _t in self._guard_rows if k == key), key)

        def done(res):
            if res.ok:
                self.ctx.say(f"{name}已{'启用' if enabled else '停用'}", "ok")
            else:
                sw = self._guard_switches.get(key)
                if sw is not None:
                    sw.set(not enabled, notify=False)   # 回滚 UI
                self.ctx.say(f"{name}切换失败：{res.error}", "error")
            self._refresh_guards()

        run_async(self, lambda: toggle(enabled), done)

    def _refresh_guards(self):
        fns = {
            "adblock": self.client.adblock_status,
            "registry_guard": self.client.registry_guard_status,
            "behavior_block": self.client.behavior_block_status,
            "process_guard": self.client.process_guard_status,
            "honeypot": self.client.honeypot_stats,
            "browser_guard": self.client.browser_guard_stats,
            "camera": self.client.camera_stats,
            "privacy": self.client.privacy_stats,
        }
        for key, fn in fns.items():
            run_async(self, fn, lambda res, k=key: self._apply_guard(k, res))

    def _apply_guard(self, key: str, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        d = res.data
        sw = self._guard_switches.get(key)
        if sw is not None and "enabled" in d:
            sw.set(bool(d["enabled"]), notify=False)
        stat = self._guard_stats.get(key)
        fn = self._guard_stat_fns.get(key)
        if stat is not None and fn is not None:
            try:
                stat.configure(text=fn(d))
            except tk.TclError:
                pass

    # ─────────────────────────────────────────────────────────
    # 生命周期
    # ─────────────────────────────────────────────────────────

    def on_show(self):
        self._net_check()
        self._refresh_usb()
        self._refresh_guards()
        self._refresh_download()
        self._refresh_url_lists()
        self._load_vuln_status()
        self.every(10000, self._refresh_guards)

    def on_hide(self):
        # 漏洞扫描轮询由 cancel_timers 一并取消；任务本身在后端继续跑
        self.cancel_timers()

    def _refresh_usb(self):
        run_async(self, self.client.usb_guard_status, self._apply_usb)

    def _load_vuln_status(self):
        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                return
            d = res.data
            if not d.get("scan_time"):
                self._vuln_tag.configure(text="未扫描", fg=T.TEXT_MUTED)
                return
            self._vuln_tag.configure(text="上次结果", fg=T.TEXT_SECONDARY)
            self._apply_vuln_report(d)

        run_async(self, self.client.vulnfix_status, done)
