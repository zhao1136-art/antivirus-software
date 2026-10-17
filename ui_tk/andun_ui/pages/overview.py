"""概览页：防护状态、关键统计、防护模块开关、待决威胁、最近活动。"""
from __future__ import annotations

import tkinter as tk

from .. import theme as T
from .. import widgets as W
from ..api import (fmt_int, fmt_time, run_async)
from ..app import Page

# 模块键 → 中文名（键取自 app.py 的 _protection_modules）
MODULE_LABELS = {
    "file_shield": ("实时文件防护", "扫描所有打开、创建和修改的文件"),
    "network_shield": ("网络威胁防护", "阻止恶意网站和网络攻击"),
    "behavior_shield": ("行为防护", "检测可疑程序和异常行为"),
    "ransomware_shield": ("勒索软件防护", "保护重要文件免受加密"),
    "process_guard": ("系统进程保护", "监控关键进程，检测注入与伪装"),
    "file_guard": ("文件防篡改", "关键系统文件完整性基线校验"),
}

REFRESH_MS = 5000


class OverviewPage(Page):
    key = "overview"
    title = "概览"
    glyph = "◈"

    def build(self):
        root = W.ScrollableFrame(self, bg=T.BG_APP)
        root.pack(fill="both", expand=True)
        body = root.content
        self._scroll = root

        pad = tk.Frame(body, bg=T.BG_APP)
        pad.pack(fill="both", expand=True, padx=22, pady=18)

        self._build_status_card(pad)
        self._build_stats(pad)
        self._build_pending(pad)
        self._build_modules(pad)
        self._build_activity(pad)

    # ── 状态卡 ──

    def _build_status_card(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        inner = card.inner

        left = tk.Frame(inner, bg=T.BG_CARD)
        left.pack(side="left", fill="x", expand=True)

        row = tk.Frame(left, bg=T.BG_CARD)
        row.pack(fill="x")
        self._dot = W.PulseDot(row, color=T.ACCENT, bg=T.BG_CARD)
        self._dot.pack(side="left", pady=(2, 0))
        self._state_label = tk.Label(row, text="正在检测防护状态…", bg=T.BG_CARD,
                                     fg=T.TEXT_PRIMARY, font=T.font(15, "bold"))
        self._state_label.pack(side="left", padx=(8, 0))

        self._state_hint = tk.Label(left, text="", bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                                    font=T.font(10), anchor="w", justify="left")
        self._state_hint.pack(fill="x", pady=(8, 0))

        right = tk.Frame(inner, bg=T.BG_CARD)
        right.pack(side="right")
        W.button(right, "快速扫描", lambda: self._quick_scan(), "accent").pack(side="left")
        W.button(right, "去扫描页", lambda: self.ctx.navigate("scan"), "ghost").pack(
            side="left", padx=(8, 0))

    # ── 统计卡 ──

    def _build_stats(self, parent):
        grid = tk.Frame(parent, bg=T.BG_APP)
        grid.pack(fill="x", pady=(0, 14))
        for col in range(4):
            grid.columnconfigure(col, weight=1, uniform="stat")

        self.stat_scanned = W.StatCard(grid, "累计扫描文件", accent=T.ACCENT)
        self.stat_blocked = W.StatCard(grid, "今日拦截威胁", accent=T.DANGER)
        self.stat_days = W.StatCard(grid, "累计守护", accent=T.WARNING)
        self.stat_quarantine = W.StatCard(grid, "隔离区文件", accent=T.ACCENT)
        self.stat_signatures = W.StatCard(grid, "特征库条目", accent=T.ACCENT)
        self.stat_c2_ip = W.StatCard(grid, "C2 IP 库", accent=T.DANGER)
        self.stat_c2_domain = W.StatCard(grid, "C2 域名库", accent=T.DANGER)
        self.stat_ioc = W.StatCard(grid, "恶意 IOC", accent=T.WARNING)

        cells = [self.stat_scanned, self.stat_blocked, self.stat_days,
                 self.stat_quarantine, self.stat_signatures, self.stat_c2_ip,
                 self.stat_c2_domain, self.stat_ioc]
        for idx, cell in enumerate(cells):
            cell.grid(row=idx // 4, column=idx % 4, sticky="nsew", padx=6, pady=6)

    # ── 待决威胁 ──

    def _build_pending(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        self._pending_card = card
        inner = card.inner
        head = tk.Frame(inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "待决威胁", T.BG_CARD).pack(side="left")
        self._pending_count = tk.Label(head, text="", bg=T.BG_CARD, fg=T.WARNING,
                                       font=T.font(10, "bold"))
        self._pending_count.pack(side="left", padx=(8, 0))

        self._pending_host = tk.Frame(inner, bg=T.BG_CARD)
        self._pending_host.pack(fill="x", pady=(10, 0))
        self._pending_empty = W.muted_label(
            self._pending_host, "当前无待决威胁。YARA 命中后会在此挂起，等待你的决定。",
            T.BG_CARD)
        self._pending_empty.pack(anchor="w")
        self._pending_rows: list[tk.Frame] = []

    # ── 防护模块 ──

    def _build_modules(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "防护模块", T.BG_CARD).pack(anchor="w",
                                                             pady=(0, 10))
        self._switches: dict[str, W.ToggleSwitch] = {}
        for key, (name, desc) in MODULE_LABELS.items():
            row = tk.Frame(card.inner, bg=T.BG_CARD)
            row.pack(fill="x", pady=5)
            text = tk.Frame(row, bg=T.BG_CARD)
            text.pack(side="left", fill="x", expand=True)
            tk.Label(text, text=name, bg=T.BG_CARD, fg=T.TEXT_PRIMARY,
                     font=T.font(10, "bold"), anchor="w").pack(fill="x")
            tk.Label(text, text=desc, bg=T.BG_CARD, fg=T.TEXT_MUTED,
                     font=T.font(9), anchor="w").pack(fill="x")
            sw = W.ToggleSwitch(row, on_toggle=lambda v, k=key: self._toggle_module(k, v),
                                initial=True)
            sw.pack(side="right")
            self._switches[key] = sw

    # ── 最近活动 ──

    def _build_activity(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 8))
        W.section_title(card.inner, "最近活动", T.BG_CARD).pack(anchor="w",
                                                            pady=(0, 10))
        self._activity_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._activity_host.pack(fill="x")

    # ── 数据加载 ──

    def on_show(self):
        self._dot.start()
        self.refresh()
        self.every(REFRESH_MS, self.refresh)

    def on_hide(self):
        self._dot.stop()
        self.cancel_timers()

    def refresh(self):
        if not self.winfo_exists():
            return
        run_async(self, self.client.stats_overview, self._apply_overview,
                  lambda exc: self.ctx.say(f"读取统计失败: {exc}", "error"))
        run_async(self, self.client.protection_status, self._apply_protection)
        run_async(self, self.client.threats_pending, self._apply_pending)
        run_async(self, self.client.stats_activity, self._apply_activity)

    def _apply_overview(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self._state_label.configure(text="无法连接后端")
            self._state_hint.configure(text=res.error or "请确认后端已启动")
            return
        d = res.data
        self.stat_scanned.set_value(fmt_int(d.get("total_scanned")))
        self.stat_blocked.set_value(fmt_int(d.get("today_blocked")))
        days = d.get("guard_days") or d.get("protection_days") or 0
        self.stat_days.set_value(f"{fmt_int(days)} 天")
        self.stat_quarantine.set_value(fmt_int(d.get("quarantine_count")))
        self.stat_signatures.set_value(fmt_int(d.get("signatures_count")))
        self.stat_c2_ip.set_value(fmt_int(d.get("c2_ip_count")))
        self.stat_c2_domain.set_value(fmt_int(d.get("c2_domain_count")))
        self.stat_ioc.set_value(fmt_int(d.get("malware_ioc_count")))

        blocked = d.get("today_blocked") or 0
        self._state_label.configure(text="系统处于保护中")
        self._state_hint.configure(
            text=f"累计扫描 {fmt_int(d.get('total_scanned'))} 个文件，"
                 f"今日拦截 {fmt_int(blocked)} 项威胁，"
                 f"特征库 {fmt_int(d.get('signatures_count'))} 条。")

    def _apply_protection(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        modules = res.data.get("modules") or {}
        for key, sw in self._switches.items():
            if key in modules:
                # set(notify=False)：这是同步服务端状态，不该触发回写
                sw.set(bool(modules[key]), notify=False)

    def _apply_pending(self, res):
        for row in self._pending_rows:
            try:
                row.destroy()
            except Exception:
                pass
        self._pending_rows.clear()

        if not res.ok or not isinstance(res.data, dict):
            # 后端不可用时也要把占位文案放回去：否则上一次有待决项时
            # 已经 pack_forget 过 _pending_empty，这里直接 return 会留一片空白。
            self._pending_count.configure(text="")
            self._show_pending_hint("无法读取待决威胁（后端未连接）")
            return
        items = res.data.get("pending") or []
        timeout = res.data.get("timeout") or 0
        self._pending_count.configure(text=f"{len(items)} 项" if items else "")

        if not items:
            self._show_pending_hint("当前无待决威胁。YARA 命中后会在此挂起，等待你的决定。")
            return
        try:
            self._pending_empty.pack_forget()
        except Exception:
            pass

        for item in items:
            self._pending_rows.append(self._pending_row(item, timeout))

    def _show_pending_hint(self, text: str):
        """显示/恢复占位文案（复用同一个 Label，不反复建控件）。"""
        try:
            if not self._pending_empty.winfo_exists():
                self._pending_empty = W.muted_label(self._pending_host, text, T.BG_CARD)
            else:
                self._pending_empty.configure(text=text)
            self._pending_empty.pack(anchor="w")
        except tk.TclError:
            pass

    def _pending_row(self, item: dict, timeout):
        pid = str(item.get("id") or item.get("pending_id") or "")
        path = item.get("path") or item.get("file_path") or ""
        name = item.get("signature") or item.get("threat_name") or "未知威胁"
        level = item.get("threat_level") or "medium"

        row = tk.Frame(self._pending_host, bg=T.BG_HOVER)
        row.pack(fill="x", pady=3)
        pad = tk.Frame(row, bg=T.BG_HOVER)
        pad.pack(fill="x", padx=10, pady=8)

        color = T.DANGER if level in ("high", "critical") else T.WARNING
        top = tk.Frame(pad, bg=T.BG_HOVER)
        top.pack(fill="x")
        tk.Label(top, text="●", bg=T.BG_HOVER, fg=color,
                 font=T.font(10)).pack(side="left")
        tk.Label(top, text=name, bg=T.BG_HOVER, fg=T.TEXT_PRIMARY,
                 font=T.font(10, "bold")).pack(side="left", padx=(6, 0))
        tk.Label(top, text=f"{timeout:.0f}s 内无决定将自动隔离", bg=T.BG_HOVER,
                 fg=T.TEXT_MUTED, font=T.font(9)).pack(side="left", padx=(10, 0))

        btns = tk.Frame(top, bg=T.BG_HOVER)
        btns.pack(side="right")
        W.button(btns, "隔离", lambda p=pid: self._decide(p, "quarantine"),
                 "danger").pack(side="left")
        W.button(btns, "忽略", lambda p=pid: self._decide(p, "ignore"),
                 "ghost").pack(side="left", padx=(6, 0))

        W.muted_label(pad, path, T.BG_HOVER, size=9, mono=True).pack(fill="x",
                                                                   pady=(4, 0))
        return row

    def _decide(self, pending_id: str, action: str):
        if not pending_id:
            return
        run_async(self, lambda: self.client.threat_decide(pending_id, action),
                  lambda r: self._after_decide(r, action))

    def _after_decide(self, res, action: str):
        if res.ok:
            self.ctx.say("已提交处置决定" if action == "quarantine" else "已忽略该威胁",
                         "ok")
        else:
            self.ctx.say(f"提交失败: {res.error}", "error")
        self.refresh()

    def _toggle_module(self, key: str, enabled: bool):
        def done(res):
            if res.ok:
                self.ctx.say(f"{MODULE_LABELS.get(key, (key,))[0]}已"
                             f"{'开启' if enabled else '关闭'}", "ok")
            else:
                # 回滚 UI：服务端没接受，界面不能停在错误状态
                sw = self._switches.get(key)
                if sw is not None:
                    sw.set(not enabled, notify=False)
                self.ctx.say(f"切换失败: {res.error}", "error")

        run_async(self, lambda: self.client.protection_toggle(key, enabled), done)

    def _quick_scan(self):
        def done(res):
            if res.ok and isinstance(res.data, dict):
                tid = res.data.get("task_id", "")
                self.ctx.say(f"快速扫描已启动（任务 {tid[:8]}）", "ok")
                self.ctx.navigate("scan")
            else:
                self.ctx.say(f"启动扫描失败: {res.error}", "error")

        run_async(self, lambda: self.client.scan_start("quick"), done)

    def _apply_activity(self, res):
        for child in self._activity_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._activity_host, "暂无活动记录", T.BG_CARD).pack(anchor="w")
            return

        threats = res.data.get("threats") or []
        scans = res.data.get("scans") or []
        if not threats and not scans:
            W.muted_label(self._activity_host, "暂无活动记录", T.BG_CARD).pack(anchor="w")
            return

        for item in threats[:5]:
            self._activity_line(
                "⚠", T.DANGER,
                item.get("path") or item.get("signature") or "威胁事件",
                f"{item.get('signature') or item.get('engine') or ''} "
                f"{fmt_time(item.get('timestamp'))}")
        for item in scans[:5]:
            event = item.get("event") or "扫描"
            stats = item.get("stats") or {}
            detail = ""
            if isinstance(stats, dict) and stats:
                detail = (f"扫描 {fmt_int(stats.get('files_scanned'))} / "
                          f"威胁 {fmt_int(stats.get('threats_found'))}")
            self._activity_line("✓", T.TEXT_SECONDARY, event,
                                f"{detail} {fmt_time(item.get('timestamp'))}")

    def _activity_line(self, glyph: str, color: str, title: str, sub: str):
        row = tk.Frame(self._activity_host, bg=T.BG_CARD)
        row.pack(fill="x", pady=3)
        tk.Label(row, text=glyph, bg=T.BG_CARD, fg=color,
                 font=T.font(11)).pack(side="left", padx=(0, 8))
        box = tk.Frame(row, bg=T.BG_CARD)
        box.pack(side="left", fill="x", expand=True)
        text = str(title)
        if len(text) > 96:
            text = text[:93] + "…"
        tk.Label(box, text=text, bg=T.BG_CARD, fg=T.TEXT_PRIMARY,
                 font=T.font(10), anchor="w").pack(fill="x")
        tk.Label(box, text=sub, bg=T.BG_CARD, fg=T.TEXT_MUTED,
                 font=T.font(9), anchor="w").pack(fill="x")
