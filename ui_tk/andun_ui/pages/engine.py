"""引擎启动页：引擎清单与状态、云查杀优先级、ETW / AMSI 启停、辅助功能开关。

后端契约（app.py）：
* ``GET  /api/v1/version``        → ``{version, name, api, engine{}, yara{}, features[]}``
* ``GET  /api/v1/scan/perf-stats``→ 扫描性能统计 + ``yara{}`` + ``realtime_queue{}``
* ``GET  /api/v1/protection/status`` / ``POST .../toggle`` ``{module, enabled}``
* ``GET  /api/v1/cloud/engines``  → ``{engine_order[], engines:{avic,threatbook,otx}, last_error}``
* ``GET  /api/v1/deep/engines``   → 洞渊引擎（capa / ClamAV / YARA）可用性
* ``GET  /api/v1/etw/status`` / ``POST /api/v1/etw/start|stop``
* ``GET  /api/v1/etw/events``     ← **消费式**：后端返回后会清空队列
* ``GET  /api/v1/amsi/status`` / ``POST /api/v1/amsi/register|unregister``
* ``GET  /api/v1/features/status``→ 辅助功能总览

两处必须显式提示用户的风险
--------------------------
1. **ETW 事件是消费式的**：``/api/v1/etw/events`` 取一次就清空，所以本页**不自动轮询**
   它（否则会把事件从其他消费者嘴里抢走），只在你点按钮时取一次。
2. **AMSI 注册有系统性风险**：``amsi_manager.py`` 的文档明确记录 —— 只写
   ``HKLM\\...\\AMSI\\Providers`` 而不写 COM CLSID，会让**全系统 AMSI 失效**
   （``AmsiInitialize`` 返回 ``0x80070002``），比"没注册"更糟；而注销时删掉
   Providers 父键会连带清掉别的厂商注册。所以注册/注销都要求二次确认。
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from .. import theme as T
from .. import widgets as W
from ..api import fmt_int, run_async
from ..app import Page

REFRESH_MS = 8000

MODULE_LABELS = {
    "file_shield": "实时文件防护",
    "network_shield": "网络威胁防护",
    "behavior_shield": "行为防护",
    "ransomware_shield": "勒索软件防护",
    "process_guard": "系统进程保护",
    "file_guard": "文件防篡改",
}

# features/status 的键 → 中文名
FEATURE_LABELS = (
    ("auto_start", "开机自启"),
    ("shell_menu", "右键菜单"),
    ("game_mode", "游戏模式"),
    ("usb_scan", "USB 自动扫描"),
    ("tray_icon", "系统托盘"),
)

ENGINE_LABELS = {
    "avic": "AVIC 云查杀",
    "threatbook": "微步在线",
    "otx": "AlienVault OTX",
}


class EnginePage(Page):
    key = "engine"
    title = "引擎启动"
    glyph = "◉"

    def build(self):
        root = W.ScrollableFrame(self, bg=T.BG_APP)
        root.pack(fill="both", expand=True)
        pad = tk.Frame(root.content, bg=T.BG_APP)
        pad.pack(fill="both", expand=True, padx=22, pady=18)

        self._build_overview(pad)
        self._build_modules(pad)
        self._build_cloud(pad)
        self._build_deep(pad)
        self._build_etw(pad)
        self._build_amsi(pad)
        self._build_features(pad)

    # ── 引擎概览 ──

    def _build_overview(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "引擎概览", T.BG_CARD).pack(side="left")
        self._engine_tag = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                                    font=T.font(10, "bold"))
        self._engine_tag.pack(side="left", padx=(10, 0))
        W.button(head, "刷新", self.refresh, "ghost").pack(side="right")

        self.kv_version = W.KeyValueRow(card.inner, "引擎版本")
        self.kv_name = W.KeyValueRow(card.inner, "版本名称")
        self.kv_scans = W.KeyValueRow(card.inner, "累计扫描")
        self.kv_cache = W.KeyValueRow(card.inner, "缓存命中率")
        self.kv_yara = W.KeyValueRow(card.inner, "YARA 规则")
        self.kv_avg = W.KeyValueRow(card.inner, "平均耗时")
        self.kv_queue = W.KeyValueRow(card.inner, "实时队列")
        for row in (self.kv_version, self.kv_name, self.kv_scans, self.kv_cache,
                    self.kv_yara, self.kv_avg, self.kv_queue):
            row.pack(fill="x", pady=3)

    # ── 防护模块 ──

    def _build_modules(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "防护模块", T.BG_CARD).pack(anchor="w",
                                                            pady=(0, 10))
        self._switches: dict[str, W.ToggleSwitch] = {}
        for key, name in MODULE_LABELS.items():
            row = tk.Frame(card.inner, bg=T.BG_CARD)
            row.pack(fill="x", pady=4)
            tk.Label(row, text=name, bg=T.BG_CARD, fg=T.TEXT_PRIMARY,
                     font=T.font(10), anchor="w").pack(side="left", fill="x",
                                                       expand=True)
            sw = W.ToggleSwitch(row, on_toggle=lambda v, k=key: self._toggle_module(k, v),
                                initial=True, on_text="● 运行中", off_text="○ 已停用")
            sw.pack(side="right")
            self._switches[key] = sw

    def _toggle_module(self, key: str, enabled: bool):
        def done(res):
            if res.ok:
                self.ctx.say(f"{MODULE_LABELS.get(key, key)}已"
                             f"{'开启' if enabled else '关闭'}", "ok")
            else:
                sw = self._switches.get(key)
                if sw is not None:
                    sw.set(not enabled, notify=False)   # 回滚
                self.ctx.say(f"切换失败：{res.error}", "error")

        run_async(self, lambda: self.client.protection_toggle(key, enabled), done)

    # ── 云查杀引擎 ──

    def _build_cloud(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "云查杀引擎", T.BG_CARD).pack(side="left")
        self._cloud_order = tk.Label(head, text="", bg=T.BG_CARD,
                                     fg=T.TEXT_SECONDARY, font=T.font(9))
        self._cloud_order.pack(side="right")
        self._cloud_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._cloud_host.pack(fill="x", pady=(10, 0))

    def _apply_cloud(self, res):
        for child in self._cloud_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._cloud_host, "无法读取云引擎配置", T.BG_CARD,
                          size=9, fg=T.DANGER).pack(anchor="w")
            return
        d = res.data
        order = d.get("engine_order") or []
        if order:
            self._cloud_order.configure(
                text="优先级：" + " → ".join(str(x) for x in order))
        else:
            self._cloud_order.configure(text="")

        engines = d.get("engines") if isinstance(d.get("engines"), dict) else {}
        if not engines:
            W.muted_label(self._cloud_host, "未配置云引擎", T.BG_CARD,
                          size=9).pack(anchor="w")
        for key, info in engines.items():
            self._cloud_row(str(key), info if isinstance(info, dict) else {})

        last_error = d.get("last_error")
        if last_error:
            W.muted_label(self._cloud_host, f"最近错误：{last_error}", T.BG_CARD,
                          size=9, fg=T.WARNING).pack(anchor="w", pady=(6, 0))

    def _cloud_row(self, key: str, info: dict):
        available = info.get("available")
        enabled = info.get("enabled")
        ok = bool(available) if available is not None else bool(enabled)
        row = tk.Frame(self._cloud_host, bg=T.BG_CARD)
        row.pack(fill="x", pady=2)
        tk.Label(row, text="●", bg=T.BG_CARD,
                 fg=T.SUCCESS if ok else T.TEXT_MUTED,
                 font=T.font(10)).pack(side="left")
        tk.Label(row, text=ENGINE_LABELS.get(key, key), bg=T.BG_CARD,
                 fg=T.TEXT_PRIMARY, font=T.font(10), width=16,
                 anchor="w").pack(side="left", padx=(6, 0))

        bits = []
        for field, label in (("state", "状态"), ("quota", "配额"),
                             ("calls", "调用"), ("hits", "命中"),
                             ("last_error", "错误")):
            if info.get(field) not in (None, "", []):
                bits.append(f"{label} {info[field]}")
        text = " · ".join(bits) if bits else ("已启用" if ok else "未启用")
        if len(text) > 96:
            text = text[:95] + "…"
        tk.Label(row, text=text, bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(9), anchor="w").pack(side="left", padx=(8, 0))

    # ── 深度分析引擎 ──

    def _build_deep(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "深度分析引擎", T.BG_CARD).pack(anchor="w")
        W.muted_label(card.inner,
                      "capa 行为规则 / ClamAV / YARA 的可用性。"
                      "本体扫描入口在「安全工具 → 沙箱分析」与扫描页。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))
        self._deep_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._deep_host.pack(fill="x")

    def _apply_deep(self, res):
        for child in self._deep_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._deep_host, "无法读取深度引擎状态", T.BG_CARD,
                          size=9, fg=T.DANGER).pack(anchor="w")
            return
        data = res.data
        if not data:
            W.muted_label(self._deep_host, "无数据", T.BG_CARD,
                          size=9).pack(anchor="w")
            return
        # 字段结构由 deep_analyzer.engines_status() 决定，按扁平键值对渲染，
        # 嵌套 dict 展开一层 —— 不做字段假设，避免猜错。
        for key, value in data.items():
            if isinstance(value, dict):
                inner = " · ".join(f"{k}={v}" for k, v in list(value.items())[:6])
                self._deep_line(str(key), inner)
            elif isinstance(value, (list, tuple)):
                self._deep_line(str(key), f"{len(value)} 项")
            else:
                self._deep_line(str(key), str(value))

    def _deep_line(self, key: str, value: str):
        row = tk.Frame(self._deep_host, bg=T.BG_CARD)
        row.pack(fill="x", pady=1)
        tk.Label(row, text=key, bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(9), width=18, anchor="w").pack(side="left")
        if len(value) > 92:
            value = value[:91] + "…"
        tk.Label(row, text=value, bg=T.BG_CARD, fg=T.TEXT_PRIMARY,
                 font=T.mono(9), anchor="w").pack(side="left")

    # ── ETW ──

    def _build_etw(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "ETW 事中检测", T.BG_CARD).pack(side="left")
        self._etw_tag = tk.Label(head, text="未知", bg=T.BG_CARD,
                                 fg=T.TEXT_MUTED, font=T.font(10, "bold"))
        self._etw_tag.pack(side="left", padx=(10, 0))
        self._etw_hint = tk.Label(card.inner, text="", bg=T.BG_CARD,
                                  fg=T.TEXT_MUTED, font=T.font(9), anchor="w",
                                  justify="left", wraplength=760)
        self._etw_hint.pack(fill="x", pady=(6, 0))

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x", pady=(10, 0))
        self._etw_start = W.button(row, "启动 ETW", self._etw_do_start)
        self._etw_start.pack(side="left")
        self._etw_stop = W.button(row, "停止 ETW", self._etw_do_stop, "ghost")
        self._etw_stop.pack(side="left", padx=(8, 0))
        W.button(row, "取一次事件", self._etw_fetch_events, "ghost").pack(
            side="left", padx=(8, 0))

        self._etw_events = tk.Label(card.inner, text="", bg=T.BG_CARD,
                                    fg=T.TEXT_SECONDARY, font=T.font(9),
                                    anchor="w", justify="left", wraplength=760)
        self._etw_events.pack(fill="x", pady=(8, 0))

    def _apply_etw(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self._etw_tag.configure(text="不可用", fg=T.TEXT_MUTED)
            self._etw_hint.configure(
                text="native_guard.dll 不可用或接口异常，ETW 未运行。")
            return
        d = res.data
        running = bool(d.get("running"))
        self._etw_tag.configure(text="运行中" if running else "未运行",
                                fg=T.SUCCESS if running else T.TEXT_MUTED)
        if d.get("error"):
            self._etw_hint.configure(text=f"后端报告：{d.get('error')}")
            return
        providers = d.get("providers") or d.get("provider_count")
        bits = []
        if providers:
            bits.append(f"Provider {providers}")
        for key in ("events_total", "dropped", "session", "poll_fallback"):
            if d.get(key) not in (None, ""):
                bits.append(f"{key}={d[key]}")
        self._etw_hint.configure(text=" · ".join(bits) if bits else "")

    def _etw_do_start(self):
        def done(res):
            data = res.data if isinstance(res.data, dict) else {}
            if res.ok and data.get("success", True):
                self.ctx.say("ETW 事中检测已启动", "ok")
            else:
                self.ctx.say(f"ETW 启动失败：{data.get('error') or res.error}",
                             "error")
            self._load_etw_status()

        run_async(self, self.client.etw_start, done)

    def _etw_do_stop(self):
        def done(res):
            data = res.data if isinstance(res.data, dict) else {}
            if res.ok and data.get("success", True):
                self.ctx.say("ETW 已停止", "warn")
            else:
                self.ctx.say(f"ETW 停止失败：{data.get('error') or res.error}",
                             "error")
            self._load_etw_status()

        run_async(self, self.client.etw_stop, done)

    def _etw_fetch_events(self):
        """取一次事件。

        ⚠ 是**消费式**接口：后端返回后即清空队列，所以这里不自动轮询，
           只在用户主动点击时取一次，避免抢走其他消费者的数据。
        """

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self._etw_events.configure(text=f"取事件失败：{res.error}",
                                           fg=T.DANGER)
                return
            events = res.data.get("events") or []
            total = res.data.get("total", len(events))
            if not events:
                self._etw_events.configure(text="当前无待取事件（队列为空）",
                                           fg=T.TEXT_MUTED)
                return
            lines = [f"取出 {fmt_int(total)} 条事件（队列已被清空）："]
            for ev in events[:5]:
                if isinstance(ev, dict):
                    lines.append(
                        f"· event={ev.get('event_id')} "
                        f"{ev.get('source_pid')} → {ev.get('target_pid')} "
                        f"{ev.get('detail') or ev.get('path') or ''}".rstrip())
                else:
                    lines.append(f"· {ev}")
            self._etw_events.configure(text="\n".join(lines), fg=T.TEXT_PRIMARY)
            self.ctx.say(f"取出 {len(events)} 条 ETW 事件", "warn")

        run_async(self, self.client.etw_events, done)

    def _load_etw_status(self):
        run_async(self, self.client.etw_status, self._apply_etw)

    # ── AMSI ──

    def _build_amsi(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "AMSI Provider", T.BG_CARD).pack(side="left")
        self._amsi_tag = tk.Label(head, text="未知", bg=T.BG_CARD,
                                  fg=T.TEXT_MUTED, font=T.font(10, "bold"))
        self._amsi_tag.pack(side="left", padx=(10, 0))

        W.muted_label(
            card.inner,
            "⚠ 注册有系统性风险：AMSI Provider 走 COM，必须同时写 "
            "CLSID\\{GUID}\\InprocServer32 与 Providers 两处。只写 Providers 会让"
            "全系统 AMSI 失效（AmsiInitialize 返回 0x80070002），比未注册更糟；"
            "注销时若删掉 Providers 父键还会连带清掉其他厂商的注册。"
            "注册/注销前请确认你在做这件事。",
            T.BG_CARD, size=9, fg=T.WARNING).pack(fill="x", pady=(6, 0))

        self.kv_amsi_reg = W.KeyValueRow(card.inner, "注册状态")
        self.kv_amsi_clsid = W.KeyValueRow(card.inner, "CLSID")
        self.kv_amsi_dll = W.KeyValueRow(card.inner, "Provider DLL")
        self.kv_amsi_health = W.KeyValueRow(card.inner, "AMSI 健康")
        for row in (self.kv_amsi_reg, self.kv_amsi_clsid, self.kv_amsi_dll,
                    self.kv_amsi_health):
            row.pack(fill="x", pady=3)

        btns = tk.Frame(card.inner, bg=T.BG_CARD)
        btns.pack(fill="x", pady=(10, 0))
        W.button(btns, "注册 Provider", self._amsi_register, "danger").pack(
            side="left")
        W.button(btns, "注销 Provider", self._amsi_unregister, "ghost").pack(
            side="left", padx=(8, 0))
        W.button(btns, "刷新", self._load_amsi, "ghost").pack(side="left",
                                                             padx=(8, 0))

        self._amsi_issues = tk.Label(card.inner, text="", bg=T.BG_CARD,
                                     fg=T.WARNING, font=T.font(9), anchor="w",
                                     justify="left", wraplength=760)
        self._amsi_issues.pack(fill="x", pady=(8, 0))

    def _apply_amsi(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self._amsi_tag.configure(text="不可用", fg=T.TEXT_MUTED)
            return
        d = res.data
        registered = bool(d.get("registered"))
        self._amsi_tag.configure(text="已注册" if registered else "未注册",
                                 fg=T.SUCCESS if registered else T.TEXT_MUTED)
        self.kv_amsi_reg.set_value("是" if registered else "否")
        self.kv_amsi_clsid.set_value(str(d.get("clsid") or "--"), T.TEXT_SECONDARY)
        self.kv_amsi_dll.set_value(str(d.get("dll") or d.get("path") or "--"),
                                   T.TEXT_SECONDARY)

        health = d.get("health")
        if isinstance(health, dict):
            ok = health.get("ok")
            self.kv_amsi_health.set_value(
                "正常" if ok else str(health.get("hint") or health.get("hr") or "异常"),
                T.SUCCESS if ok else T.WARNING)
        else:
            self.kv_amsi_health.set_value("--")

        issues = d.get("issues") or []
        self._amsi_issues.configure(
            text="；".join(str(x) for x in issues[:4]) if issues else "")
        if d.get("error"):
            self._amsi_issues.configure(text=f"后端报告：{d.get('error')}")

    def _load_amsi(self):
        run_async(self, self.client.amsi_status, self._apply_amsi)

    def _amsi_register(self):
        if not messagebox.askyesno(
                "确认注册 AMSI Provider",
                "注册会把本产品注入到所有 AMSI 消费者（PowerShell / Office / VBS）。\n\n"
                "如果 DLL 不是合法的 COM 进程内服务器，或注册项写不全，"
                "会导致全系统 AMSI 失效。\n\n确定继续？",
                parent=self.winfo_toplevel()):
            return

        def done(res):
            data = res.data if isinstance(res.data, dict) else {}
            if res.ok and data.get("success", True):
                self.ctx.say("AMSI Provider 已注册", "ok")
            else:
                self.ctx.say(f"注册失败：{data.get('error') or res.error}", "error")
            self._load_amsi()

        run_async(self, self.client.amsi_register, done)

    def _amsi_unregister(self):
        if not messagebox.askyesno(
                "确认注销 AMSI Provider",
                "注销会移除本产品的 AMSI 注册项。\n\n"
                "正确实现只删自己的 GUID，不会影响其他厂商；"
                "但若后端实现有误，可能影响全系统 AMSI。\n\n确定继续？",
                parent=self.winfo_toplevel()):
            return

        def done(res):
            data = res.data if isinstance(res.data, dict) else {}
            if res.ok and data.get("success", True):
                self.ctx.say("AMSI Provider 已注销", "warn")
            else:
                self.ctx.say(f"注销失败：{data.get('error') or res.error}", "error")
            self._load_amsi()

        run_async(self, self.client.amsi_unregister, done)

    # ── 辅助功能 ──

    def _build_features(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 8))
        W.section_title(card.inner, "辅助功能", T.BG_CARD).pack(anchor="w")
        W.muted_label(card.inner,
                      "只读展示。这些开关的写入口在设置页/主程序，"
                      "本页仅反映后端当前状态。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))
        self._feature_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._feature_host.pack(fill="x")

    def _apply_features(self, res):
        for child in self._feature_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._feature_host, "无法读取功能状态", T.BG_CARD,
                          size=9, fg=T.DANGER).pack(anchor="w")
            return
        d = res.data
        for key, label in FEATURE_LABELS:
            info = d.get(key) if isinstance(d.get(key), dict) else {}
            enabled = info.get("enabled")
            extra = ""
            if key == "game_mode" and info.get("in_game") is not None:
                extra = "（游戏中）" if info.get("in_game") else "（未检测到游戏）"
            self._feature_line(label, enabled, extra)
        # ETW / AMSI 单独两行（它们的状态字段结构不同）
        etw = d.get("etw_guard") if isinstance(d.get("etw_guard"), dict) else {}
        self._feature_line("ETW 事中检测", etw.get("running"))
        amsi = d.get("amsi_provider") if isinstance(d.get("amsi_provider"), dict) else {}
        self._feature_line("AMSI Provider", amsi.get("registered"))

    def _feature_line(self, label: str, value, extra: str = ""):
        row = tk.Frame(self._feature_host, bg=T.BG_CARD)
        row.pack(fill="x", pady=1)
        if value is None:
            text, color = "未知", T.TEXT_MUTED
        elif value:
            text, color = "开启", T.SUCCESS
        else:
            text, color = "关闭", T.TEXT_MUTED
        tk.Label(row, text=label, bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                 font=T.font(9), width=18, anchor="w").pack(side="left")
        tk.Label(row, text=text, bg=T.BG_CARD, fg=color,
                 font=T.font(9, "bold"), anchor="w").pack(side="left")
        if extra:
            tk.Label(row, text=extra, bg=T.BG_CARD, fg=T.TEXT_MUTED,
                     font=T.font(9), anchor="w").pack(side="left", padx=(6, 0))

    # ── 加载 ──

    def on_show(self):
        self.refresh()
        self.every(REFRESH_MS, self._refresh_live)

    def on_hide(self):
        self.cancel_timers()

    def refresh(self):
        """全量刷新（含只读信息）。"""
        self._refresh_live()
        run_async(self, self.client.version, self._apply_version)
        run_async(self, self.client.scan_perf_stats, self._apply_perf)
        run_async(self, self.client.cloud_engines, self._apply_cloud)
        run_async(self, self.client.deep_engines, self._apply_deep)
        run_async(self, self.client.amsi_status, self._apply_amsi)

    def _refresh_live(self):
        """高频刷新：只刷会变的状态，不重复拉只读的引擎清单。"""
        run_async(self, self.client.protection_status, self._apply_protection)
        self._load_etw_status()
        run_async(self, self.client.features_status, self._apply_features)

    def _apply_protection(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        modules = res.data.get("modules") or {}
        for key, sw in self._switches.items():
            if key in modules:
                sw.set(bool(modules[key]), notify=False)

    def _apply_version(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self._engine_tag.configure(text="引擎不可用", fg=T.DANGER)
            return
        d = res.data
        engine = d.get("engine") if isinstance(d.get("engine"), dict) else {}
        self._engine_tag.configure(text=str(d.get("version") or ""), fg=T.ACCENT)
        self.kv_version.set_value(str(d.get("version") or "--"))
        self.kv_name.set_value(str(d.get("name") or "--"))
        self.kv_scans.set_value(fmt_int(engine.get("total_scans")))
        rate = engine.get("cache_hit_rate")
        self.kv_cache.set_value(f"{rate}%" if rate is not None else "--")
        avg = engine.get("avg_scan_time_ms")
        self.kv_avg.set_value(f"{avg} ms" if avg is not None else "--")

    def _apply_perf(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        d = res.data
        yara = d.get("yara") if isinstance(d.get("yara"), dict) else {}
        if yara:
            self.kv_yara.set_value(
                f"{fmt_int(yara.get('total_rules'))} 条"
                f"（PE {fmt_int(yara.get('pe_rules'))}"
                f" / 通用 {fmt_int(yara.get('generic_rules'))}）")
        queue = d.get("realtime_queue") if isinstance(d.get("realtime_queue"), dict) else {}
        if queue:
            self.kv_queue.set_value(
                f"深度 {fmt_int(queue.get('queue_depth'))}"
                f"/{fmt_int(queue.get('queue_max'))}"
                f" · 丢弃 {fmt_int(queue.get('dropped_events'))}")
        elif d.get("cpu_percent") is not None:
            self.kv_queue.set_value(f"CPU {d.get('cpu_percent')}%")
