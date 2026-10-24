"""设置页：后端连接、引擎/特征库信息、系统健康、关于。

这里刻意没有"启动/停止后端"这类按钮——按约定本 UI **不接入**主程序，
不负责后端生命周期，只做一个独立的查询客户端（改地址除外）。
"""
from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox

from .. import theme as T
from .. import widgets as W
from ..api import fmt_int, run_async
from ..app import Page
from ..backend import save_prefs

REFRESH_MS = 8000
# 节流的实际占用变化较快（一次扫描来去就跳），单独用更短的周期
RTG_REFRESH_MS = 3000


class SettingsPage(Page):
    key = "settings"
    title = "设置"
    glyph = "⚙"

    def build(self):
        root = W.ScrollableFrame(self, bg=T.BG_APP)
        root.pack(fill="both", expand=True)
        pad = tk.Frame(root.content, bg=T.BG_APP)
        pad.pack(fill="both", expand=True, padx=22, pady=18)
        self._scroll = root

        self._build_backend_control(pad)
        self._build_rtguard(pad)
        self._build_connection(pad)
        self._build_engine(pad)
        self._build_signatures(pad)
        self._build_health(pad)
        self._build_exit(pad)

    # ── 实时防护 · CPU 节流 ──
    #
    # 这段能力原先只存在于 HTML 版的 frontend/guard.html。主程序界面换成 Tkinter
    # 之后那页在程序里看不到了，节流按钮就跟着没了入口（三个接口 /api/v1/rtguard/*
    # 变成只被 HTML 版调用）。这里把它接回来。
    #
    # 主程序与 rtguard 是**两个进程**：后端做 HTTP 转发。rtguard 没在跑时后端返回
    # available=False 且 **HTTP 200**（不报错），所以这里要能显示"未运行"并给启动入口。

    def _build_rtguard(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "实时防护 · CPU 节流", T.BG_CARD).pack(side="left")
        self._rtg_tag = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                                 font=T.font(10, "bold"))
        self._rtg_tag.pack(side="left", padx=(10, 0))

        lv = tk.Frame(card.inner, bg=T.BG_CARD)
        lv.pack(fill="x", pady=(10, 0))
        self._rtg_btns = {}
        for key, label in (("low", "低 5%"), ("medium", "中 10%"), ("high", "高 15%")):
            b = W.button(lv, label, lambda k=key: self._rtg_set_level(k), "ghost")
            b.pack(side="left", padx=(0, 8))
            self._rtg_btns[key] = b
        self._rtg_start_btn = W.button(lv, "启动实时防护", self._rtg_start, "accent")
        self._rtg_start_btn.pack(side="left", padx=(8, 0))

        self.kv_rtg_level = W.KeyValueRow(card.inner, "当前档位")
        self.kv_rtg_load = W.KeyValueRow(card.inner, "CPU 占用")
        self.kv_rtg_stats = W.KeyValueRow(card.inner, "防护统计")
        for row in (self.kv_rtg_level, self.kv_rtg_load, self.kv_rtg_stats):
            row.pack(fill="x", pady=3)

        W.muted_label(
            card.inner,
            "档位 = 允许扫描占用的 CPU 上限（按整机核数换算）。"
            "实际低于目标不代表没在跑，只是没活干。",
            T.BG_CARD, size=9).pack(fill="x", pady=(8, 0))
        self._rtg_apply(None)

    def _rtg_tick(self):
        run_async(self, self.client.rtguard_status, self._rtg_apply)

    def _rtg_apply(self, res):
        d = res.data if (res is not None and res.ok and isinstance(res.data, dict)) else None
        if not (d and d.get("available")):
            self._rtg_tag.configure(
                text=(d or {}).get("error") or "实时防护未运行", fg=T.WARNING)
            self.kv_rtg_level.set_value("--", T.TEXT_MUTED)
            self.kv_rtg_load.set_value("--", T.TEXT_MUTED)
            self.kv_rtg_stats.set_value("--", T.TEXT_MUTED)
            for b in self._rtg_btns.values():
                b.configure(state="disabled")
            self._rtg_start_btn.configure(state="normal", text="启动实时防护")
            return

        self._rtg_tag.configure(text="运行中", fg=T.SUCCESS)
        self._rtg_start_btn.configure(state="disabled", text="启动实时防护")

        levels = d.get("levels") if isinstance(d.get("levels"), dict) else {}
        cur = str(d.get("level") or "")
        for k, b in self._rtg_btns.items():
            info = levels.get(k) if isinstance(levels.get(k), dict) else {}
            b.configure(text=str(info.get("label") or b.cget("text")), state="normal",
                        bg=(T.ACCENT if k == cur else T.BG_HOVER),
                        fg=(T.TEXT_ON_ACCENT if k == cur else T.TEXT_PRIMARY),
                        activebackground=(T.ACCENT_DIM if k == cur else T.BORDER_LIGHT))

        tgt, act = d.get("target_pct"), d.get("actual_pct")
        self.kv_rtg_level.set_value(str(d.get("label") or cur or "--"))
        try:
            over = float(act) > float(tgt) * 1.5
        except (TypeError, ValueError):
            over = False
        self.kv_rtg_load.set_value(
            f"实际 {act}% / 目标 {tgt}%　允许 {d.get('budget_cores')} 核"
            f"（共 {d.get('cores')} 核）",
            T.DANGER if over else T.TEXT_SECONDARY)

        s = d.get("stats") if isinstance(d.get("stats"), dict) else {}
        bits = [f"{lab} {fmt_int(s.get(key))}"
                for lab, key in (("规则", "rules"), ("已扫描", "scanned"),
                                 ("可疑", "suspicious"), ("恶意", "malicious"),
                                 ("隔离", "quarantine"), ("缓存命中", "cache_hits"))
                if key in s]
        self.kv_rtg_stats.set_value("　".join(bits) or "--", T.TEXT_SECONDARY)

    def _rtg_set_level(self, level: str):
        def done(res):
            if res is None or not res.ok:
                messagebox.showwarning("切换失败",
                                       (res.error if res else "无响应") or "无响应",
                                       parent=self)
            self._rtg_tick()
        run_async(self, lambda: self.client.rtguard_throttle(level), done)

    def _rtg_start(self):
        def done(res):
            if res is None or not res.ok:
                messagebox.showwarning("启动失败",
                                       (res.error if res else "无响应") or "无响应",
                                       parent=self)
            self._rtg_tick()
        self._rtg_start_btn.configure(state="disabled", text="正在启动…")
        run_async(self, self.client.rtguard_start, done)

    # ── 退出程序 ──
    # 走 POST /api/v1/shutdown：保存状态 → 释放引擎资源 → os._exit(0)。
    # **不可逆**（进程没了，界面也连不上后端了），所以必须二次确认。

    def _build_exit(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "退出程序", T.BG_CARD).pack(anchor="w",
                                                            pady=(0, 10))
        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x")
        W.button(row, "立即退出御天", self._exit_now, "danger").pack(side="left")
        tk.Label(row, text="会一并停止实时防护与后台监控",
                 bg=T.BG_CARD, fg=T.TEXT_MUTED,
                 font=T.font(9)).pack(side="left", padx=(10, 0))

    def _exit_now(self):
        if not messagebox.askyesno(
                "确认退出",
                "退出后实时防护与后台监控都会停止，"
                "要重新启动程序才能恢复。\n\n确定退出吗？",
                parent=self):
            return

        def done(res):
            if res is None or not res.ok:
                messagebox.showwarning("退出失败",
                                       (res.error if res else "无响应") or "无响应",
                                       parent=self)
        run_async(self, self.client.shutdown, done)

    # ── 后端连接 ──

    def _build_connection(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "后端连接", T.BG_CARD).pack(anchor="w",
                                                            pady=(0, 10))

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x")
        self._url_var = tk.StringVar(value=self.client.base)
        entry = tk.Entry(row, textvariable=self._url_var, bg=T.BG_INPUT,
                         fg=T.TEXT_PRIMARY, insertbackground=T.ACCENT,
                         relief="flat", bd=0, highlightthickness=1,
                         highlightbackground=T.BORDER, highlightcolor=T.ACCENT,
                         font=T.mono(10))
        entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 10))
        W.button(row, "保存并测试", self._save_base).pack(side="left")

        self._conn_state = W.muted_label(card.inner, "未测试", T.BG_CARD, size=9)
        self._conn_state.pack(fill="x", pady=(8, 0))

        W.muted_label(card.inner,
                      "默认 127.0.0.1:8899（backend/app.py 里 uvicorn 的监听端口）。"
                      "改地址只影响本 UI 的请求目标，不会改动后端配置。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(6, 0))

    def _save_base(self):
        raw = (self._url_var.get() or "").strip()
        if not raw:
            self._conn_state.configure(text="地址不能为空", fg=T.DANGER)
            return
        if not raw.startswith(("http://", "https://")):
            raw = "http://" + raw
        self.client.base = raw.rstrip("/")
        self._url_var.set(self.client.base)
        self._conn_state.configure(text=f"已切换到 {self.client.base}，正在测试…",
                                   fg=T.TEXT_SECONDARY)
        self.ctx.say(f"后端地址已切换为 {self.client.base}", "info")

        def done(res):
            if res.ok:
                self._conn_state.configure(text="连接正常", fg=T.SUCCESS)
                self.ctx.say("后端连接正常", "ok")
            else:
                self._conn_state.configure(text=f"连接失败：{res.error}", fg=T.DANGER)
                self.ctx.say(f"后端连接失败: {res.error}", "error")

        run_async(self, self.client.health, done)

    # ── 引擎信息 ──

    def _build_engine(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "引擎信息", T.BG_CARD).pack(anchor="w",
                                                            pady=(0, 10))
        self.kv_engine_version = W.KeyValueRow(card.inner, "软件版本")
        self.kv_engine_name = W.KeyValueRow(card.inner, "版本名称")
        self.kv_api = W.KeyValueRow(card.inner, "API 版本")
        self.kv_scans = W.KeyValueRow(card.inner, "累计扫描次数")
        self.kv_cache = W.KeyValueRow(card.inner, "缓存命中率")
        self.kv_yara = W.KeyValueRow(card.inner, "YARA 规则")
        self.kv_perf = W.KeyValueRow(card.inner, "平均扫描耗时")
        for row in (self.kv_engine_version, self.kv_engine_name, self.kv_api,
                    self.kv_scans, self.kv_cache, self.kv_yara, self.kv_perf):
            row.pack(fill="x", pady=3)

    # ── 特征库 ──

    def _build_signatures(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "特征库", T.BG_CARD).pack(anchor="w",
                                                          pady=(0, 10))
        self.kv_sig_total = W.KeyValueRow(card.inner, "特征条目")
        self.kv_sig_version = W.KeyValueRow(card.inner, "病毒库版本")
        self.kv_sig_levels = W.KeyValueRow(card.inner, "按等级分布")
        for row in (self.kv_sig_total, self.kv_sig_version, self.kv_sig_levels):
            row.pack(fill="x", pady=3)

    # ── 系统健康 ──

    def _build_health(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "系统健康", T.BG_CARD).pack(anchor="w",
                                                            pady=(0, 10))
        self.kv_uptime = W.KeyValueRow(card.inner, "后端运行时长")
        self.kv_python = W.KeyValueRow(card.inner, "Python")
        self.kv_platform = W.KeyValueRow(card.inner, "平台")
        self.kv_memory = W.KeyValueRow(card.inner, "内存占用")
        self.kv_disk = W.KeyValueRow(card.inner, "磁盘")
        self.kv_guard_days = W.KeyValueRow(card.inner, "累计守护")
        for row in (self.kv_uptime, self.kv_python, self.kv_platform,
                    self.kv_memory, self.kv_disk, self.kv_guard_days):
            row.pack(fill="x", pady=3)

    # ── 后端控制 ──

    def _build_backend_control(self, parent):
        """后端生命周期控制。

        本界面会代管后端：自动拉起、可手动停止，但**只停自己启动的**。
        若后端是用户自己或主程序起的，这里只显示、不接管。
        """
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "后端服务", T.BG_CARD).pack(side="left")
        self._svc_tag = tk.Label(head, text="", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                                 font=T.font(10, "bold"))
        self._svc_tag.pack(side="left", padx=(10, 0))

        backend = self.ctx.backend
        self.kv_svc_dir = W.KeyValueRow(card.inner, "后端目录")
        self.kv_svc_py = W.KeyValueRow(card.inner, "Python")
        self.kv_svc_log = W.KeyValueRow(card.inner, "日志")
        for row in (self.kv_svc_dir, self.kv_svc_py, self.kv_svc_log):
            row.pack(fill="x", pady=3)

        if backend is not None:
            self.kv_svc_dir.set_value(backend.detect_backend_dir() or "未找到（需含 app.py）",
                                      T.TEXT_SECONDARY)
            self.kv_svc_py.set_value(backend.python_exe(), T.TEXT_SECONDARY)
            self.kv_svc_log.set_value(backend.log_path, T.TEXT_SECONDARY)

        btns = tk.Frame(card.inner, bg=T.BG_CARD)
        btns.pack(fill="x", pady=(10, 0))
        W.button(btns, "启动后端", self._svc_start).pack(side="left")
        W.button(btns, "停止后端", self._svc_stop, "danger").pack(side="left",
                                                                padx=(8, 0))
        W.button(btns, "指定后端目录…", self._svc_pick_dir, "ghost").pack(
            side="left", padx=(8, 0))

        # 偏好开关
        prefs = backend.prefs if backend is not None else {}
        self._auto_var = tk.BooleanVar(value=bool(prefs.get("auto_start_backend", True)))
        self._exit_var = tk.BooleanVar(value=bool(prefs.get("stop_on_exit", False)))
        opts = tk.Frame(card.inner, bg=T.BG_CARD)
        opts.pack(fill="x", pady=(10, 0))
        for text, var, hint in (
            ("启动界面时自动拉起后端", self._auto_var, ""),
            ("退出界面时停止我启动的后端", self._exit_var,
             "（默认不关：关掉后端等于停止防护）"),
        ):
            row = tk.Frame(opts, bg=T.BG_CARD)
            row.pack(fill="x", pady=2)
            tk.Checkbutton(row, text=text, variable=var, command=self._svc_save_prefs,
                           bg=T.BG_CARD, fg=T.TEXT_PRIMARY,
                           activebackground=T.BG_CARD,
                           activeforeground=T.TEXT_PRIMARY,
                           selectcolor=T.BG_INPUT, highlightthickness=0, bd=0,
                           font=T.font(10), anchor="w").pack(side="left")
            if hint:
                tk.Label(row, text=hint, bg=T.BG_CARD, fg=T.TEXT_MUTED,
                         font=T.font(9)).pack(side="left", padx=(6, 0))

        self._svc_state = W.muted_label(
            card.inner,
            "启动命令：python -m uvicorn app:app --host 127.0.0.1 --port 8899"
            "（只起 API 服务，不会弹出 WebView2 窗口或托盘）",
            T.BG_CARD, size=9)
        self._svc_state.pack(fill="x", pady=(8, 0))

    def _svc_start(self):
        backend = self.ctx.backend
        if backend is None:
            return
        self._svc_tag.configure(text="启动中…", fg=T.TEXT_SECONDARY)
        self.ctx.app.start_backend()

    def _svc_stop(self):
        backend = self.ctx.backend
        if backend is None:
            return
        if not backend.started_by_us:
            self._svc_tag.configure(text="外部后端", fg=T.TEXT_MUTED)
            self.ctx.say("后端不是本界面启动的，不予停止", "warn")
            return
        self.ctx.app.stop_backend()

    def _svc_pick_dir(self):
        backend = self.ctx.backend
        if backend is None:
            return
        try:
            path = filedialog.askdirectory(title="选择包含 app.py 的 backend 目录")
        except Exception as exc:
            self.ctx.say(f"打开目录选择器失败：{exc}", "error")
            return
        if not path:
            return
        if not os.path.isfile(os.path.join(path, "app.py")):
            if not messagebox.askyesno(
                    "该目录没有 app.py",
                    f"{path}\n\n里面没有找到 app.py，确定仍要使用它作为后端目录？",
                    parent=self.winfo_toplevel()):
                return
        backend.backend_dir = os.path.normpath(path)
        backend.prefs["backend_dir"] = backend.backend_dir
        save_prefs(backend.prefs)
        self.kv_svc_dir.set_value(backend.backend_dir, T.SUCCESS)
        self.ctx.say(f"后端目录已设为：{backend.backend_dir}", "ok")

    def _svc_save_prefs(self):
        backend = self.ctx.backend
        if backend is None:
            return
        backend.prefs["auto_start_backend"] = bool(self._auto_var.get())
        backend.prefs["stop_on_exit"] = bool(self._exit_var.get())
        if save_prefs(backend.prefs):
            self.ctx.say("后端偏好已保存", "ok")
        else:
            self.ctx.say("偏好保存失败（检查 %LOCALAPPDATA% 写权限）", "error")

    # ── 加载 ──

    def _apply_svc_state(self, res):
        """用 /api/health 的结果刷新后端状态标签。

        区分"本界面启动的"与"外部的"—— 因为这决定了「停止后端」是否可用。
        """
        backend = self.ctx.backend
        alive = bool(getattr(res, "ok", False))
        if not alive:
            self._svc_tag.configure(text="未运行", fg=T.TEXT_MUTED)
        elif backend is not None and backend.started_by_us:
            self._svc_tag.configure(text="运行中（本界面启动）", fg=T.SUCCESS)
        else:
            self._svc_tag.configure(text="运行中（外部启动）", fg=T.SUCCESS)

    def on_show(self):
        self.refresh()
        self.every(REFRESH_MS, self.refresh)
        self._rtg_tick()
        self.every(RTG_REFRESH_MS, self._rtg_tick)

    def on_hide(self):
        self.cancel_timers()

    def refresh(self):
        run_async(self, self.client.version, self._apply_version)
        run_async(self, self.client.signatures_info, self._apply_signatures)
        run_async(self, self.client.health, self._apply_health)
        run_async(self, self.client.guard_days, self._apply_guard)

    def _apply_version(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self.kv_engine_version.set_value(res.error or "不可用", T.DANGER)
            return
        d = res.data
        engine = d.get("engine") if isinstance(d.get("engine"), dict) else {}
        yara = d.get("yara") if isinstance(d.get("yara"), dict) else {}

        self.kv_engine_version.set_value(str(d.get("version") or "--"))
        self.kv_engine_name.set_value(str(d.get("name") or "--"))
        self.kv_api.set_value(str(d.get("api") or "--"))
        self.kv_scans.set_value(fmt_int(engine.get("total_scans")))
        rate = engine.get("cache_hit_rate")
        self.kv_cache.set_value(f"{rate}%" if rate is not None else "--")
        self.kv_yara.set_value(
            f"{fmt_int(yara.get('total_rules'))} 条 "
            f"(PE {fmt_int(yara.get('pe_rules'))} / "
            f"通用 {fmt_int(yara.get('generic_rules'))})")
        avg = engine.get("avg_scan_time_ms")
        self.kv_perf.set_value(f"{avg} ms" if avg is not None else "--")

    def _apply_signatures(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self.kv_sig_total.set_value(res.error or "不可用", T.DANGER)
            return
        d = res.data
        self.kv_sig_total.set_value(fmt_int(d.get("total_signatures")))
        self.kv_sig_version.set_value(str(d.get("version") or "--"))
        by_level = d.get("by_level")
        if isinstance(by_level, dict) and by_level:
            text = " · ".join(f"{k} {fmt_int(v)}" for k, v in by_level.items())
        else:
            text = "--"
        self.kv_sig_levels.set_value(text)

    def _apply_health(self, res):
        # 复用同一次 /api/health 的结果刷新后端状态标签，不重复发请求
        self._apply_svc_state(res)
        if not res.ok or not isinstance(res.data, dict):
            self.kv_uptime.set_value(res.error or "不可用", T.DANGER)
            return
        d = res.data
        uptime = d.get("uptime_seconds")
        if isinstance(uptime, (int, float)):
            hours, rem = divmod(int(uptime), 3600)
            minutes = rem // 60
            self.kv_uptime.set_value(f"{hours} 小时 {minutes} 分")
        else:
            self.kv_uptime.set_value("--")

        self.kv_python.set_value(str(d.get("python") or "--"))
        platform_text = str(d.get("platform") or "--")
        if len(platform_text) > 70:
            platform_text = platform_text[:67] + "…"
        self.kv_platform.set_value(platform_text)

        memory = d.get("memory") if isinstance(d.get("memory"), dict) else {}
        rss = memory.get("rss_mb")
        self.kv_memory.set_value(f"{rss} MB" if rss is not None else "--")

        disk = d.get("disk") if isinstance(d.get("disk"), dict) else {}
        if disk:
            self.kv_disk.set_value(
                f"{disk.get('percent', '--')}% 已用 · "
                f"{disk.get('free_gb', '--')} GB 可用",
                T.WARNING if d.get("disk_status") == "warning" else None)
        else:
            self.kv_disk.set_value("--")

        sig = d.get("signatures") if isinstance(d.get("signatures"), dict) else {}
        self._conn_state.configure(
            text=f"连接正常 · 特征库 {fmt_int(sig.get('total'))} 条", fg=T.SUCCESS)

    def _apply_guard(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        d = res.data
        days = d.get("accumulated_days", 0)
        first = d.get("first_start_date") or "--"
        self.kv_guard_days.set_value(f"{fmt_int(days)} 天（首次 {first}）")
