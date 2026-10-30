"""扫描页：快速 / 全盘 / 自定义扫描 + 实时进度 + 结果列表。

进度用 Canvas 自绘而不是 ``ttk.Progressbar``：后者在 Windows 上永远是系统
主题样式（浅色），塞进暗色界面里非常突兀。
"""
from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog

from .. import theme as T
from .. import widgets as W
from ..api import fmt_int, run_async, short_hash
from ..app import Page

POLL_MS = 900
BAR_H = 8


class ProgressBar(tk.Canvas):
    """自绘进度条：底槽 + 填充，宽度随百分比变化。"""

    def __init__(self, parent, bg: str = T.BG_CARD, height: int = BAR_H):
        super().__init__(parent, height=height, bg=bg, highlightthickness=0, bd=0)
        self._bg = bg
        self._value = 0.0
        self._track = self.create_rectangle(0, 0, 0, height, fill=T.BORDER, outline="")
        self._fill = self.create_rectangle(0, 0, 0, height, fill=T.ACCENT, outline="")
        self.bind("<Configure>", lambda _e: self._redraw())

    def set(self, percent: float):
        try:
            self._value = max(0.0, min(100.0, float(percent)))
        except (TypeError, ValueError):
            self._value = 0.0
        self._redraw()

    def set_color(self, color: str):
        try:
            self.itemconfigure(self._fill, fill=color)
        except tk.TclError:
            pass

    def _redraw(self):
        try:
            width = max(1, self.winfo_width())
            height = max(1, self.winfo_height())
            self.coords(self._track, 0, 0, width, height)
            self.coords(self._fill, 0, 0, int(width * self._value / 100.0), height)
        except tk.TclError:
            pass


class ScanPage(Page):
    key = "scan"
    title = "病毒扫描"
    glyph = "⌕"

    def build(self):
        self._task_id: str | None = None
        self._running = False

        wrap = tk.Frame(self, bg=T.BG_APP)
        wrap.pack(fill="both", expand=True, padx=22, pady=18)

        self._build_actions(wrap)
        self._build_progress(wrap)
        self._build_results(wrap)

    # ── 操作区 ──

    def _build_actions(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        W.section_title(card.inner, "选择扫描方式", T.BG_CARD).pack(anchor="w",
                                                              pady=(0, 12))

        row = tk.Frame(card.inner, bg=T.BG_CARD)
        row.pack(fill="x")
        self._btn_quick = W.button(row, "快速扫描", lambda: self._start("quick"))
        self._btn_quick.pack(side="left")
        self._btn_full = W.button(row, "全盘扫描", lambda: self._start("full"), "ghost")
        self._btn_full.pack(side="left", padx=(10, 0))
        self._btn_custom = W.button(row, "自定义目录…", self._start_custom, "ghost")
        self._btn_custom.pack(side="left", padx=(10, 0))

        self._btn_cancel = W.button(row, "取消任务", self._cancel, "danger")
        self._btn_cancel.pack(side="right")
        self._btn_cancel.configure(state="disabled", bg=T.BORDER,
                                   fg=T.TEXT_MUTED, cursor="")

        # 记住常态底色：禁用时要压暗，恢复时要还原（否则会停在灰底）
        self._scan_buttons = [
            (self._btn_quick, T.ACCENT),
            (self._btn_full, T.BG_HOVER),
            (self._btn_custom, T.BG_HOVER),
        ]

        tk.Label(card.inner,
                 text="取消是正常路径：已扫到的结果会保留，进行中的读取会尽快中断。",
                 bg=T.BG_CARD, fg=T.TEXT_MUTED, font=T.font(9),
                 anchor="w").pack(fill="x", pady=(10, 0))

    # ── 进度区 ──

    def _build_progress(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "任务进度", T.BG_CARD).pack(side="left")
        self._status_tag = tk.Label(head, text="空闲", bg=T.BG_CARD, fg=T.TEXT_MUTED,
                                    font=T.font(10, "bold"))
        self._status_tag.pack(side="left", padx=(10, 0))
        self._pct = tk.Label(head, text="0%", bg=T.BG_CARD, fg=T.ACCENT,
                             font=T.font(12, "bold"))
        self._pct.pack(side="right")

        self._bar = ProgressBar(card.inner)
        self._bar.pack(fill="x", pady=(10, 10))

        self._current = W.muted_label(card.inner, "尚未开始", T.BG_CARD, size=9,
                                     mono=True)
        self._current.pack(fill="x")
        self._task_line = W.muted_label(card.inner, "", T.BG_CARD, size=9)
        self._task_line.pack(fill="x", pady=(4, 0))

    # ── 结果区 ──

    def _build_results(self, parent):
        card = W.Card(parent)
        card.pack(fill="both", expand=True)
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "扫描结果", T.BG_CARD).pack(side="left")
        self._result_summary = tk.Label(head, text="", bg=T.BG_CARD,
                                        fg=T.TEXT_SECONDARY, font=T.font(10))
        self._result_summary.pack(side="left", padx=(10, 0))

        self._result_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._result_host.pack(fill="both", expand=True, pady=(10, 0))
        self._render_empty("尚无扫描结果", "选择上方任一方式开始扫描")

    def _render_empty(self, title: str, hint: str = ""):
        for child in self._result_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        W.EmptyHint(self._result_host, title, hint, T.BG_CARD, "🛡").pack(fill="both",
                                                                       expand=True)

    # ── 生命周期 ──

    def on_show(self):
        if self._running and self._task_id:
            self._poll()

    def on_hide(self):
        self.cancel_timers()

    # ── 动作 ──

    def _start(self, scan_type: str, paths=None):
        if self._running:
            self.ctx.say("已有扫描任务在进行中", "warn")
            return

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self.ctx.say(f"启动失败: {res.error}", "error")
                return
            self._task_id = res.data.get("task_id")
            self._running = True
            self._set_busy(True)
            self._status_tag.configure(text="运行中", fg=T.ACCENT)
            self._result_summary.configure(text="")
            self._render_empty("扫描进行中…", "结果将在任务完成后显示")
            self.ctx.say(f"扫描已启动（{scan_type}）", "ok")
            self._poll()

        run_async(self, lambda: self.client.scan_start(scan_type, paths), done)

    def _start_custom(self):
        try:
            directory = filedialog.askdirectory(title="选择要扫描的目录")
        except Exception as exc:
            self.ctx.say(f"打开目录选择器失败: {exc}", "error")
            return
        if not directory:
            return
        directory = os.path.abspath(directory)
        self._start("custom", [directory])

    def _cancel(self):
        if not self._task_id or not self._running:
            return

        def done(res):
            if res.ok:
                self.ctx.say("已请求取消任务", "warn")
            else:
                self.ctx.say(f"取消失败: {res.error}", "error")

        run_async(self, lambda: self.client.scan_cancel(self._task_id), done)

    def _set_busy(self, busy: bool):
        for btn, base_bg in self._scan_buttons:
            try:
                if busy:
                    # 压成边框色 + 弱化文字，避免"亮着的按钮其实点不动"
                    btn.configure(state="disabled", bg=T.BORDER, fg=T.TEXT_MUTED)
                else:
                    fg = T.TEXT_ON_ACCENT if base_bg == T.ACCENT else T.TEXT_PRIMARY
                    btn.configure(state="normal", bg=base_bg, fg=fg)
            except tk.TclError:
                pass
        try:
            if busy:
                self._btn_cancel.configure(state="normal", bg=T.DANGER,
                                           fg="#ffffff", cursor="hand2")
            else:
                self._btn_cancel.configure(state="disabled", bg=T.BORDER,
                                           fg=T.TEXT_MUTED, cursor="")
        except tk.TclError:
            pass

    # ── 轮询 ──

    def _poll(self):
        if not self._task_id:
            return
        run_async(self, lambda: self.client.scan_status(self._task_id),
                  self._apply_status)
        self.every(POLL_MS, self._poll)

    def _apply_status(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self._bar.set_color(T.DANGER)
            self._status_tag.configure(text="查询失败", fg=T.DANGER)
            self._current.configure(text=str(res.error or ""))
            return

        d = res.data
        status = (d.get("status") or "").lower()
        try:
            progress = float(d.get("progress") or 0)
        except (TypeError, ValueError):
            progress = 0.0

        self._bar.set(progress)
        self._pct.configure(text=f"{progress:.0f}%")

        label, color = {
            "queued": ("排队中", T.TEXT_SECONDARY),
            "running": ("运行中", T.ACCENT),
            "completed": ("已完成", T.SUCCESS),
            "cancelled": ("已取消", T.WARNING),
            "failed": ("失败", T.DANGER),
        }.get(status, (status or "未知", T.TEXT_SECONDARY))
        self._status_tag.configure(text=label, fg=color)

        current = d.get("current_file") or ""
        if len(current) > 110:
            current = "…" + current[-109:]
        self._current.configure(text=current or "—")

        task_id = d.get("task_id") or ""
        self._task_line.configure(
            text=f"任务 {short_hash(task_id, 8)} · 类型 {d.get('scan_type') or '-'}"
                 f" · 创建 {d.get('created_at') or '-'}")

        if status in ("completed", "cancelled", "failed"):
            self._running = False
            self._set_busy(False)
            self.cancel_timers()
            self._apply_result(d)

    def _apply_result(self, d: dict):
        status = (d.get("status") or "").lower()
        if status == "failed":
            self._bar.set_color(T.DANGER)
            self._render_empty("扫描失败", str(d.get("error") or "未知错误"))
            self.ctx.say(f"扫描失败: {d.get('error')}", "error")
            return

        if status == "cancelled":
            self._bar.set_color(T.WARNING)

        result = d.get("result")
        if not isinstance(result, dict):
            self._render_empty("无结果数据",
                               "任务已结束，但服务端未返回 result 字段")
            return

        threats = result.get("threats") or []
        scanned = result.get("files_scanned", result.get("total_scanned", 0))
        found = result.get("threats_found", len(threats))
        quarantined = result.get("quarantined", 0)
        cloud_hits = result.get("cloud_hits", 0)
        # 失败/跳过的如实展示：扫描失败绝不能显示成"未发现威胁"
        scan_errors = int(result.get("scan_errors") or 0)
        skipped = int(result.get("skipped") or 0)

        summary = (f"扫描 {fmt_int(scanned)} · 检出 {fmt_int(found)} · "
                   f"已隔离 {fmt_int(quarantined)} · 云命中 {fmt_int(cloud_hits)}")
        if scan_errors:
            summary += f" · 失败 {fmt_int(scan_errors)}"
        if skipped:
            summary += f" · 跳过 {fmt_int(skipped)}"
        self._result_summary.configure(text=summary)

        if not threats:
            if scan_errors:
                # 有文件扫不了 —— 结论只能是"部分未扫描"，不能报"安全"
                self._render_empty(
                    "部分未扫描（不能判定为安全）",
                    f"{fmt_int(scan_errors)} 个文件扫描失败，"
                    f"另有 {fmt_int(skipped)} 个按规则跳过；"
                    "建议对这些路径单独排查或查看日志")
                self.ctx.say(
                    f"扫描结束：{fmt_int(scan_errors)} 个文件未能扫描，结论不完整",
                    "danger")
                return
            self._render_empty("未发现威胁", "本次扫描未检出可疑文件")
            self.ctx.say("扫描完成，未发现威胁", "ok")
            return

        self._render_threats(threats)
        if scan_errors:
            self.ctx.say(
                f"扫描完成，检出 {len(threats)} 项威胁；"
                f"另有 {fmt_int(scan_errors)} 个文件未能扫描", "error")
        else:
            self.ctx.say(f"扫描完成，检出 {len(threats)} 项威胁", "error")

    def _render_threats(self, threats: list):
        for child in self._result_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass

        for item in threats[:200]:
            if not isinstance(item, dict):
                continue
            level = str(item.get("threat_level") or "medium").lower()
            color = T.DANGER if level in ("high", "critical") else T.WARNING

            row = tk.Frame(self._result_host, bg=T.BG_HOVER)
            row.pack(fill="x", pady=2)
            pad = tk.Frame(row, bg=T.BG_HOVER)
            pad.pack(fill="x", padx=10, pady=7)

            top = tk.Frame(pad, bg=T.BG_HOVER)
            top.pack(fill="x")
            tk.Label(top, text="●", bg=T.BG_HOVER, fg=color,
                     font=T.font(10)).pack(side="left")
            tk.Label(top, text=str(item.get("signature") or "未知"),
                     bg=T.BG_HOVER, fg=T.TEXT_PRIMARY,
                     font=T.font(10, "bold")).pack(side="left", padx=(6, 0))
            tk.Label(top, text=f"[{level}] {item.get('engine') or ''}",
                     bg=T.BG_HOVER, fg=T.TEXT_MUTED,
                     font=T.font(9)).pack(side="left", padx=(8, 0))
            if item.get("quarantined"):
                tk.Label(top, text="已隔离", bg=T.BG_HOVER, fg=T.SUCCESS,
                         font=T.font(9, "bold")).pack(side="right")

            path = str(item.get("path") or "")
            if len(path) > 118:
                path = "…" + path[-117:]
            W.muted_label(pad, path, T.BG_HOVER, size=9, mono=True).pack(fill="x",
                                                                       pady=(4, 0))
            sha = item.get("sha256") or item.get("md5") or ""
            if sha:
                W.muted_label(pad, f"SHA256 {short_hash(sha, 32)}", T.BG_HOVER,
                              size=8, mono=True, fg=T.TEXT_MUTED).pack(fill="x")
