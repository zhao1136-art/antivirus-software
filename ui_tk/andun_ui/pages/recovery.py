"""数据恢复页：版本快照监控 + 文件/版本浏览 + 还原 + 设置。

后端契约（app.py / data_recovery.py）：
* ``GET  /api/v1/recovery/stats``  → ``{watched_directories, watch_dirs[],
  files_tracked, total_versions, total_storage_bytes, total_storage_mb, running}``
* ``GET  /api/v1/recovery/status`` → ``{running, watch_dirs[], files_tracked,
  total_versions, stats{}}``
* ``GET  /api/v1/recovery/files``  → ``{files: [{name, path}]}``
* ``GET  /api/v1/recovery/versions?file_path=`` → ``{versions: [{version_id,
  timestamp, hash, size}]}``（按时间升序）
* ``POST /api/v1/recovery/restore`` body ``{file_path, version_id}`` → ``{ok}``
* ``POST /api/v1/recovery/delete-version`` body ``{file_path, version_id}`` → ``{ok}``
* ``POST /api/v1/recovery/start`` body ``{directories: []}`` → ``{ok}``
* ``POST /api/v1/recovery/stop`` → ``{ok}``
* ``GET  /api/v1/recovery/settings`` / ``POST`` body ``{retain_days, storage_limit}``
* ``POST /api/v1/recovery/watch-dirs`` body ``{dir}``
* ``POST /api/v1/recovery/watch-dirs/delete`` body ``{dir}`` 或 ``{index}``
"""
from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox

from .. import theme as T
from .. import widgets as W
from ..api import fmt_int, fmt_size, fmt_time, run_async, short_hash
from ..app import Page

FILE_PAGE = 60


class RecoveryPage(Page):
    key = "recovery"
    title = "数据恢复"
    glyph = "↺"

    def build(self):
        self._files: list[dict] = []
        self._current_file = ""
        self._restore_job: str | None = None
        self._restoring = False

        root = W.ScrollableFrame(self, bg=T.BG_APP)
        root.pack(fill="both", expand=True)
        pad = tk.Frame(root.content, bg=T.BG_APP)
        pad.pack(fill="both", expand=True, padx=22, pady=18)

        self._build_status(pad)
        self._build_watch_dirs(pad)
        self._build_files(pad)
        self._build_versions(pad)
        self._build_settings(pad)

    # ── 状态 ──

    def _build_status(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "快照监控", T.BG_CARD).pack(side="left")
        self._run_tag = tk.Label(head, text="未知", bg=T.BG_CARD,
                                 fg=T.TEXT_MUTED, font=T.font(10, "bold"))
        self._run_tag.pack(side="left", padx=(10, 0))
        W.button(head, "刷新", self.refresh, "ghost").pack(side="right")

        self.kv_dirs = W.KeyValueRow(card.inner, "监控目录数")
        self.kv_files = W.KeyValueRow(card.inner, "跟踪文件")
        self.kv_versions = W.KeyValueRow(card.inner, "快照版本数")
        self.kv_storage = W.KeyValueRow(card.inner, "占用空间")
        for row in (self.kv_dirs, self.kv_files, self.kv_versions, self.kv_storage):
            row.pack(fill="x", pady=3)

        btns = tk.Frame(card.inner, bg=T.BG_CARD)
        btns.pack(fill="x", pady=(10, 0))
        W.button(btns, "启动监控", self._start, "accent").pack(side="left")
        W.button(btns, "停止监控", self._stop, "ghost").pack(side="left",
                                                            padx=(8, 0))
        self._restore_tag = tk.Label(card.inner, text="", bg=T.BG_CARD,
                                     fg=T.TEXT_SECONDARY, font=T.font(9),
                                     anchor="w")
        self._restore_tag.pack(fill="x", pady=(8, 0))

    def _apply_status(self, res):
        if not res.ok or not isinstance(res.data, dict):
            self._run_tag.configure(text="不可用", fg=T.TEXT_MUTED)
            return
        d = res.data
        running = bool(d.get("running"))
        self._run_tag.configure(text="运行中" if running else "已停止",
                                fg=T.SUCCESS if running else T.TEXT_MUTED)
        dirs = d.get("watch_dirs") or []
        self.kv_dirs.set_value(f"{fmt_int(len(dirs))}")
        self.kv_files.set_value(fmt_int(d.get("files_tracked")))
        self.kv_versions.set_value(fmt_int(d.get("total_versions")))

    def _apply_stats(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        d = res.data
        running = d.get("running")
        if running is not None:
            self._run_tag.configure(text="运行中" if running else "已停止",
                                    fg=T.SUCCESS if running else T.TEXT_MUTED)
        dirs = d.get("watch_dirs") or []
        self.kv_dirs.set_value(fmt_int(d.get("watched_directories", len(dirs))))
        self.kv_files.set_value(fmt_int(d.get("files_tracked")))
        self.kv_versions.set_value(fmt_int(d.get("total_versions")))
        if d.get("total_storage_bytes") is not None:
            self.kv_storage.set_value(
                f"{fmt_size(d.get('total_storage_bytes'))}"
                f"（{d.get('total_storage_mb', '--')} MB）")

    def _start(self):
        def done(res):
            if res.ok:
                self.ctx.say("快照监控已启动", "ok")
            else:
                self.ctx.say(f"启动失败：{res.error}", "error")
            self.refresh()

        run_async(self, lambda: self.client.recovery_start(), done)

    def _stop(self):
        def done(res):
            if res.ok:
                self.ctx.say("快照监控已停止", "warn")
            else:
                self.ctx.say(f"停止失败：{res.error}", "error")
            self.refresh()

        run_async(self, self.client.recovery_stop, done)

    # ── 监控目录 ──

    def _build_watch_dirs(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "监控目录", T.BG_CARD).pack(side="left")
        W.button(head, "添加目录…", self._add_dir, "ghost").pack(side="right")
        self._dirs_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._dirs_host.pack(fill="x", pady=(10, 0))

    def _apply_dirs(self, res):
        for child in self._dirs_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._dirs_host, "无法读取设置", T.BG_CARD,
                          size=9, fg=T.DANGER).pack(anchor="w")
            return
        dirs = res.data.get("watch_dirs") or []
        if not dirs:
            W.muted_label(self._dirs_host, "未配置监控目录", T.BG_CARD,
                          size=9).pack(anchor="w")
            return
        for idx, item in enumerate(dirs):
            row = tk.Frame(self._dirs_host, bg=T.BG_HOVER)
            row.pack(fill="x", pady=1)
            text = str(item)
            shown = text if len(text) <= 70 else "…" + text[-69:]
            tk.Label(row, text=shown, bg=T.BG_HOVER, fg=T.TEXT_PRIMARY,
                     font=T.mono(9), anchor="w").pack(side="left", fill="x",
                                                      expand=True, padx=(8, 4),
                                                      pady=4)
            tk.Button(row, text="×", command=lambda d=text: self._remove_dir(d),
                      bg=T.BG_HOVER, fg=T.DANGER, activebackground=T.BORDER_LIGHT,
                      activeforeground=T.DANGER, relief="flat", bd=0,
                      highlightthickness=0, font=T.font(10, "bold"),
                      cursor="hand2", padx=8).pack(side="right")

    def _add_dir(self):
        try:
            path = filedialog.askdirectory(title="选择要纳入快照监控的目录")
        except Exception as exc:
            self.ctx.say(f"打开目录选择器失败：{exc}", "error")
            return
        if not path:
            return

        def done(res):
            if res.ok and isinstance(res.data, dict) and res.data.get("ok", True):
                self.ctx.say(f"已添加监控目录：{path}", "ok")
            else:
                self.ctx.say("添加失败", "error")
            self.refresh()

        run_async(self, lambda: self.client.recovery_watch_dir_add(path), done)

    def _remove_dir(self, directory: str):
        if not messagebox.askyesno(
                "确认移除",
                f"不再监控该目录：\n{directory}\n\n"
                "已生成的快照不会被删除，仍可还原。继续？",
                parent=self.winfo_toplevel()):
            return

        def done(res):
            if res.ok and isinstance(res.data, dict) and res.data.get("ok", True):
                self.ctx.say("已移除监控目录", "ok")
            else:
                self.ctx.say("移除失败", "error")
            self.refresh()

        run_async(self, lambda: self.client.recovery_watch_dir_remove(directory),
                  done)

    # ── 文件列表 ──

    def _build_files(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "受监控文件", T.BG_CARD).pack(side="left")
        self._file_count = tk.Label(head, text="", bg=T.BG_CARD,
                                    fg=T.TEXT_SECONDARY, font=T.font(9))
        self._file_count.pack(side="left", padx=(10, 0))
        W.button(head, "刷新", self._load_files, "ghost").pack(side="right")
        W.muted_label(card.inner, "点一行查看它的历史版本。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 8))
        self._files_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._files_host.pack(fill="x")

    def _load_files(self):
        run_async(self, self.client.recovery_files, self._apply_files)

    def _apply_files(self, res):
        for child in self._files_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._files_host, "无法读取文件列表", T.BG_CARD,
                          size=9, fg=T.DANGER).pack(anchor="w")
            return
        self._files = [f for f in (res.data.get("files") or [])
                       if isinstance(f, dict)]
        self._file_count.configure(text=f"{fmt_int(len(self._files))} 个")
        if not self._files:
            W.muted_label(self._files_host, "还没有被跟踪的文件",
                          T.BG_CARD, size=9).pack(anchor="w")
            return
        for item in self._files[:FILE_PAGE]:
            self._file_row(item)
        if len(self._files) > FILE_PAGE:
            W.muted_label(self._files_host,
                          f"仅显示前 {FILE_PAGE} 个，请用更精确的监控目录缩小范围",
                          T.BG_CARD, size=9).pack(anchor="w", pady=(6, 0))

    def _file_row(self, item: dict):
        path = str(item.get("path") or "")
        name = str(item.get("name") or path)

        row = tk.Frame(self._files_host, bg=T.BG_CARD)
        row.pack(fill="x", pady=1)
        btn = tk.Button(row, text=name if len(name) <= 62 else name[:61] + "…",
                        command=lambda p=path, n=name: self._select_file(p, n),
                        bg=T.BG_CARD, fg=T.TEXT_PRIMARY,
                        activebackground=T.BG_HOVER,
                        activeforeground=T.ACCENT, relief="flat", bd=0,
                        highlightthickness=0, font=T.font(10), anchor="w",
                        cursor="hand2", padx=8, pady=4)
        btn.pack(fill="x")
        if path and path != name:
            shown = path if len(path) <= 100 else "…" + path[-99:]
            W.muted_label(row, shown, T.BG_CARD, size=8, mono=True,
                          fg=T.TEXT_MUTED).pack(fill="x", padx=8)

    def _select_file(self, path: str, name: str):
        self._current_file = path
        self._current_label.configure(text=name)
        self._load_versions()

    # ── 版本列表 ──

    def _build_versions(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 14))
        head = tk.Frame(card.inner, bg=T.BG_CARD)
        head.pack(fill="x")
        W.section_title(head, "历史版本", T.BG_CARD).pack(side="left")
        self._current_label = tk.Label(head, text="未选择文件", bg=T.BG_CARD,
                                       fg=T.TEXT_MUTED, font=T.font(9))
        self._current_label.pack(side="left", padx=(10, 0))
        W.button(head, "刷新", self._load_versions, "ghost").pack(side="right")
        self._versions_host = tk.Frame(card.inner, bg=T.BG_CARD)
        self._versions_host.pack(fill="x", pady=(10, 0))
        W.muted_label(self._versions_host, "先在上方选择一个文件",
                      T.BG_CARD, size=9).pack(anchor="w")

    def _load_versions(self):
        if not self._current_file:
            return
        run_async(self, lambda: self.client.recovery_versions(self._current_file),
                  self._apply_versions)

    def _apply_versions(self, res):
        for child in self._versions_host.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        if not res.ok or not isinstance(res.data, dict):
            W.muted_label(self._versions_host, "无法读取版本列表", T.BG_CARD,
                          size=9, fg=T.DANGER).pack(anchor="w")
            return
        versions = [v for v in (res.data.get("versions") or [])
                    if isinstance(v, dict)]
        if not versions:
            W.muted_label(self._versions_host,
                          "该文件还没有历史版本（改动后才会生成快照）",
                          T.BG_CARD, size=9).pack(anchor="w")
            return
        # 后端按时间升序返回，这里倒序展示（最新在上）
        for ver in reversed(versions):
            self._version_row(ver)

    def _version_row(self, ver: dict):
        vid = str(ver.get("version_id") or "")
        row = tk.Frame(self._versions_host, bg=T.BG_HOVER)
        row.pack(fill="x", pady=2)
        pad = tk.Frame(row, bg=T.BG_HOVER)
        pad.pack(fill="x", padx=10, pady=6)

        top = tk.Frame(pad, bg=T.BG_HOVER)
        top.pack(fill="x")
        tk.Label(top, text=vid, bg=T.BG_HOVER, fg=T.TEXT_PRIMARY,
                 font=T.mono(9)).pack(side="left")
        when = ver.get("timestamp")
        if isinstance(when, (int, float)):
            try:
                from datetime import datetime
                when_text = datetime.fromtimestamp(when).strftime("%m-%d %H:%M")
            except Exception:
                when_text = str(when)
        else:
            when_text = fmt_time(str(when)) if when else "--"
        tk.Label(top, text=when_text, bg=T.BG_HOVER, fg=T.TEXT_SECONDARY,
                 font=T.font(9)).pack(side="left", padx=(10, 0))
        size = ver.get("size")
        if size is not None:
            tk.Label(top, text=fmt_size(size), bg=T.BG_HOVER, fg=T.TEXT_SECONDARY,
                     font=T.font(9)).pack(side="left", padx=(10, 0))

        actions = tk.Frame(top, bg=T.BG_HOVER)
        actions.pack(side="right")
        W.button(actions, "还原此版本",
                 lambda v=vid: self._restore(v), "accent").pack(side="left")
        W.button(actions, "删除",
                 lambda v=vid: self._delete_version(v), "danger").pack(
            side="left", padx=(6, 0))

        digest = ver.get("hash")
        if digest:
            W.muted_label(pad, f"哈希 {short_hash(str(digest), 40)}", T.BG_HOVER,
                          size=8, mono=True, fg=T.TEXT_MUTED).pack(fill="x")

    def _restore(self, version_id: str):
        if not self._current_file or not version_id or self._restoring:
            return
        if not messagebox.askyesno(
                "确认还原",
                f"把文件还原到版本 {version_id}？\n\n"
                "当前内容会被该版本覆盖。继续？",
                parent=self.winfo_toplevel()):
            return

        self._restore_tag.configure(text="正在提交还原任务…", fg=T.TEXT_SECONDARY)

        def done(res):
            if not res.ok or not isinstance(res.data, dict):
                self._restore_tag.configure(text=f"提交失败：{res.error}",
                                            fg=T.DANGER)
                return
            self._restore_job = res.data.get("task_id")
            self._restoring = True
            self.ctx.say("还原任务已提交", "info")
            self._poll_restore()

        run_async(self,
                  lambda: self.client.recovery_restore_job(self._current_file,
                                                           version_id),
                  done)

    def _poll_restore(self):
        if not self._restore_job or not self._restoring:
            return
        run_async(self, lambda: self.client.job_status(self._restore_job),
                  self._apply_restore)
        self.every(1000, self._poll_restore)

    def _apply_restore(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        d = res.data
        status = str(d.get("status") or "").lower()
        progress = d.get("progress")
        current = str(d.get("current") or "")
        label = {"queued": "排队中", "running": "还原中", "completed": "已完成",
                 "cancelled": "已取消", "failed": "失败"}.get(status, status)
        if isinstance(progress, (int, float)) and status == "running":
            label = f"{label} {progress:.0f}%"
        if current:
            label += f" · {current[:60]}"
        color = {"completed": T.SUCCESS, "failed": T.DANGER,
                 "cancelled": T.WARNING}.get(status, T.ACCENT)
        self._restore_tag.configure(text=label, fg=color)

        if status in ("completed", "cancelled", "failed"):
            self._restoring = False
            result = d.get("result") if isinstance(d.get("result"), dict) else {}
            if status == "completed" and result.get("ok"):
                self.ctx.say("文件已还原到所选版本", "ok")
            elif status == "cancelled":
                self.ctx.say("还原已取消", "warn")
            else:
                self.ctx.say(f"还原失败：{d.get('error') or result.get('error') or '未知原因'}",
                             "error")
            self.refresh()
            self._load_versions()

    def _delete_version(self, version_id: str):
        if not self._current_file or not version_id:
            return
        if not messagebox.askyesno(
                "确认删除版本",
                f"删除版本 {version_id}？此操作不可撤销。",
                parent=self.winfo_toplevel()):
            return

        def done(res):
            if res.ok and isinstance(res.data, dict) and res.data.get("ok", True):
                self.ctx.say(f"已删除版本 {version_id}", "ok")
            else:
                self.ctx.say("删除失败", "error")
            self._load_versions()

        run_async(self,
                  lambda: self.client.recovery_delete_version(self._current_file,
                                                               version_id),
                  done)

    # ── 设置 ──

    def _build_settings(self, parent):
        card = W.Card(parent)
        card.pack(fill="x", pady=(0, 8))
        W.section_title(card.inner, "快照设置", T.BG_CARD).pack(anchor="w")
        W.muted_label(card.inner,
                      "保留天数与存储上限用于自动清理旧快照。填 0 表示不限制。",
                      T.BG_CARD, size=9).pack(fill="x", pady=(4, 10))

        form = tk.Frame(card.inner, bg=T.BG_CARD)
        form.pack(fill="x")
        self._retain_var = tk.StringVar(value="")
        self._limit_var = tk.StringVar(value="")
        for label, var, hint in (("保留天数", self._retain_var, "天"),
                                 ("存储上限", self._limit_var, "MB")):
            row = tk.Frame(form, bg=T.BG_CARD)
            row.pack(fill="x", pady=4)
            tk.Label(row, text=label, bg=T.BG_CARD, fg=T.TEXT_SECONDARY,
                     font=T.font(9), width=8, anchor="w").pack(side="left")
            tk.Entry(row, textvariable=var, bg=T.BG_INPUT, fg=T.TEXT_PRIMARY,
                     insertbackground=T.ACCENT, relief="flat", bd=0,
                     highlightthickness=1, highlightbackground=T.BORDER,
                     highlightcolor=T.ACCENT, font=T.mono(10), width=12).pack(
                side="left", ipady=4)
            tk.Label(row, text=hint, bg=T.BG_CARD, fg=T.TEXT_MUTED,
                     font=T.font(9)).pack(side="left", padx=(6, 0))

        W.button(card.inner, "保存设置", self._save_settings).pack(anchor="w",
                                                                 pady=(10, 0))

    def _apply_settings(self, res):
        if not res.ok or not isinstance(res.data, dict):
            return
        d = res.data
        if d.get("retain_days") is not None:
            self._retain_var.set(str(d.get("retain_days")))
        if d.get("storage_limit") is not None:
            self._limit_var.set(str(d.get("storage_limit")))
        self._apply_dirs(res)

    def _save_settings(self):
        def as_int(value: str) -> int:
            try:
                return int(str(value).strip() or 0)
            except (TypeError, ValueError):
                return 0

        retain = as_int(self._retain_var.get())
        limit = as_int(self._limit_var.get())

        def done(res):
            if res.ok and isinstance(res.data, dict) and res.data.get("ok", True):
                self.ctx.say(f"设置已保存（保留 {retain} 天 / 上限 {limit} MB）", "ok")
            else:
                self.ctx.say("保存失败", "error")
            self.refresh()

        run_async(self, lambda: self.client.recovery_save_settings(retain, limit),
                  done)

    # ── 生命周期 ──

    def on_show(self):
        self.refresh()

    def on_hide(self):
        self.cancel_timers()

    def refresh(self):
        run_async(self, self.client.recovery_stats, self._apply_stats)
        run_async(self, self.client.recovery_status, self._apply_status)
        run_async(self, self.client.recovery_settings, self._apply_settings)
        self._load_files()
