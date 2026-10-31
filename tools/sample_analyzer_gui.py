#!/usr/bin/env python3
"""样本安全分析工具 —— Tkinter 图形界面（非 HTML / 非 WebView）

分析内核直接复用同目录的 ``sample_analyzer.py``（已实测：notepad 出报告、
XXH64 过官方测试向量、6 个 System32 文件无误报）。这个文件只做界面。

界面结构
--------
    工具条：添加文件 / 添加文件夹 / 开始分析 / 导出报告 / 清空
    进度条
    表格（Treeview）：文件 / 类型 / 大小 / SHA256(前16) / 评分 / 判定
    状态栏：统计
双击一行看完整指纹与命中规则。

为什么用 Tkinter
----------------
产品主界面（ui_tk/）本来就是 Tkinter，不引第三方 UI 库、不嵌浏览器。
分析在后台线程跑，主线程只刷界面 —— 不会卡。

用法
----
    python sample_analyzer_gui.py
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# ── 复用 CLI 版的分析内核 ──
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sample_analyzer import (  # noqa: E402
    Engines, Fingerprint, attribute, escape_ioc, iter_samples,
    render_md, sniff,
)

APP_TITLE = "御天 · 样本安全分析工具"
ROW_TAGS = {
    "malicious": ("#ffd7dc", "#7a1220"),
    "suspicious": ("#fff3c4", "#6b4a00"),
    "low": ("#eef0f4", "#333a45"),
    "clean": ("#ddf3e4", "#0f4d28"),
}


def verdict_tag(verdict: str) -> str:
    if verdict.startswith("恶意"):
        return "malicious"
    if verdict.startswith("可疑"):
        return "suspicious"
    if verdict.startswith("低风险"):
        return "low"
    return "clean"


def fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.0f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    return f"{n / 1024 / 1024 / 1024:.2f} GB"


class AnalyzerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1000x620")
        self.root.minsize(820, 480)

        self.inputs: list[str] = []
        self.records: list[dict] = []
        self.iocs = {"url": set(), "domain": set(), "ip": set()}
        self.engines = Engines(True, True, True)
        self.queue: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.busy = False
        self.elapsed = 0.0

        self._build()
        self.root.after(100, self._drain)
        self._set_status("就绪 ｜ " + " ｜ ".join(self.engines.notes))

    # ── 界面 ──
    def _build(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=22)
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"))

        bar = ttk.Frame(self.root, padding=(8, 8, 8, 4))
        bar.pack(fill="x")
        ttk.Button(bar, text="添加文件…", command=self.add_files,
                   width=12).pack(side="left")
        ttk.Button(bar, text="添加文件夹…", command=self.add_dir,
                   width=12).pack(side="left", padx=(6, 0))
        self.btn_start = ttk.Button(bar, text="开始分析", command=self.start,
                                    width=12)
        self.btn_start.pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="导出报告…", command=self.export,
                   width=12).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="清空", command=self.clear,
                   width=8).pack(side="left", padx=(6, 0))

        self.prog = ttk.Progressbar(self.root, mode="determinate", maximum=100)
        self.prog.pack(fill="x", padx=8, pady=(0, 4))

        wrap = ttk.Frame(self.root, padding=(8, 0, 8, 0))
        wrap.pack(fill="both", expand=True)
        cols = ("file", "kind", "size", "sha256", "score", "verdict")
        heads = ("文件", "类型", "大小", "SHA256(前16)", "评分", "判定")
        widths = (300, 90, 90, 170, 60, 130)
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings",
                                 selectmode="browse")
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="w" if c in ("file", "sha256")
                             else "center", stretch=(c == "file"))
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        for tag, (bg, fg) in ROW_TAGS.items():
            self.tree.tag_configure(tag, background=bg, foreground=fg)
        self.tree.bind("<Double-1>", self._on_double)

        self.status = ttk.Label(self.root, anchor="w", padding=(10, 4),
                                relief="sunken")
        self.status.pack(fill="x", side="bottom")

    def _set_status(self, text: str) -> None:
        self.status.configure(text=text)

    # ── 输入 ──
    def add_files(self) -> None:
        paths = filedialog.askopenfilenames(title="选择要分析的文件")
        if not paths:
            return
        self.inputs.extend(paths)
        self._set_status(f"已加入 {len(self.inputs)} 个输入")

    def add_dir(self) -> None:
        d = filedialog.askdirectory(title="选择要分析的文件夹")
        if not d:
            return
        self.inputs.append(d)
        n = sum(len(fs) for _, _, fs in os.walk(d))
        self._set_status(f"已加入文件夹（约 {n} 个文件）")

    def clear(self) -> None:
        if self.busy:
            return
        self.inputs.clear()
        self.records.clear()
        for k in self.iocs:
            self.iocs[k].clear()
        self.tree.delete(*self.tree.get_children())
        self.prog["value"] = 0
        self.elapsed = 0.0
        self._set_status("已清空")

    # ── 分析 ──
    def start(self) -> None:
        if self.busy:
            messagebox.showinfo("提示", "正在分析中")
            return
        if not self.inputs:
            messagebox.showinfo("提示", "请先添加文件或文件夹")
            return
        self.records.clear()
        for k in self.iocs:
            self.iocs[k].clear()
        self.tree.delete(*self.tree.get_children())
        self.prog["value"] = 0
        self.busy = True
        self.btn_start.configure(state="disabled")
        self.worker = threading.Thread(target=self._run, daemon=True)
        self.worker.start()

    def _run(self) -> None:
        from collections import Counter
        stats: Counter = Counter()
        t0 = time.perf_counter()
        total = 0
        try:
            for display, spool, _ in iter_samples(self.inputs, None, 3, stats):
                total += 1
                if spool is None:
                    self.queue.put(("row", {"name": display, "error": True}))
                    continue
                try:
                    fpr = Fingerprint()
                    spool.seek(0)
                    while True:
                        c = spool.read(1 << 20)
                        if not c:
                            break
                        fpr.update(c)
                    fp = fpr.finish()
                    spool.seek(0)
                    head4m = spool.read(4 << 20)
                    fp["_data"] = head4m
                    fp["kind"] = sniff(fp["head"], display)
                    eng = self.engines.run(display, fp)
                    verdict, basis = attribute(eng)
                    rec = {
                        "name": display, "kind": fp["kind"], "size": fp["size"],
                        "crc32": fp["crc32"], "xxh64": fp["xxh64"],
                        "md5": fp["md5"], "sha1": fp["sha1"],
                        "sha256": fp["sha256"], "sha3_256": fp["sha3_256"],
                        "verdict": verdict, "basis": basis,
                        "yara": [h["rule"] for h in (eng.get("yara") or [])],
                    }
                    # IOC
                    for m in __import__("sample_analyzer").IOC_URL.finditer(head4m):
                        self.iocs["url"].add(escape_ioc(m.group(0).decode("latin1", "ignore")))
                    for m in __import__("sample_analyzer").IOC_DOM.finditer(head4m):
                        self.iocs["domain"].add(escape_ioc(m.group(0).decode("latin1", "ignore")))
                    for m in __import__("sample_analyzer").IOC_IP.finditer(head4m):
                        ip = m.group(0).decode("latin1")
                        if not ip.startswith(("0.", "127.", "255.")):
                            self.iocs["ip"].add(escape_ioc(ip))
                    self.queue.put(("row", rec))
                except Exception as exc:
                    self.queue.put(("row", {"name": display, "error": True,
                                            "err": str(exc)}))
                finally:
                    spool.close()
        finally:
            self.elapsed = time.perf_counter() - t0
            self.queue.put(("done", total))

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "row":
                    self._add_row(payload)
                elif kind == "done":
                    self._finish(payload)
        except queue.Empty:
            pass
        self.root.after(80, self._drain)

    def _add_row(self, rec: dict) -> None:
        if self.busy:
            # 粗略进度：已知输入总数时更准，这里用已处理数滚动
            self.prog["value"] = min(99, self.prog["value"] + 1)
        if rec.get("error"):
            self.tree.insert("", "end", values=(rec["name"], "-", "-", "-", "-",
                                                "读取失败"), tags=("low",))
            return
        self.records.append(rec)
        tag = verdict_tag(rec["verdict"])
        self.tree.insert("", "end", tags=(tag,), values=(
            rec["name"], rec["kind"], fmt_size(rec["size"]),
            rec["sha256"][:16], "-", rec["verdict"]))
        self.tree.see(self.tree.get_children()[-1])

    def _finish(self, total: int) -> None:
        self.busy = False
        self.btn_start.configure(state="normal")
        self.prog["value"] = 100
        mal = sum(1 for r in self.records if r["verdict"].startswith("恶意"))
        susp = sum(1 for r in self.records if r["verdict"].startswith("可疑"))
        self._set_status(
            f"{len(self.records)} 个样本 ｜ 恶意 {mal} ｜ 可疑 {susp} ｜ "
            f"用时 {self.elapsed:.1f}s ｜ " + " ｜ ".join(self.engines.notes))

    # ── 详情 ──
    def _on_double(self, _evt) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx < 0 or idx >= len(self.records):
            return
        r = self.records[idx]
        lines = [
            f"文件: {r['name']}",
            "",
            f"类型: {r['kind']}    大小: {r['size']} 字节",
            "",
            f"判定: {r['verdict']}",
        ]
        if r.get("basis"):
            lines.append(f"依据: {r['basis']}")
        lines += [
            "",
            f"MD5:      {r['md5']}",
            f"SHA1:     {r['sha1']}",
            f"SHA256:   {r['sha256']}",
            f"SHA3-256: {r['sha3_256']}",
            f"CRC32:    {r['crc32']}",
            f"XXH64:    {r['xxh64']}",
        ]
        if r.get("yara"):
            lines += ["", "YARA: " + ", ".join(r["yara"][:8])]
        messagebox.showinfo("样本详情", "\n".join(lines))

    # ── 导出 ──
    def export(self) -> None:
        if not self.records:
            messagebox.showinfo("提示", "还没有分析结果")
            return
        path = filedialog.asksaveasfilename(
            title="导出报告", defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("JSON", "*.json")])
        if not path:
            return
        result = {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_s": round(self.elapsed, 1),
            "engines": self.engines.notes,
            "samples": self.records,
            "iocs": {k: sorted(v)[:40] for k, v in self.iocs.items()},
        }
        text = (json.dumps(result, ensure_ascii=False, indent=2)
                if path.lower().endswith(".json") else render_md(result))
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))
            return
        messagebox.showinfo("导出", f"已写入\n{path}")


def main() -> int:
    root = tk.Tk()
    AnalyzerApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
