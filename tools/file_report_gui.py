#!/usr/bin/env python3
"""文件取证上报工具 —— 用户用它分析可疑文件，把报告发给分析人员。

设计原则
--------
1. **不做病毒判定**。工具只输出可复核的事实（哈希、PE 结构、区段熵、导入表、
   PDB 路径、字符串取证……）。判定由接收报告的人做。
2. **分析要详细**。一个样本的完整报告 ≈ 250 行 Markdown，包含证据所需的全部原始数据。
3. **一键导出**。用户点「导出报告」，得到一份可直接发的 Markdown/JSON。

界面
----
    工具条：添加文件 / 添加文件夹 / 分析 / 导出报告 / 清空
    表格  ：文件 / 类型 / 大小 / SHA256(前16) / 区段 / 导入 / 字符串类别
    双击一行 → 完整取证详情
"""
from __future__ import annotations

import json
import os
import queue
import socket
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from file_report import Analysis, header_markdown  # noqa: E402

APP_TITLE = "御天 · 文件取证上报工具"

# ── 记住上次导出目录（写到用户配置目录，不在 exe 旁边写，避免无权限）──
_CONFIG_DIR = os.path.join(os.environ.get("LOCALAPPDATA") or
                           os.path.expanduser("~"), "YutianSampleAnalyzer")
_CONFIG_FILE = os.path.join(_CONFIG_DIR, "config.json")


def _load_last_dir() -> str:
    try:
        with open(_CONFIG_FILE, encoding="utf-8") as fh:
            d = json.load(fh).get("last_dir", "")
            if d and os.path.isdir(d):
                return d
    except Exception:
        pass
    # 默认落到「文档\YutianReports」。不能默认到驱动器根目录（C:\ / H:\）——
    # 根目录需要提权，非提升进程写不进去，Windows 另存为对话框会一直弹
    # "你没有权限在此位置保存文件"，换位置也没用。
    docs = os.path.join(os.path.expanduser("~"), "Documents", "YutianReports")
    try:
        os.makedirs(docs, exist_ok=True)
        return docs
    except Exception:
        return os.path.expanduser("~")


def _save_last_dir(d: str) -> None:
    try:
        os.makedirs(_CONFIG_DIR, exist_ok=True)
        with open(_CONFIG_FILE, "w", encoding="utf-8") as fh:
            json.dump({"last_dir": d}, fh)
    except Exception:
        pass


def fmt_size(n: int) -> str:
    for unit, div in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= div:
            return f"{n / div:.1f} {unit}"
    return f"{n} B"


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1080x660")
        self.root.minsize(860, 500)

        self.inputs: list[str] = []
        self.results: list[Analysis] = []
        self.queue: queue.Queue = queue.Queue()
        self.busy = False
        self.elapsed = 0.0

        self._build()
        self.root.after(100, self._drain)
        self._status("就绪 —— 选择可疑文件后点「分析」，完成后导出报告发给分析人员")

    # ── 界面 ──
    def _build(self) -> None:
        st = ttk.Style(self.root)
        try:
            st.theme_use("vista")
        except tk.TclError:
            pass
        st.configure("Treeview", rowheight=22)
        st.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"))

        bar = ttk.Frame(self.root, padding=(8, 8, 8, 4))
        bar.pack(fill="x")
        ttk.Button(bar, text="添加文件…", width=12,
                   command=self.add_files).pack(side="left")
        ttk.Button(bar, text="添加文件夹…", width=12,
                   command=self.add_dir).pack(side="left", padx=(6, 0))
        self.btn_run = ttk.Button(bar, text="分析", width=12, command=self.run)
        self.btn_run.pack(side="left", padx=(6, 0))
        self.btn_exp = ttk.Button(bar, text="导出报告…", width=12,
                                  command=self.export, state="disabled")
        self.btn_exp.pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="清空", width=8,
                   command=self.clear).pack(side="left", padx=(6, 0))

        self.prog = ttk.Progressbar(self.root, mode="determinate", maximum=100)
        self.prog.pack(fill="x", padx=8, pady=(0, 4))

        wrap = ttk.Frame(self.root, padding=(8, 0, 8, 0))
        wrap.pack(fill="both", expand=True)
        cols = ("file", "kind", "size", "sha256", "sections", "imports",
                "strs")
        heads = ("文件", "类型", "大小", "SHA256(前16)", "区段", "导入函数",
                 "字符串类别")
        widths = (330, 110, 90, 180, 60, 90, 200)
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings")
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="w" if c == "file" else "center",
                             stretch=(c in ("file", "strs")))
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._detail)

        tip = ttk.Label(
            self.root, anchor="w", padding=(10, 2),
            text="提示：本工具只做事实描述，不下病毒判定。导出报告后发给分析人员。")
        tip.pack(fill="x", side="bottom")
        self.status = ttk.Label(self.root, anchor="w", padding=(10, 4),
                                relief="sunken")
        self.status.pack(fill="x", side="bottom")

    def _status(self, t: str) -> None:
        self.status.configure(text=t)

    # ── 输入 ──
    def add_files(self) -> None:
        ps = filedialog.askopenfilenames(title="选择要上报的文件")
        if ps:
            self.inputs.extend(ps)
            self._status(f"已加入 {len(self.inputs)} 个输入")

    def add_dir(self) -> None:
        d = filedialog.askdirectory(title="选择文件夹")
        if not d:
            return
        self.inputs.append(d)
        n = sum(len(fs) for _, _, fs in os.walk(d))
        self._status(f"已加入文件夹（约 {n} 个文件）")

    def clear(self) -> None:
        if self.busy:
            return
        self.inputs.clear()
        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        self.prog["value"] = 0
        self.btn_exp.configure(state="disabled")
        self._status("已清空")

    # ── 分析 ──
    def _iter_files(self):
        for p in self.inputs:
            if os.path.isdir(p):
                for dp, _dn, fn in os.walk(p):
                    for f in sorted(fn):
                        yield os.path.join(dp, f)
            elif os.path.isfile(p):
                yield p

    def run(self) -> None:
        if self.busy:
            return
        if not self.inputs:
            messagebox.showinfo("提示", "请先添加文件或文件夹")
            return
        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        self.prog["value"] = 0
        self.busy = True
        self.btn_run.configure(state="disabled")
        self.btn_exp.configure(state="disabled")
        threading.Thread(target=self._work, daemon=True).start()

    def _work(self) -> None:
        files = list(self._iter_files())
        t0 = time.perf_counter()
        for i, f in enumerate(files, 1):
            self.queue.put(("progress", (i, len(files))))
            try:
                a = Analysis(f).run()
            except Exception as exc:
                a = Analysis(f)
                a.error = f"{type(exc).__name__}: {exc}"
            self.queue.put(("row", a))
        self.elapsed = time.perf_counter() - t0
        self.queue.put(("done", len(files)))

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "progress":
                    cur, tot = payload
                    self.prog["value"] = cur * 100 / max(1, tot)
                    self._status(f"分析中 {cur}/{tot} …")
                elif kind == "row":
                    self._add(payload)
                elif kind == "done":
                    self._finish(payload)
        except queue.Empty:
            pass
        self.root.after(80, self._drain)

    def _add(self, a: Analysis) -> None:
        self.results.append(a)
        if a.error:
            self.tree.insert("", "end", values=(a.name, "-", "-", "-", "-", "-",
                                                "读取失败"))
            return
        self.tree.insert("", "end", values=(
            a.name, a.kind, fmt_size(a.size),
            a.hashes.get("SHA256", "")[:16],
            len(a.sections),
            sum(len(v) for v in a.imports.values()),
            " ".join(sorted(a.strings)) or "-"))
        self.tree.see(self.tree.get_children()[-1])

    def _finish(self, n: int) -> None:
        self.busy = False
        self.btn_run.configure(state="normal")
        self.prog["value"] = 100
        if self.results:
            self.btn_exp.configure(state="normal")
        self._status(f"完成 {n} 个文件 ｜ 用时 {self.elapsed:.1f}s ｜ "
                     f"导出报告后发给分析人员")

    # ── 详情 ──
    def _detail(self, _e=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        i = self.tree.index(sel[0])
        if not (0 <= i < len(self.results)):
            return
        a = self.results[i]
        top = tk.Toplevel(self.root)
        top.title(f"取证详情 · {a.name}")
        top.geometry("980x720")
        txt = tk.Text(top, wrap="none", font=("Consolas", 9))
        ys = ttk.Scrollbar(top, orient="vertical", command=txt.yview)
        xs = ttk.Scrollbar(top, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y")
        xs.pack(side="bottom", fill="x")
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", a.to_markdown(1))
        txt.configure(state="disabled")

    # ── 导出 ──
    def export(self) -> None:
        """导出报告。

        整个流程都包在 try 里 —— 之前只包了写文件那一段，拼报告时的任何异常
        都会静默失败，用户只看到"点了没反应"。现在任何错误都会弹出来带 traceback。
        """
        import traceback

        if not self.results:
            messagebox.showwarning(
                "无法导出",
                "还没有分析结果。\n\n请先「添加文件」→ 点「分析」，"
                "等表格里出现记录之后再导出。")
            return
        try:
            path = filedialog.asksaveasfilename(
                title="导出取证报告", defaultextension=".md",
                initialdir=_load_last_dir(),
                initialfile="取证报告.md",
                filetypes=[("Markdown", "*.md"), ("JSON", "*.json"),
                           ("所有文件", "*.*")])
            if not path:
                self._status("已取消导出")
                return
            _save_last_dir(os.path.dirname(path))
            host = socket.gethostname()
            if path.lower().endswith(".json"):
                payload = {
                    "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "host": host,
                    "elapsed_s": round(self.elapsed, 1),
                    "samples": [a.to_dict() for a in self.results],
                }
                text = json.dumps(payload, ensure_ascii=False, indent=2)
            else:
                parts = [header_markdown(host, len(self.results), self.elapsed)]
                for i, a in enumerate(self.results, 1):
                    parts.append(a.to_markdown(i))
                    parts.append("")
                text = "\n".join(parts)
            # 用二进制写 + 显式 utf-8 编码，避免被系统代码页影响
            with open(path, "wb") as fh:
                fh.write(text.encode("utf-8"))
            size_kb = os.path.getsize(path) / 1024
            self._status(f"已导出 {size_kb:.1f} KB -> {path}")
            messagebox.showinfo(
                "导出完成",
                f"报告已写入\n{path}\n（{size_kb:.1f} KB）\n\n"
                f"请把这个文件发给分析人员。")
        except Exception as exc:
            detail = traceback.format_exc()
            messagebox.showerror(
                "导出失败",
                f"{type(exc).__name__}: {exc}\n\n"
                f"（结果数 {len(self.results)}，"
                f"可用空间见下）\n\n{detail[-1200:]}")
            self._status("导出失败：" + str(exc)[:80])


def main() -> int:
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
