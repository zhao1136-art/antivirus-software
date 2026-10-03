"""
桌面决策窗口 —— 用户不在浏览器前时的**唯一可点通道**

为什么必须有它
--------------
2026-10-03：威胁处置做成了「右下角网页弹窗 + 系统托盘气泡」。但这两条都是
**通知**而非**决策**：

    * 浏览器右下角弹窗 —— 用户人在桌面/别的程序里，根本点不到；
    * 系统托盘气泡   —— 只能看，没有按钮。

结果是：**桌面用户没有任何可以点的地方，15 秒一到文件照样被自动隔离。**
这和当天那两次事故是同一个病根 —— 用户没参与，东西就没了。

所以这里用 tkinter 起一个**置顶的原生窗口**，完全独立于浏览器页面：
一行一个待决威胁，带倒计时和「立即隔离 / 忽略」两个按钮。

实现要点
--------
* Tk 必须在**自己的线程**里跑 mainloop，且**一个进程只用一个 Tk 根窗口**
  （多个 root 会出各种怪问题），所以这里做成单例 + 一个窗口承载多条待决项。
* 窗口用 `overrideredirect` 去边框、`-topmost` 置顶，自己画标题栏和关闭钮。
* 所有跨线程操作都通过队列进 Tk 线程，不直接碰控件。
* 用户点了按钮就回调 `YutianDecision.decide()`；窗口只负责收集决定。
* 任何异常都不能影响判定流程 —— 桌面窗口起不来时，网页弹窗和托盘气泡仍在。
"""
from __future__ import annotations

import queue
import threading
import time

__all__ = ["DesktopDecisionWindow", "get_window", "show", "dismiss_all"]

_BG = "#1b1b1d"
_BG2 = "#131315"
_FG = "#f2f3f5"
_DIM = "#8d9199"
_RED = "#e0483c"
_RED_HOVER = "#ef5a4e"
_GREY = "rgba"  # 占位，不用


class _Item:
    __slots__ = ("pd", "decide_cb")

    def __init__(self, pd, decide_cb):
        self.pd = pd
        self.decide_cb = decide_cb


class DesktopDecisionWindow:
    """单例的置顶决策窗口。线程安全：show/dismiss 可从任意线程调用。"""

    def __init__(self):
        self._q = queue.Queue()
        self._thread = None
        self._lock = threading.Lock()
        self._started = False
        self.available = True
        self.last_error = ""

    # ── 对外 ──
    def show(self, pd, decide_cb):
        """把一个待决项摆到桌面上（不阻塞）"""
        if not self.available:
            return False
        self._q.put(("add", _Item(pd, decide_cb)))
        self._ensure_thread()
        return True

    def dismiss(self, pending_id):
        """后端已处理（含超时自动处理）——把这一行从窗口上撤掉"""
        self._q.put(("remove", pending_id))

    def close(self):
        self._q.put(("quit", None))

    # ── 内部 ──
    def _ensure_thread(self):
        with self._lock:
            if self._started:
                return
            self._started = True
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="yutian-desktop-prompt")
        self._thread.start()

    def _run(self):
        try:
            import tkinter as tk
        except Exception as exc:
            self.available = False
            self.last_error = "tkinter 不可用: %s" % exc
            return
        try:
            root = tk.Tk()
        except Exception as exc:
            self.available = False
            self.last_error = "Tk 初始化失败: %s" % exc
            return

        root.withdraw()
        root.overrideredirect(True)
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass

        win = tk.Toplevel(root)
        win.overrideredirect(True)
        try:
            win.attributes("-topmost", True)
            win.attributes("-alpha", 0.98)
        except Exception:
            pass
        win.configure(bg=_BG)

        header = tk.Frame(win, bg=_RED, height=3)
        header.pack(fill="x", side="top")

        title = tk.Label(win, text="  御天 · 发现威胁", bg=_BG, fg=_FG,
                         font=("Microsoft YaHei UI", 11, "bold"), anchor="w")
        title.pack(fill="x", padx=12, pady=(10, 2))

        rows_holder = tk.Frame(win, bg=_BG)
        rows_holder.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        state = {"rows": {}, "alive": True}

        def _place():
            """窗口贴右上角"""
            try:
                win.update_idletasks()
                sw = win.winfo_screenwidth()
                w = max(win.winfo_reqwidth(), 360)
                win.geometry("+%d+%d" % (sw - w - 24, 24))
            except Exception:
                pass

        def _build_row(item):
            pd = item.pd
            f = tk.Frame(rows_holder, bg=_BG2, highlightthickness=1,
                         highlightbackground="#2b2b2e")
            f.pack(fill="x", pady=(6, 0))

            name = tk.Label(f, text=(pd.threat_name or "未知威胁"), bg=_BG2, fg=_FG,
                            font=("Microsoft YaHei UI", 10, "bold"), anchor="w",
                            justify="left", wraplength=330)
            name.pack(fill="x", padx=10, pady=(8, 0))

            path = tk.Label(f, text=pd.path, bg=_BG2, fg=_DIM,
                            font=("Consolas", 8), anchor="w", justify="left",
                            wraplength=330)
            path.pack(fill="x", padx=10, pady=(1, 0))

            foot = tk.Frame(f, bg=_BG2)
            foot.pack(fill="x", padx=10, pady=(6, 9))

            left = tk.Label(foot, text="", bg=_BG2, fg=_DIM,
                            font=("Microsoft YaHei UI", 9), anchor="w")
            left.pack(side="left")

            def _mk(text, bg, fg, hover, cb):
                b = tk.Label(foot, text=text, bg=bg, fg=fg, cursor="hand2",
                             font=("Microsoft YaHei UI", 9), padx=12, pady=3)
                b.pack(side="right", padx=(6, 0))
                b.bind("<Button-1>", lambda _e: cb())
                b.bind("<Enter>", lambda _e: b.configure(bg=hover))
                b.bind("<Leave>", lambda _e: b.configure(bg=bg))
                return b

            def _decide(action):
                try:
                    item.decide_cb(pd.id, action)
                except Exception:
                    pass
                _remove(pd.id)

            _mk("立即隔离", _RED, "#ffffff", _RED_HOVER, lambda: _decide("quarantine"))
            _mk("忽略", "#2a2a2d", "#c9ccd2", "#37373b", lambda: _decide("ignore"))

            state["rows"][pd.id] = {"frame": f, "left": left, "deadline": pd.deadline,
                                    "total": max(0.1, pd.deadline - pd.created_at)}
            return f

        def _remove(pid):
            row = state["rows"].pop(pid, None)
            if row is not None:
                try:
                    row["frame"].destroy()
                except Exception:
                    pass
            _place()
            if not state["rows"]:
                try:
                    win.withdraw()
                except Exception:
                    pass

        def _pump():
            """从队列取指令（Tk 线程内执行）"""
            if not state["alive"]:
                return
            try:
                while True:
                    op, payload = self._q.get_nowait()
                    if op == "add":
                        _build_row(payload)
                        win.deiconify()
                        _place()
                    elif op == "remove":
                        _remove(payload)
                    elif op == "quit":
                        state["alive"] = False
                        try:
                            root.quit()
                        except Exception:
                            pass
                        return
            except queue.Empty:
                pass
            root.after(120, _pump)

        def _tick():
            """更新倒计时；到 0 后由后端自动处理，这里只把行撤掉"""
            if not state["alive"]:
                return
            now = time.time()
            for pid, row in list(state["rows"].items()):
                left = row["deadline"] - now
                if left <= 0:
                    row["left"].configure(text="正在自动处理…", fg=_RED)
                else:
                    row["left"].configure(text="%d 秒后自动隔离" % int(left + 0.999),
                                          fg=_RED if left < 5 else _DIM)
            root.after(200, _tick)

        win.withdraw()
        root.after(120, _pump)
        root.after(200, _tick)
        try:
            root.mainloop()
        except Exception as exc:
            self.last_error = str(exc)
        finally:
            self.available = False


_win = None
_win_lock = threading.Lock()


def get_window() -> DesktopDecisionWindow:
    global _win
    with _win_lock:
        if _win is None:
            _win = DesktopDecisionWindow()
        return _win


def show(pd, decide_cb) -> bool:
    return get_window().show(pd, decide_cb)


def dismiss_all(pending_ids) -> None:
    w = get_window()
    for pid in pending_ids:
        w.dismiss(pid)
