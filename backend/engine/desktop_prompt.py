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
窗口贴在屏幕**右下角**，与网页弹窗位置一致。

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

# ── 配色：与 ui_tk/andun_ui/theme.py 对齐 ──
# 主程序界面已从 WebView2（backend/frontend/*.html）整体换成 Tkinter（ui_tk/），
# 色板也跟着变了。这个桌面窗口原先用的是旧的火绒风（近黑 + 红），弹出来跟新界面
# 像是两个软件，所以对齐：
#
#     旧（火绒风）      新（ui_tk/andun_ui/theme.py）
#     #1b1b1d  卡片     BG_CARD        = #13131c
#     #131315  次级     BG_SIDEBAR     = #0e0e14
#     #f2f3f5  文字     TEXT_PRIMARY   = #f4f4f9
#     #8d9199  次文字   TEXT_SECONDARY = #8f8fab
#     #e0483c  强调红   DANGER         = #ff4d6d
#     —                 BORDER         = #252536
#     —                 BG_HOVER       = #1a1a26
#
# 为什么不直接 `from andun_ui import theme`：本文件在 backend/engine/ 下，而
# ui_tk/ 在仓库根（打包后在 _MEIPASS/ui_tk）。跨目录 import 在打包场景里多一个
# 失败点，而这里只是 7 个颜色常量 —— 复制值更稳。**改了 theme.py 记得同步这里。**
_BG = "#13131c"          # theme.BG_CARD        卡片底
_BG2 = "#0e0e14"         # theme.BG_SIDEBAR     行底
_FG = "#f4f4f9"          # theme.TEXT_PRIMARY
_DIM = "#8f8fab"         # theme.TEXT_SECONDARY
_RED = "#ff4d6d"         # theme.DANGER         威胁标记 +「立即隔离」
_RED_HOVER = "#ff6b85"   # 同色相提亮一档（theme 未定义 hover）
_BORDER = "#252536"      # theme.BORDER
_HOVER = "#1a1a26"       # theme.BG_HOVER       「忽略」按钮底
_HOVER_HI = "#252536"    # 「忽略」悬停
_GHOST_FG = "#f4f4f9"    # 「忽略」文字
_ON_DANGER = "#ffffff"   # DANGER 底上的文字
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
        # 显式 close() 之后永久停止；与"窗口意外退出"区分开（后者要能重启）
        self._closed = False
        self.available = True
        self.last_error = ""

    # ── 对外 ──
    def show(self, pd, decide_cb):
        """把一个待决项摆到桌面上（不阻塞）。返回是否已投递。

        2026-11-01 修正：不再用 `available` 做投递前的硬门禁。
        原实现里 mainloop 一退出就 `available = False`，而 `_ensure_thread`
        只认 `_started` 不会重启线程 —— 等于**这个进程余生所有通知都被静默丢弃**。
        现在只有显式 close() 才拒绝投递；窗口异常/正常退出后，下一次 show()
        会重新拉起（见 _run 的 finally 与 _reset_for_retry）。
        """
        if self._closed:
            return False
        self._q.put(("add", _Item(pd, decide_cb)))
        return self._ensure_thread()

    def dismiss(self, pending_id):
        """后端已处理（含超时自动处理）——把这一行从窗口上撤掉"""
        self._q.put(("remove", pending_id))

    def close(self):
        """永久关闭通知窗口（进程退出时调用）。之后 show() 一律返回 False。"""
        self._closed = True
        self._q.put(("quit", None))

    # ── 内部 ──
    def _reset_for_retry(self):
        """工作线程结束后复位，让下一次 show() 能重新拉起窗口。"""
        with self._lock:
            self._started = False

    def _ensure_thread(self) -> bool:
        """确保工作线程在跑；返回「是否可投递」。"""
        with self._lock:
            if self._started:
                return True
            self._started = True
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="yutian-desktop-prompt")
        try:
            self._thread.start()
        except Exception as exc:
            self._reset_for_retry()
            self.last_error = "通知线程启动失败: %s" % exc
            return False
        return True

    def _run(self):
        try:
            import tkinter as tk
        except Exception as exc:
            self.available = False
            self.last_error = "tkinter 不可用: %s" % exc
            self._reset_for_retry()      # 允许下次 show() 重试
            return
        try:
            root = tk.Tk()
        except Exception as exc:
            self.available = False
            self.last_error = "Tk 初始化失败: %s" % exc
            self._reset_for_retry()
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
            """窗口贴**右下角**，与网页右下角弹窗位置一致。

            底部留 64px 给任务栏 —— 不留的话窗口会被任务栏压住，
            而「立即隔离 / 忽略」两个按钮正好在那一行。
            """
            try:
                win.update_idletasks()
                sw = win.winfo_screenwidth()
                sh = win.winfo_screenheight()
                w = max(win.winfo_reqwidth(), 360)
                h = max(win.winfo_reqheight(), 120)
                win.geometry("+%d+%d" % (sw - w - 24, sh - h - 64))
            except Exception:
                pass

        def _build_row(item):
            pd = item.pd
            f = tk.Frame(rows_holder, bg=_BG2, highlightthickness=1,
                         highlightbackground=_BORDER)
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

            _mk("立即隔离", _RED, _ON_DANGER, _RED_HOVER, lambda: _decide("quarantine"))
            _mk("忽略", _HOVER, _GHOST_FG, _HOVER_HI, lambda: _decide("ignore"))

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
            # 2026-11-01：原来是 available=False 且不复位 _started —— 窗口一旦退出，
            # 此后所有通知永久失效。现在恢复可用并允许下一次 show() 重新拉起。
            self.available = True
            self._reset_for_retry()


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
