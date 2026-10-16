"""主窗口：侧边栏导航 + 页面容器 + 底部状态条。

页面模型
--------
每个页面是 :class:`Page` 子类，挂在 ``self.container`` 上。切页时
**调用 ``on_hide()`` 并 pack_forget，而不是 destroy** —— 保留控件树可以避免
反复重建带来的卡顿；代价是页面必须自己负责停掉定时器（``on_hide`` 里做）。
窗口关闭时统一 ``on_hide()`` 收尾。
"""
from __future__ import annotations

import tkinter as tk
import urllib.parse

from . import theme as T
from . import widgets as W
from .api import ApiClient, run_async
from .backend import BackendManager

APP_TITLE = "御天 · 安全防护"
WINDOW_W, WINDOW_H = 1180, 760
MIN_W, MIN_H = 940, 620
BACKEND_POLL_MS = 5000


class AppContext:
    """页面共享的上下文：HTTP 客户端、状态条、主窗口引用、后端管理器。"""

    def __init__(self, root: tk.Tk, client: ApiClient, status: W.StatusLine,
                 app: "App", backend: BackendManager | None = None):
        self.root = root
        self.client = client
        self.status = status
        self.app = app
        self.backend = backend

    def say(self, text: str, level: str = "info"):
        """在底部状态条留言（线程安全的：内部走 after）。"""
        try:
            self.root.after(0, lambda: self.status.set(text, level))
        except Exception:
            pass

    def navigate(self, key: str):
        self.app.show_page(key)


class Page(tk.Frame):
    """页面基类。子类实现 ``build()`` 与可选的 ``on_show`` / ``on_hide``。"""

    #: 侧边栏显示名
    title = "页面"
    #: 侧边栏图标字符（用 Unicode 而非位图，省掉 PIL/ImageTk 依赖）
    glyph = "•"
    #: 导航键
    key = "page"

    def __init__(self, parent, ctx: AppContext):
        super().__init__(parent, bg=T.BG_APP)
        self.ctx = ctx
        self.client = ctx.client
        self._timers: list[str] = []
        self.build()

    # ── 子类实现 ──

    def build(self):
        """构建界面。只调用一次。"""

    def on_show(self):
        """页面变为可见时调用。适合启动轮询。"""

    def on_hide(self):
        """页面被切走时调用。必须停掉本页所有定时器。"""

    # ── 定时器登记（避免忘记 after_cancel）──

    def every(self, ms: int, fn) -> str:
        """注册一个周期性回调，``on_hide`` / ``destroy`` 时自动取消。"""
        aid = self.after(ms, lambda: self._run_timer(aid, ms, fn))
        self._timers.append(aid)
        return aid

    def _run_timer(self, aid: str, ms: int, fn):
        # 先注销当前 id，再执行；执行中若页面已隐藏则不再续期
        if aid in self._timers:
            self._timers.remove(aid)
        if not self.winfo_exists():
            return
        try:
            fn()
        except Exception:
            pass
        if self.winfo_exists():
            try:
                new_id = self.after(ms, lambda: self._run_timer(new_id, ms, fn))
                self._timers.append(new_id)
            except tk.TclError:
                pass

    def once(self, ms: int, fn) -> str:
        aid = self.after(ms, fn)
        self._timers.append(aid)
        return aid

    def cancel_timers(self):
        for aid in list(self._timers):
            try:
                self.after_cancel(aid)
            except Exception:
                pass
        self._timers.clear()

    def destroy(self):
        self.cancel_timers()
        super().destroy()


class App:
    def __init__(self, client: ApiClient | None = None, base_url: str | None = None,
                 initial_page: str = "overview"):
        self.root = tk.Tk()
        self.root.title(APP_TITLE)
        self.root.configure(bg=T.BG_APP)
        self.root.geometry(f"{WINDOW_W}x{WINDOW_H}")
        self.root.minsize(MIN_W, MIN_H)

        T.resolve_fonts(self.root)

        self.client = client or ApiClient(base_url or "http://127.0.0.1:8899")
        # 后端生命周期由界面代管（探测/拉起/停止）。只连接、只停自己启的，
        # 若后端早已在跑（用户自己起的、或主程序在跑）则绝不接管。
        parsed = urllib.parse.urlparse(self.client.base)
        self.backend = BackendManager(host=parsed.hostname or "127.0.0.1",
                                      port=parsed.port or 8899)
        self._initial_page = initial_page or "overview"
        self._pages: dict[str, Page] = {}
        self._nav_buttons: dict[str, tk.Button] = {}
        self._active: str | None = None
        self._backend_ok: bool | None = None
        self._poll_id: str | None = None
        self._start_busy = False
        self._closing = False

        self._build_shell()

    # ── 外壳 ──

    def _build_shell(self):
        body = tk.Frame(self.root, bg=T.BG_APP)
        body.pack(fill="both", expand=True)

        self._build_sidebar(body)

        right = tk.Frame(body, bg=T.BG_APP)
        right.pack(side="left", fill="both", expand=True)

        # 顺序要紧：先 pack 底部固定条，最后 pack 自适应内容区。
        # 反过来写的话，expand 容器会先吃掉全部空间，底栏可能被压成 0 高度。
        self.status = W.StatusLine(right, bg=T.BG_SIDEBAR)
        self.status.pack(side="bottom", fill="x")
        tk.Frame(right, bg=T.BORDER, height=1).pack(side="bottom", fill="x")

        self.container = tk.Frame(right, bg=T.BG_APP)
        self.container.pack(fill="both", expand=True)

    def _build_sidebar(self, parent):
        bar = tk.Frame(parent, bg=T.BG_SIDEBAR, width=T.SIDEBAR_W)
        bar.pack(side="left", fill="y")
        bar.pack_propagate(False)

        # 品牌区
        brand = tk.Frame(bar, bg=T.BG_SIDEBAR)
        brand.pack(fill="x", pady=(20, 18), padx=16)
        tk.Label(brand, text="◈", bg=T.BG_SIDEBAR, fg=T.ACCENT,
                 font=T.font(20, "bold")).pack(side="left")
        tk.Label(brand, text="御天", bg=T.BG_SIDEBAR, fg=T.TEXT_PRIMARY,
                 font=T.font(14, "bold")).pack(side="left", padx=(8, 0))

        self._nav_host = tk.Frame(bar, bg=T.BG_SIDEBAR)
        self._nav_host.pack(fill="x", padx=10)

        # 底部后端状态 + 启停
        foot = tk.Frame(bar, bg=T.BG_SIDEBAR)
        foot.pack(side="bottom", fill="x", pady=14, padx=16)
        row = tk.Frame(foot, bg=T.BG_SIDEBAR)
        row.pack(fill="x")
        self._backend_dot = tk.Canvas(row, width=8, height=8, bg=T.BG_SIDEBAR,
                                      highlightthickness=0, bd=0)
        self._backend_dot.pack(side="left")
        self._backend_dot_id = self._backend_dot.create_oval(
            1, 1, 7, 7, fill=T.TEXT_MUTED, outline="")
        self._backend_label = tk.Label(row, text="后端未连接", bg=T.BG_SIDEBAR,
                                       fg=T.TEXT_MUTED, font=T.font(9), anchor="w")
        self._backend_label.pack(side="left", padx=(6, 0))
        tk.Label(foot, text=self.client.base.replace("http://", ""),
                 bg=T.BG_SIDEBAR, fg=T.TEXT_MUTED, font=T.mono(8),
                 anchor="w").pack(fill="x", pady=(2, 0))

        # 启停按钮：文字随状态在"启动后端 / 停止后端"之间切换
        self._backend_btn = tk.Button(
            foot, text="启动后端", command=self.on_backend_button,
            bg=T.BG_HOVER, fg=T.TEXT_PRIMARY, activebackground=T.BORDER_LIGHT,
            activeforeground=T.TEXT_PRIMARY, disabledforeground=T.TEXT_MUTED,
            relief="flat", bd=0, highlightthickness=0, font=T.font(9),
            cursor="hand2", padx=8, pady=4)
        self._backend_btn.pack(fill="x", pady=(8, 0))

    def _register(self, page: Page):
        self._pages[page.key] = page
        host = self._nav_host

        def _go():
            self.show_page(page.key)

        btn = tk.Button(host, text=f"  {page.glyph}   {page.title}", command=_go,
                        bg=T.BG_SIDEBAR, fg=T.TEXT_SECONDARY,
                        activebackground=T.BG_HOVER, activeforeground=T.TEXT_PRIMARY,
                        relief="flat", bd=0, highlightthickness=0,
                        font=T.font(10), anchor="w", cursor="hand2",
                        padx=10, pady=9)
        btn.pack(fill="x", pady=2)
        btn.bind("<Enter>", lambda _e, b=btn, k=page.key: self._hover_nav(b, k, True))
        btn.bind("<Leave>", lambda _e, b=btn, k=page.key: self._hover_nav(b, k, False))
        self._nav_buttons[page.key] = btn

    def _hover_nav(self, btn: tk.Button, key: str, entering: bool):
        if key == self._active:
            return
        try:
            btn.configure(bg=T.BG_HOVER if entering else T.BG_SIDEBAR)
        except tk.TclError:
            pass

    # ── 页面切换 ──

    def show_page(self, key: str):
        page = self._pages.get(key)
        if page is None or key == self._active:
            return

        if self._active is not None:
            old = self._pages.get(self._active)
            if old is not None:
                try:
                    old.on_hide()
                except Exception:
                    pass
                old.pack_forget()

        page.pack(fill="both", expand=True)
        self._active = key

        # 导航高亮
        for nav_key, btn in self._nav_buttons.items():
            try:
                if nav_key == key:
                    btn.configure(bg=T.BG_HOVER, fg=T.ACCENT)
                else:
                    btn.configure(bg=T.BG_SIDEBAR, fg=T.TEXT_SECONDARY)
            except tk.TclError:
                pass

        try:
            page.on_show()
        except Exception:
            pass

    # ── 后端连通性轮询 ──

    def _poll_backend(self):
        """定期探测后端存活，用于侧栏指示灯与状态条。

        这里**不**在"刚连上"时重新触发页面 on_show：页面各自有 5-8s 的刷新
        周期，会自己拿到数据；而重复调用 on_show 会让 every() 再注册一条
        定时器链，导致刷新频率翻倍。
        """
        def done(result):
            self._set_backend_state(bool(getattr(result, "ok", False)))

        run_async(self.root, self.client.health, done,
                  lambda _exc: self._set_backend_state(False))

    def _set_backend_state(self, ok: bool):
        if ok == self._backend_ok:
            return
        self._backend_ok = ok
        try:
            self._backend_dot.itemconfigure(
                self._backend_dot_id, fill=T.SUCCESS if ok else T.DANGER)
            self._backend_label.configure(
                text="后端已连接" if ok else "后端未连接",
                fg=T.TEXT_SECONDARY if ok else T.TEXT_MUTED)
            if not self._start_busy:
                # 已连接时按钮变成"停止"；但只有"本界面启动的"才真的能停
                if ok:
                    if self.backend.started_by_us:
                        self._backend_btn.configure(text="停止后端", state="normal",
                                                    cursor="hand2")
                    else:
                        self._backend_btn.configure(text="外部后端", state="disabled",
                                                    cursor="")
                else:
                    self._backend_btn.configure(text="启动后端", state="normal",
                                                cursor="hand2")
        except tk.TclError:
            pass
        self.status.set(
            "后端已连接" if ok else "后端未连接 —— 可点左下角「启动后端」",
            "ok" if ok else "warn")

    # ── 后端启停 ──

    def on_backend_button(self):
        if self.backend.is_alive(timeout=1.0):
            self.stop_backend()
        else:
            self.start_backend()

    def _set_start_busy(self, busy: bool, text: str = ""):
        self._start_busy = busy
        try:
            if busy:
                self._backend_btn.configure(state="disabled",
                                            text=text or "启动中…", cursor="")
            else:
                self._backend_btn.configure(state="normal")
        except tk.TclError:
            pass

    def start_backend(self):
        """拉起后端并等待就绪（异步，不阻塞 UI）。设置页与侧栏按钮共用。"""
        if self._start_busy:
            return
        self._set_start_busy(True)
        self.status.set("正在启动后端…", "info")

        def work():
            ok, message = self.backend.start()
            if not ok:
                return (False, message)
            ready, ready_msg = self.backend.wait_ready(
                should_abort=lambda: self._closing)
            return (ready, ready_msg if not ready else message)

        def done(result):
            ok, message = result
            self._set_start_busy(False)
            self.status.set(message, "ok" if ok else "error")
            if ok:
                self._refresh_current_page()
            # 无论成败都立刻探一次，让指示灯/按钮回到真实状态
            self._poll_backend()

        run_async(self.root, work, done,
                  lambda exc: (self._set_start_busy(False),
                               self.status.set(f"启动后端异常：{exc}", "error")))

    def stop_backend(self):
        """停止本界面启动的后端；外部启动的一律拒绝。"""
        if not self.backend.started_by_us:
            self.status.set("后端不是本界面启动的，不予停止", "warn")
            return

        def work():
            return self.backend.stop()

        def done(result):
            ok, message = result
            self.status.set(message, "ok" if ok else "error")
            self._poll_backend()

        run_async(self.root, work, done)

    def _refresh_current_page(self):
        """后端刚起来时，让当前页立刻拉一次数据，不用等下一个轮询周期。"""
        page = self._pages.get(self._active or "")
        if page is None:
            return
        try:
            handler = getattr(page, "refresh", None)
            if callable(handler):
                handler()
            else:
                page.on_show()
        except Exception:
            pass

    def _schedule_poll(self):
        self._poll_backend()
        self._poll_id = self.root.after(BACKEND_POLL_MS, self._schedule_poll)

    # ── 生命周期 ──

    def load_pages(self):
        """导入并注册所有页面。放在这里而不是模块顶层，避免循环 import。"""
        from .pages.clean import CleanPage
        from .pages.engine import EnginePage
        from .pages.history import HistoryPage
        from .pages.logs import LogsPage
        from .pages.optimize import OptimizePage
        from .pages.overview import OverviewPage
        from .pages.privacy import PrivacyPage
        from .pages.quarantine import QuarantinePage
        from .pages.recovery import RecoveryPage
        from .pages.rules import RulesPage
        from .pages.scan import ScanPage
        from .pages.settings import SettingsPage
        from .pages.tools import ToolsPage

        # 顺序即侧边栏顺序：日常主链路 → 工具 → 记录/管理 → 设置
        # PrivacyPage 紧跟 ToolsPage：它的开关就在工具页的「增强防护」卡片里，
        # 放一起用户在概念上不会走散。
        order = (OverviewPage, ScanPage, QuarantinePage, CleanPage, OptimizePage,
                 ToolsPage, PrivacyPage, RecoveryPage, RulesPage, HistoryPage,
                 EnginePage, LogsPage, SettingsPage)
        for cls in order:
            page = cls(self.container,
                       AppContext(self.root, self.client, self.status,
                                  self, self.backend))
            self._register(page)

    def run(self):
        self.load_pages()
        if self._pages:
            first = self._initial_page if self._initial_page in self._pages else "overview"
            if first not in self._pages:
                first = next(iter(self._pages))
            self.show_page(first)
        self._schedule_poll()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # 自动拉起后端：先探一次，没在跑且偏好允许就启动。
        # 放在 mainloop 之前异步做，避免拖慢界面首帧。
        if self.backend.prefs.get("auto_start_backend", True):
            self.root.after(300, self._auto_start_backend)

        self.root.mainloop()

    def _auto_start_backend(self):
        def work():
            if self.backend.is_alive(timeout=1.5):
                return (True, "后端已在运行")
            ok, message = self.backend.start()
            if not ok:
                return (False, message)
            ready, ready_msg = self.backend.wait_ready(
                should_abort=lambda: self._closing)
            return (ready, ready_msg)

        def done(result):
            ok, message = result
            self.status.set(message, "ok" if ok else "error")
            if ok:
                self._refresh_current_page()
            self._poll_backend()

        run_async(self.root, work, done)

    def _on_close(self):
        self._closing = True
        if self._poll_id is not None:
            try:
                self.root.after_cancel(self._poll_id)
            except Exception:
                pass
            self._poll_id = None
        for page in self._pages.values():
            try:
                page.on_hide()
            except Exception:
                pass
        # 只关自己启的后端；默认不关（关掉等于关掉防护）
        if self.backend.prefs.get("stop_on_exit", False):
            try:
                self.backend.stop()
            except Exception:
                pass
        try:
            self.root.destroy()
        except Exception:
            pass
