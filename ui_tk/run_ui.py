"""御天 Tkinter 界面入口。

用法::

    F:\\Python314\\python.exe ui_tk\\run_ui.py
    F:\\Python314\\python.exe ui_tk\\run_ui.py --base http://127.0.0.1:8899
    F:\\Python314\\python.exe ui_tk\\run_ui.py --self-test     # 无窗口自检

**本程序不接入主程序**：不导入 backend、不启动后端、不改任何配置。
它只是一个 HTTP 客户端；后端没在跑也能启动，只是显示「后端未连接」。
"""
from __future__ import annotations

import argparse
import os
import sys

# 允许 `python ui_tk/run_ui.py` 直接运行（此时包不在 sys.path 上）
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from andun_ui.api import DEFAULT_BASE, ApiClient  # noqa: E402


def _say(msg: str = ""):
    """自检输出一律 flush。

    原因：这个自检是用来排查"卡在哪一步"的。stdout 一旦被重定向就是块缓冲，
    不 flush 的话进程崩/卡时前面几行会全部丢掉，等于没有诊断信息。
    """
    print(msg, flush=True)


def _self_test() -> int:
    """无窗口自检，分 4 个阶段逐段打印。

    阶段划分是有意的：Tcl/Tk 的 DLL 加载发生在 ``import tkinter`` 与
    ``tk.Tk()``，如果进程在这一步卡死或崩溃，**第一行输出之前**就已经出事，
    所以每个阶段前先打印标记，才能看出卡在哪。

    返回 0 表示全部通过。
    """
    failures: list[str] = []

    # 1) 纯逻辑模块（不碰 tkinter，用来隔离"是代码问题还是环境问题"）
    #    注意：这里**只**导入 api。theme 里有 `import tkinter.font`，一旦导入
    #    就会加载 Tcl/Tk DLL，本阶段的隔离意义就没了。
    _say("[1/4] 纯逻辑模块（不加载 tkinter）")
    try:
        from andun_ui import api

        assert api.fmt_size(0) == "0 B", api.fmt_size(0)
        assert api.fmt_size(1536) == "1.5 KB", api.fmt_size(1536)
        assert api.fmt_size(1073741824) == "1.0 GB", api.fmt_size(1073741824)
        assert api.fmt_size("bogus") == "--"
        assert api.fmt_int(1234567) == "1,234,567"
        assert api.fmt_int(None) == "--"
        assert api.short_hash("abcdef1234567890", 6) == "abcdef…"
        assert api.short_hash("") == "--"
        assert api.fmt_time("2026-10-05T20:28:06+08:00") == "10-05 20:28", \
            api.fmt_time("2026-10-05T20:28:06+08:00")
        assert api.fmt_time("") == "--"
        assert api.fmt_time("garbage") == "garbage"
        _say("      [ok] api 工具函数（含边界值）")

        # 后端管理器同样不依赖 tkinter，放这里一并验（只读，不启进程）
        from andun_ui import backend as be

        prefs = be.load_prefs()
        assert isinstance(prefs, dict), "load_prefs 应返回 dict"
        for key in ("auto_start_backend", "stop_on_exit", "backend_dir", "python"):
            assert key in prefs, f"缺偏好键 {key}"
        mgr = be.BackendManager()
        assert mgr.python_exe(), "python_exe() 不应为空"
        assert mgr.base_url.startswith("http://"), mgr.base_url
        found = mgr.detect_backend_dir()
        _say(f"      [ok] backend 模块（后端目录={found or '未找到'}，"
             f"python={mgr.python_exe()}，偏好={be.PREFS_PATH}）")
    except Exception as exc:
        failures.append(f"api: {exc!r}")
        _say(f"      [FAIL] {exc!r}")

    # 2) tkinter 导入 + Tk 实例化（Tcl/Tk DLL 在这里加载）
    _say("[2/4] 加载 tkinter 并创建 Tk 根窗口")
    root = None
    try:
        import tkinter as tk

        _say(f"      tkinter 导入成功，版本 {tk.TkVersion}")
        from andun_ui import app as app_mod
        from andun_ui import theme as theme_mod

        root = tk.Tk()
        root.withdraw()
        theme_mod.resolve_fonts(root)
        _say(f"      [ok] Tk {tk.TkVersion}，UI 字体 = {theme_mod.ui_family()}")
    except Exception as exc:
        failures.append(f"tk: {exc!r}")
        _say(f"      [FAIL] {exc!r}")

    if root is not None:
        # 3) 页面类契约 + 构建（每个页面的 build() 真正跑一遍）
        _say("[3/4] 页面契约与控件构建")
        ctx = None
        try:
            from andun_ui.pages.clean import CleanPage
            from andun_ui.pages.engine import EnginePage
            from andun_ui.pages.history import HistoryPage
            from andun_ui.pages.lists import ListsPage
            from andun_ui.pages.logs import LogsPage
            from andun_ui.pages.optimize import OptimizePage
            from andun_ui.pages.overview import OverviewPage
            from andun_ui.pages.privacy import PrivacyPage
            from andun_ui.pages.quarantine import QuarantinePage
            from andun_ui.pages.recovery import RecoveryPage
            from andun_ui.pages.rules import RulesPage
            from andun_ui.pages.scan import ScanPage
            from andun_ui.pages.settings import SettingsPage
            from andun_ui.pages.tools import ToolsPage

            expected = {
                OverviewPage: "overview",
                ScanPage: "scan",
                QuarantinePage: "quarantine",
                CleanPage: "clean",
                OptimizePage: "optimize",
                ToolsPage: "tools",
                PrivacyPage: "privacy",
                RecoveryPage: "recovery",
                RulesPage: "rules",
                ListsPage: "lists",
                HistoryPage: "history",
                EnginePage: "engine",
                LogsPage: "logs",
                SettingsPage: "settings",
            }
            keys = set()
            for cls, key in expected.items():
                assert cls.key == key, f"{cls.__name__}.key={cls.key} 期望 {key}"
                assert isinstance(cls.title, str) and cls.title
                assert isinstance(cls.glyph, str) and cls.glyph
                keys.add(cls.key)
            assert len(keys) == len(expected), "页面 key 有重复"
            _say(f"      [ok] {len(expected)} 个页面类契约完整：{sorted(keys)}")

            from andun_ui import backend as be_local

            ctx = app_mod.AppContext(root, ApiClient("http://127.0.0.1:1"),
                                     app_mod.W.StatusLine(root), None,
                                     be_local.BackendManager())
            for cls in expected:
                page = cls(root, ctx)
                page.update_idletasks()
                page.destroy()
            _say("      [ok] 每个页面可构建并销毁（build() 无异常）")
        except Exception as exc:
            failures.append(f"pages: {exc!r}")
            _say(f"      [FAIL] {exc!r}")

        # 4) 生命周期：on_show → 跑几轮事件循环 → on_hide
        #    这一步会真正触发 refresh()，后端指向死端口，因此同时验证
        #    "后端不在时界面不崩"的离线降级路径，以及定时器能否被正确取消。
        _say("[4/4] 页面生命周期与离线降级（后端指向死端口，预期全部失败但不得崩溃）")
        if ctx is None:
            _say("      [SKIP] 上一阶段失败，跳过")
        else:
            from andun_ui.pages.clean import CleanPage
            from andun_ui.pages.engine import EnginePage
            from andun_ui.pages.history import HistoryPage
            from andun_ui.pages.lists import ListsPage
            from andun_ui.pages.logs import LogsPage
            from andun_ui.pages.optimize import OptimizePage
            from andun_ui.pages.overview import OverviewPage
            from andun_ui.pages.privacy import PrivacyPage
            from andun_ui.pages.quarantine import QuarantinePage
            from andun_ui.pages.recovery import RecoveryPage
            from andun_ui.pages.rules import RulesPage
            from andun_ui.pages.scan import ScanPage
            from andun_ui.pages.settings import SettingsPage
            from andun_ui.pages.tools import ToolsPage

            # 并非所有页面都会注册周期任务（every()）：
            #   有 every() 的：overview / tools / engine / logs / settings / privacy
            #   只在有活动任务时才轮询的：scan（扫描中）、clean（扫描中）、
            #                             tools 的漏洞/沙箱、recovery 的还原
            #   只在 on_show 拉一次的：quarantine / optimize / rules / history
            order = (OverviewPage, ScanPage, QuarantinePage, CleanPage,
                     OptimizePage, ToolsPage, PrivacyPage, RecoveryPage, RulesPage,
                     ListsPage, HistoryPage, EnginePage, LogsPage, SettingsPage)
            expects_timer = {
                OverviewPage: True, ScanPage: False, QuarantinePage: False,
                CleanPage: False, OptimizePage: False, ToolsPage: True,
                PrivacyPage: True,
                RecoveryPage: False, RulesPage: False, HistoryPage: False,
                ListsPage: True,
                EnginePage: True, LogsPage: True, SettingsPage: True,
            }

            for cls in order:
                try:
                    page = cls(root, ctx)
                    page.pack(fill="both", expand=True)
                    page.on_show()
                    # 跑几轮事件循环：让 after(0,...) 回调与离线降级分支执行
                    for _ in range(4):
                        root.update()

                    if expects_timer[cls] and not page._timers:
                        raise AssertionError("on_show 未注册周期任务")
                    pending = len(page._timers)

                    page.on_hide()
                    if page._timers:
                        raise AssertionError(f"on_hide 未清空定时器（剩 {page._timers}）")

                    page.destroy()
                    _say(f"      [ok] {cls.__name__} on_show/on_hide 正常"
                         f"（周期任务 {pending} 个）")
                except Exception as exc:
                    failures.append(f"lifecycle[{cls.__name__}]: {exc!r}")
                    _say(f"      [FAIL] {cls.__name__}: {exc!r}")

        try:
            root.destroy()
        except Exception:
            pass

    _say()
    if failures:
        _say("自检失败：")
        for item in failures:
            _say(f"  - {item}")
        return 1

    _say("自检通过。")
    return 0


def _enable_hidpi() -> float:
    """开启进程 DPI 感知，返回建议的 Tk scaling。

    不开启的话，在 150%/200% 缩放的屏幕上 Windows 会把整个窗口**位图拉伸**，
    界面明显发糊。必须在创建 ``Tk()`` **之前**调用才有效。

    Tk 的 scaling 语义是"每 point 多少像素"，默认约 1.333（96/72）。
    这里按实测 DPI 换算，任何一步失败都静默放弃——宁可糊一点，也不能因为
    DPI 处理让界面起不来或布局错乱。
    """
    if os.name != "nt":
        return 0.0
    try:
        import ctypes

        try:
            # Win8.1+：per-monitor aware
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()

        hdc = ctypes.windll.user32.GetDC(0)
        try:
            dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)  # LOGPIXELSX
        finally:
            ctypes.windll.user32.ReleaseDC(0, hdc)
        if dpi and dpi > 0:
            return dpi / 72.0
    except Exception:
        pass
    return 0.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="御天 Tkinter 桌面界面（独立运行）")
    parser.add_argument("--base", default=DEFAULT_BASE,
                        help=f"后端地址，默认 {DEFAULT_BASE}")
    parser.add_argument("--page", default="overview",
                        help="启动后直接进入的页面 key（overview/scan/quarantine/logs/settings）")
    parser.add_argument("--self-test", action="store_true",
                        help="不打开窗口，只做导入与页面契约自检")
    parser.add_argument("--no-dpi", action="store_true",
                        help="不开启 DPI 感知（默认开启，避免高缩放屏下发糊）")
    parser.add_argument("--no-backend", action="store_true",
                        help="本次运行不自动拉起后端（仅本次，不写入偏好）")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    scaling = 0.0 if args.no_dpi else _enable_hidpi()

    from andun_ui.app import App

    app = App(base_url=args.base, initial_page=args.page)
    if args.no_backend:
        # 只改内存里的偏好，不落盘 —— 免得临时用一次就把用户的设置改掉
        app.backend.prefs["auto_start_backend"] = False
    if scaling > 0:
        try:
            app.root.tk.call("tk", "scaling", scaling)
        except Exception:
            pass
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
