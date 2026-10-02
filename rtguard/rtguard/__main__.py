"""
御天实时防护（新版）入口

    python -m rtguard --dirs "C:\\Users\\me\\Downloads" "%TEMP%"
    python -m rtguard --once <文件或目录>        # 单次扫描，不进监控模式

默认**只告警、不自动隔离**。理由是实测规则集存在误报（notepad.exe 就会命中
三条 LNK 相关规则），自动处置会误删系统文件。确认规则集可信后再用
--quarantine-on-detect 打开自动隔离。
"""
from __future__ import annotations

import argparse
import os
import queue
import signal
import sys
import threading
import time

from .scanner import Scanner, DEFAULT_EXTENSIONS
from .watcher import DirWatcher
from .quarantine import Quarantine
from .tray import TrayIcon

DEFAULT_DIRS = [
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.environ.get("TEMP", ""),
]

SEVERITY_RANK = {"clean": 0, "suspicious": 1, "malicious": 2}


class Probe:
    """有界工作队列 + 固定扫描线程池"""

    def __init__(self, scanner, workers=2, quarantine=None, quarantine_on_detect=False,
                 verbose=False):
        self.scanner = scanner
        self.queue: "queue.Queue[str]" = queue.Queue(maxsize=4096)
        self.quarantine = quarantine
        self.auto_quarantine = quarantine_on_detect
        self.verbose = verbose
        self._stop = threading.Event()
        self._threads = []
        self._seen = {}                     # path -> (size, mtime) 去重
        self._lock = threading.Lock()
        self.counts = {"scanned": 0, "malicious": 0, "suspicious": 0, "skipped": 0}
        self._workers = max(1, min(int(workers), 4))

    def start(self):
        for i in range(self._workers):
            t = threading.Thread(target=self._run, daemon=True,
                                 name="rtguard-scan-%d" % i)
            t.start()
            self._threads.append(t)

    def submit(self, path: str):
        if self._stop.is_set():
            return
        try:
            st = os.stat(path)
        except OSError:
            return
        key = (st.st_size, int(st.st_mtime))
        with self._lock:
            if self._seen.get(path) == key:
                return
            self._seen[path] = key
            if len(self._seen) > 20000:
                self._seen.clear()
                self._seen[path] = key
        try:
            self.queue.put_nowait(path)
        except queue.Full:
            pass

    def _run(self):
        while not self._stop.is_set():
            try:
                path = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._handle(path)
            except Exception as exc:
                if self.verbose:
                    print("[scan] 异常 %s: %s" % (path, exc))
            finally:
                self.queue.task_done()

    def _handle(self, path):
        res = self.scanner.scan_file(path)
        if res.verdict == "skipped":
            self.counts["skipped"] += 1
            return
        self.counts["scanned"] += 1
        if res.verdict == "clean":
            if self.verbose:
                print("[clean] %s (%.1f ms)" % (path, res.elapsed * 1000))
            return
        self.counts[res.verdict] = self.counts.get(res.verdict, 0) + 1
        rules = ", ".join(t["rule"] for t in res.threats[:3])
        print("[%s] %s  ->  %s" % (res.verdict.upper(), path, rules))

        if (res.verdict == "malicious" and self.auto_quarantine
                and self.quarantine is not None):
            try:
                entry = self.quarantine.add(path, {
                    "verdict": res.verdict,
                    "rules": [t["rule"] for t in res.threats],
                    "sha256": res.sha256,
                })
                print("   已隔离: %s (id=%s)" % (path, entry.get("id")))
            except Exception as exc:
                print("   隔离失败: %s" % exc)

    def stop(self, timeout=3.0):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=timeout)
        self._threads.clear()


def _scan_path(scanner, target, recursive=True):
    """单次扫描模式"""
    targets = []
    if os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
            for f in files:
                targets.append(os.path.join(root, f))
            if not recursive:
                break
    else:
        targets.append(target)
    n = {"clean": 0, "suspicious": 0, "malicious": 0, "skipped": 0, "error": 0}
    worst = []
    t0 = time.perf_counter()
    total = 0
    for p in targets:
        r = scanner.scan_file(p)
        n[r.verdict] = n.get(r.verdict, 0) + 1
        total += r.size
        if r.verdict in ("suspicious", "malicious"):
            worst.append((r.verdict, p, [t["rule"] for t in r.threats]))
    el = time.perf_counter() - t0
    print("")
    print("扫描 %d 个文件, %.1f MB, 用时 %.2f s (%.1f MB/s)" % (
        len(targets), total / 1048576.0, el, (total / 1048576.0) / el if el else 0))
    print("  clean=%d suspicious=%d malicious=%d skipped=%d error=%d" % (
        n["clean"], n["suspicious"], n["malicious"], n["skipped"], n["error"]))
    for verdict, p, rules in worst[:20]:
        print("  [%s] %s -> %s" % (verdict.upper(), p, ", ".join(rules[:3])))
    return 0 if not worst else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="rtguard", description="御天实时防护（新版）")
    ap.add_argument("--rules", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "engine", "yara_rules"),
        help="YARA 规则目录")
    ap.add_argument("--dirs", nargs="*", default=None, help="要监控的目录")
    ap.add_argument("--quarantine", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "quarantine"),
        help="隔离区目录")
    ap.add_argument("--workers", type=int, default=2, help="扫描线程数 1~4")
    ap.add_argument("--max-mb", type=int, default=64, help="单文件扫描上限 MB")
    ap.add_argument("--quarantine-on-detect", action="store_true",
                    help="检出即隔离（默认关闭：规则集存在误报）")
    ap.add_argument("--no-tray", action="store_true", help="不启动托盘")
    ap.add_argument("--no-native", action="store_true", help="强制使用纯 Python 匹配后端")
    ap.add_argument("--min-literal", type=int, default=6,
                    help="字面量最小长度（默认 6：更短的串没有鉴别力，只会误报）")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--once", metavar="PATH", help="只扫描一次指定路径，不进监控模式")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.rules):
        print("规则目录不存在: %s" % args.rules)
        return 2

    print("御天实时防护（新版）")
    t0 = time.perf_counter()
    scanner = Scanner(args.rules, max_bytes=args.max_mb * 1024 * 1024,
                      prefer_native=not args.no_native,
                      min_literal_len=args.min_literal)
    load = time.perf_counter() - t0
    print("  规则: %d 条 / %d 文件, 加载 %.2f s" % (
        len(scanner.ruleset.rules), scanner.ruleset.files, load))
    print("  字面量: 保留 %d 个, 因 < %d 字节丢弃 %d 个" % (
        len(scanner.ruleset.cs_patterns) + len(scanner.ruleset.ci_patterns),
        args.min_literal, scanner.ruleset.dropped))
    print("  匹配后端: %s" % scanner.ruleset.backend())

    if args.once:
        return _scan_path(scanner, args.once)

    qdir = args.quarantine
    quarantine = Quarantine(qdir)
    probe = Probe(scanner, workers=args.workers, quarantine=quarantine,
                  quarantine_on_detect=args.quarantine_on_detect, verbose=args.verbose)

    def on_event(path, action):
        if action in ("added", "modified", "renamed"):
            probe.submit(path)

    dirs = [d for d in (args.dirs or DEFAULT_DIRS) if d and os.path.isdir(d)]
    if not dirs:
        print("没有可监控的目录（用 --dirs 指定）")
        return 2
    print("  监控目录:")
    for d in dirs:
        print("    - %s" % d)
    print("  自动隔离: %s" % ("开" if args.quarantine_on_detect else "关（仅告警）"))

    watcher = DirWatcher(on_event, dirs=dirs)
    probe.start()
    watcher.start()

    stop_ev = threading.Event()

    def _quit():
        stop_ev.set()

    tray = None
    if not args.no_tray:
        tray = TrayIcon("御天实时防护", "后台实时防护运行中", on_quit=_quit)
        if not tray.start():
            print("  托盘不可用: %s（继续无托盘运行）" % getattr(tray, "last_error", "?"))
            tray = None

    def _sig(_signum, _frame):
        stop_ev.set()

    try:
        signal.signal(signal.SIGINT, _sig)
        signal.signal(signal.SIGTERM, _sig)
    except Exception:
        pass

    try:
        while not stop_ev.is_set():
            stop_ev.wait(1.0)
    except KeyboardInterrupt:
        pass

    print("")
    print("正在停止…")
    watcher.stop()
    probe.stop()
    if tray is not None:
        tray.stop()
    scanner.close()
    print("统计: %s" % probe.counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
