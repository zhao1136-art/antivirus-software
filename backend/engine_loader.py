"""
御天 引擎后台并行加载模块
在 Logo 动画播放期间，异步线程同步加载全套引擎资源

加载顺序：
1. 持久化配置、守护天数数据
2. 扫描管线、YARA 规则索引、LRU 扫描缓存
3. native_guard.dll + ctypes 桥接初始化
4. 自适应线程池、性能统计模块、DEX 解析器
"""
import os
import sys
import time
import threading


def load_engine_resources(status_callback=None, done_callback=None):
    """
    后台线程入口：加载全套引擎资源
    status_callback(msg) 用于更新 Logo 窗口状态文字
    """
    def _report(msg):
        if status_callback:
            status_callback(msg)
        print(f"[EngineLoader] {msg}")

    start = time.time()

    # ── 1. 持久化配置 & 守护天数 ───────────────────────
    _report("正在加载持久化配置...")
    try:
        from persistence import load_config_save, load_guard_days, update_guard_days
        _cfg = load_config_save()
        _guard = update_guard_days()
        _report(f"已守护 {_guard.get('accumulated_days', 0)} 天")
    except Exception as e:
        _report(f"持久化配置加载完成（部分: {e})")

    # ── 2. 扫描管线 & YARA 规则索引 ────────────────────
    _report("正在初始化扫描引擎...")
    try:
        from engine.scheduler import Scheduler
        _scheduler = Scheduler()
        yara_total = len(_scheduler.yara.rules) if _scheduler.yara else 0
        _report(f"YARA 规则索引完成: {yara_total} 条规则")
    except Exception as e:
        _report(f"扫描引擎初始化完成（部分: {e})")

    # ── 3. LRU 扫描缓存 ────────────────────────────────
    _report("正在初始化扫描缓存...")
    try:
        from persistence import cache_stats, cache_cleanup
        cache_cleanup()
        stats = cache_stats()
        _report(f"扫描缓存就绪: {stats.get('valid_entries', 0)} 条有效条目")
    except Exception as e:
        _report(f"扫描缓存初始化完成（部分: {e})")

    # ── 4. native_guard.dll + ctypes 桥接 ──────────────
    _report("正在加载原生防护引擎...")
    try:
        from engine.native_guard_bridge import get_native_guard
        guard = get_native_guard()
        if guard and guard.available:
            ver = guard.version()
            _report(f"原生防护引擎已加载: {ver.get('version', 'unknown')}")
        else:
            _report("原生防护引擎 DLL 未找到，使用 Python 回退方案")
    except Exception as e:
        _report(f"原生防护引擎加载完成（回退: {e})")

    # ── 5. 自适应线程池 & 性能统计 ─────────────────────
    _report("正在初始化线程池与性能统计...")
    try:
        from config import MAX_WORKERS
        _report(f"自适应线程池: {MAX_WORKERS} 个工作线程")
    except Exception as e:
        _report(f"线程池配置加载完成（部分: {e})")
    try:
        from engine.perf import reset as perf_reset
        perf_reset()
        _report("性能统计模块已就绪")
    except Exception as e:
        _report(f"性能统计模块初始化完成（部分: {e})")

    # ── 6. DEX 解析器 ──────────────────────────────────
    _report("正在初始化 DEX 解析器...")
    try:
        from engine.dex_parser import scan_dex
        _report("DEX 解析器已就绪")
    except Exception as e:
        _report(f"DEX 解析器初始化完成（部分: {e})")

    elapsed = time.time() - start
    _report(f"所有引擎资源加载完成（耗时 {elapsed:.1f}s）")

    # 通知调用方引擎加载完成
    if done_callback:
        try:
            done_callback()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════
#  退出时资源释放
# ══════════════════════════════════════════════════════════════

def release_engine_resources():
    """
    退出时释放引擎资源：
    - 清理扫描缓存
    - 保存配置 & 守护天数
    - 释放 DLL 引用（让 GC 处理）
    """
    print("[EngineLoader] 正在释放引擎资源...")
    try:
        from persistence import cache_cleanup, save_config_save, save_guard_days, load_guard_days
        cache_cleanup()
        # 配置和天数由 app.py 的 atexit 钩子负责保存，此处仅清理缓存
        print("[EngineLoader] 扫描缓存已清理")
    except Exception as e:
        print(f"[EngineLoader] 资源释放（部分: {e})")
    print("[EngineLoader] 引擎资源已释放")