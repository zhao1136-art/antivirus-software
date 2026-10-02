"""
御天实时防护（新版）

从零实现的后台实时防护：目录监控 + 快速扫描 + 隔离 + 托盘。

设计要点
--------
匹配引擎不再使用纯 Python 的 YARA 复刻（实测仅约 1 MB/s，
22.5 MB 文件耗时 141.8 秒）。改为：

  1. native/matcher.dll —— Aho-Corasick 完全 DFA（C 实现，gcc 编译），
     扫描开销只与数据长度有关、与模式数量无关；
  2. 无 DLL 时回退到 rtguard.matcher 的纯 Python 实现。

模块
----
    rtguard.watcher       ReadDirectoryChangesW 目录监控
    rtguard.matcher       多模式匹配（原生 / 纯 Python 双后端）
    rtguard.scanner       扫描编排（过滤 -> 哈希 -> 特征库 -> 匹配 -> 启发式）
    rtguard.quarantine    隔离区（异或混淆 + 原子索引）
    rtguard.tray          托盘图标与通知
"""

__all__ = ["watcher", "matcher", "scanner", "quarantine", "tray"]
__version__ = "1.0.0"
