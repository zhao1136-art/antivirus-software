"""self_guard.dll 的 ctypes 桥接层（自保护 / 防 kill）。

对应原生实现：engine/native_guard/self_guard.cpp
构建：        engine/native_guard/build.bat 里的 self_guard.dll 目标

为什么要有这一层
================
`engine/self_protect.py` 原来的 `_protect_process()` 只调用
`EnableDebugPrivilege()` —— **该权限完全不能防止进程被杀**，等于没有防护
（它自己的注释也承认只是"提升+标记方式记录状态"）。真正的实现放在
self_guard.cpp 里：替换进程对象的 DACL，不授予 PROCESS_TERMINATE。

⚠️ 能力边界（**必须如实对外表述，不要当成绝对防护**）
====================================================
实测（2026-10-06 本机管理员会话）：
    持有 SeDebugPrivilege      -> OpenProcess(PROCESS_TERMINATE) 成功，taskkill /F 成功
    移除 SeDebugPrivilege      -> err=5 ACCESS_DENIED，taskkill /F "Access is denied"，进程存活
即 **SeDebugPrivilege 会绕过进程 DACL**。所以本模块：
    ✅ 挡得住非提权的恶意进程 / 普通用户的 taskkill
    ❌ 挡不住任何提权进程
对抗提权攻击者需要内核驱动 ObRegisterCallbacks 在句柄层面剥离 PROCESS_TERMINATE
（本项目无 WDK，未实现）。
"""

import ctypes
import ctypes.wintypes as wt
import logging
import os
import sys
import threading

logger = logging.getLogger("self_guard")

DLL_NAME = "self_guard.dll"

# 返回码约定（与 self_guard.cpp 一致）
GUARD_OK = 0
GUARD_BAD_ARG = -1

_dll = None
_dll_error = ""
_lock = threading.Lock()


def dll_candidates():
    """按 开发目录 -> 冻结产物目录 的顺序查找 self_guard.dll。"""
    here = os.path.dirname(os.path.abspath(__file__))
    out = [os.path.join(here, "native_guard", DLL_NAME)]
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass:
            out.append(os.path.join(meipass, "engine", "native_guard", DLL_NAME))
    else:
        out.append(os.path.join(here, "native_guard", DLL_NAME))
    return out


def load():
    """加载 self_guard.dll（单例）。失败抛 RuntimeError。"""
    global _dll, _dll_error
    if _dll is not None:
        return _dll
    with _lock:
        if _dll is not None:
            return _dll
        last = ""
        for path in dll_candidates():
            if not os.path.isfile(path):
                continue
            try:
                d = ctypes.CDLL(path)
                d.YutianProtectProcess.argtypes = [wt.DWORD, ctypes.c_int]
                d.YutianProtectProcess.restype = ctypes.c_int
                d.YutianUnprotectProcess.argtypes = [wt.DWORD]
                d.YutianUnprotectProcess.restype = ctypes.c_int
                d.YutianIsProcessProtected.argtypes = [wt.DWORD]
                d.YutianIsProcessProtected.restype = ctypes.c_int
                d.YutianSelfGuardVersion.restype = ctypes.c_char_p
            except OSError as e:
                last = f"{path}: {e}"
                continue
            d.SELF_GUARD_PATH = path
            _dll = d
            return _dll
        _dll_error = last or f"未找到 {DLL_NAME}（请先运行 engine/native_guard/build.bat）"
        raise RuntimeError(_dll_error)


def available() -> bool:
    try:
        load()
        return True
    except Exception:
        return False


def version() -> str:
    try:
        d = load()
        return (d.YutianSelfGuardVersion() or b"").decode("utf-8", "replace")
    except Exception as e:
        return f"不可用: {e}"


def protect_process(pid: int = 0, protect_from_admins: bool = True) -> int:
    """给进程加 DACL 保护（默认连管理员也不授予 PROCESS_TERMINATE）。

    :return: 0 成功；非 0 为 Win32 错误码；-1 参数错误。DLL 缺失时抛 RuntimeError。
    """
    d = load()
    if not pid:
        pid = os.getpid()
    return int(d.YutianProtectProcess(wt.DWORD(pid), 1 if protect_from_admins else 0))


def unprotect_process(pid: int = 0) -> int:
    """解除保护（逃生通道）。提权用户即使 DACL 拒绝也能调用，因为
    SeDebugPrivilege 会绕过 DACL。"""
    d = load()
    if not pid:
        pid = os.getpid()
    return int(d.YutianUnprotectProcess(wt.DWORD(pid)))


def is_protected(pid: int = 0) -> int:
    """1=当前调用方能取得 PROCESS_TERMINATE（未受保护）；0=被拒（受保护）；
    负值=其它错误。"""
    d = load()
    if not pid:
        pid = os.getpid()
    return int(d.YutianIsProcessProtected(wt.DWORD(pid)))


def status(pid: int = 0) -> dict:
    """给上层/UI 用的状态快照。"""
    if not pid:
        pid = os.getpid()
    try:
        d = load()
    except Exception as e:
        return {"available": False, "error": str(e), "pid": pid}
    try:
        return {
            "available": True,
            "pid": pid,
            "dll": getattr(d, "SELF_GUARD_PATH", ""),
            "version": version(),
            "terminate_denied": is_protected(pid) == 0,
            # 如实标注能力边界
            "limits": "用户态 DACL；提权进程(持有 SeDebugPrivilege)可绕过，"
                      "需内核驱动 ObRegisterCallbacks 才能真正对抗",
        }
    except Exception as e:
        return {"available": True, "error": str(e), "pid": pid}
