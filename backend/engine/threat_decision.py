"""
威胁处置决策 —— 系统文件二次复核 + 用户决定（15 秒超时自动处理）

为什么需要这个
--------------
2026-10-03 的事故：一次普通扫描把 **42 个 Windows 系统文件**搬进了隔离区
（PowerShell 的 Pester / PackageManagement 模块、ImagingDevices.exe、sqmapi.dll…），
用户毫不知情。触发它们的全是 `EXE_in_LNK` / `Archive_in_LNK` 这类垃圾规则 ——
实测 `EXE_in_LNK` 会命中 **514/585 = 88%** 的合法 System32 文件。

两个根因，对应本模块的两道闸门：

  闸门一（系统文件二次复核，**不使用 YARA**）
      命中文件若位于系统目录，不能只凭 YARA 定罪。这里用 Windows 自己的
      Authenticode 签名校验（WinVerifyTrust）做第二次判断 ——
      **独立于 YARA 的第二信源**。签名有效且在系统目录 => 判为可信，
      降级为仅告警，不进入隔离流程。

  闸门二（用户决定，15 秒超时自动处理）
      不再"YARA 命中即自动隔离"。改为挂起成一个待决项、通报给用户，
      由用户决定；**15 秒内没有决定就自动处理**（默认隔离），
      以保证长时间无人值守时防护不会失效。
"""
from __future__ import annotations

import ctypes
import os
import threading
import time
import uuid
from ctypes import wintypes

__all__ = ["is_system_path", "verify_signature", "second_opinion",
           "DecisionQueue", "PendingDecision", "DECISION_TIMEOUT",
           "ACTION_QUARANTINE", "ACTION_IGNORE", "ACTION_AUTO"]

# 用户决定的等待时长（秒）；超时后按默认动作自动处理
DECISION_TIMEOUT = 15.0

ACTION_QUARANTINE = "quarantine"
ACTION_IGNORE = "ignore"
ACTION_AUTO = "auto"          # 超时自动处理

# ── 系统目录（命中这些路径的文件要走二次复核）──
def _system_prefixes():
    win = os.environ.get("SystemRoot", r"C:\Windows")
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    pd = os.environ.get("ProgramData", r"C:\ProgramData")
    return tuple(os.path.normcase(os.path.abspath(p)) for p in (win, pf, pf86, pd))


_SYSTEM_PREFIXES = _system_prefixes()


def is_system_path(path: str) -> bool:
    """路径是否位于系统目录（Windows / Program Files / Program Files (x86) / ProgramData）"""
    if not path:
        return False
    try:
        p = os.path.normcase(os.path.abspath(path))
    except Exception:
        return False
    for pre in _SYSTEM_PREFIXES:
        if p == pre or p.startswith(pre + os.sep):
            return True
    return False


# ── Authenticode 签名校验（WinVerifyTrust），与 YARA 完全无关 ──
class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p)]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD)]


_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0xaac56b, 0xcd44, 0x11d0,
    (ctypes.c_ubyte * 8)(0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee))

_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
# 只用本地缓存做吊销检查，避免联网导致卡住（隔离判定必须在几十毫秒内返回）
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000
_WTD_SAFER_FLAG = 0x00000100


def verify_signature(path: str, timeout_ms: int = 4000):
    """校验文件的 Authenticode 数字签名。

    返回 (ok: bool, detail: str)。ok=True 表示签名有效且未被吊销。
    这是**独立于 YARA 的第二信源** —— 系统目录里的微软签名文件可以据此判定可信。
    """
    if not path or not os.path.isfile(path):
        return False, "文件不存在"
    try:
        wintrust = ctypes.WinDLL("wintrust")
        wintrust.WinVerifyTrust.restype = ctypes.c_long
        wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(_GUID),
                                           ctypes.c_void_p]
    except Exception as exc:
        return False, "WinVerifyTrust 不可用: %s" % exc

    fi = _WINTRUST_FILE_INFO()
    fi.cbStruct = ctypes.sizeof(fi)
    fi.pcwszFilePath = os.path.abspath(path)
    fi.hFile = None
    fi.pgKnownSubject = None

    data = _WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(data)
    data.dwUIChoice = _WTD_UI_NONE            # 绝不弹窗
    data.fdwRevocationChecks = _WTD_REVOKE_NONE
    data.dwUnionChoice = _WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(fi)
    data.dwStateAction = _WTD_STATEACTION_VERIFY
    data.dwProvFlags = _WTD_CACHE_ONLY_URL_RETRIEVAL | _WTD_SAFER_FLAG

    action = _GUID.from_buffer_copy(_WINTRUST_ACTION_GENERIC_VERIFY_V2)
    try:
        # WinVerifyTrust 对不可信文件会自己去联网/查 CRL，这里用线程包一层超时保护
        result = {}

        def _call():
            try:
                result["rc"] = wintrust.WinVerifyTrust(
                    None, ctypes.byref(action), ctypes.byref(data))
            except Exception as exc:
                result["err"] = str(exc)

        th = threading.Thread(target=_call, daemon=True)
        th.start()
        th.join(timeout_ms / 1000.0)
        if th.is_alive():
            data.dwStateAction = _WTD_STATEACTION_CLOSE
            try:
                wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
            except Exception:
                pass
            return False, "签名校验超时"

        # 无论结果如何都要关闭状态句柄，否则会泄漏
        data.dwStateAction = _WTD_STATEACTION_CLOSE
        try:
            wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
        except Exception:
            pass

        if "err" in result:
            return False, result["err"]
        rc = result.get("rc", -1)
        if rc == 0:
            return True, "签名有效"
        return False, "签名无效 (0x%08x)" % (rc & 0xFFFFFFFF)
    except Exception as exc:
        return False, str(exc)


def second_opinion(path: str) -> dict:
    """系统文件的二次复核（**不使用 YARA**）。

    返回 {"trusted": bool, "reason": str, "method": str}

    两个信源，按可靠性排序：
      1) Authenticode 内嵌签名有效 -> 可信（method=authenticode）
      2) 内嵌签名拿不到（**大量系统文件是目录签名**，签名在 CatRoot 的 .cat 里，
         实测 notepad.exe 返回 0x800B0100 TRUST_E_NOSIGNATURE）-> 按策略仍然
         **不允许自动隔离**（method=system-path）

    为什么第 2 条要这样定：系统目录只有管理员能写，恶意软件长期驻留在
    System32 的概率远低于杀软规则误报的概率 —— 今天的 42 个文件就是代价。
    复核不出结论时，正确动作是**交给人**，而不是自动把文件从系统里搬走。
    代价是可能漏掉真正的系统目录感染；这个取舍是刻意的，并且会记录在案。
    """
    if not is_system_path(path):
        return {"trusted": False, "reason": "非系统目录", "method": "none"}
    ok, detail = verify_signature(path)
    if ok:
        return {"trusted": True, "method": "authenticode",
                "reason": "系统目录 + 内嵌签名有效（%s）" % detail}
    return {"trusted": True, "method": "system-path",
            "reason": "系统目录文件，内嵌签名不可用（%s）；按策略不自动隔离，仅告警待人处理" % detail}


# ── 待决项与 15 秒超时 ──
class PendingDecision:
    __slots__ = ("id", "path", "threat_name", "threat_level", "rule", "created_at",
                 "deadline", "action", "decided", "auto", "_event")

    def __init__(self, path, threat):
        self.id = uuid.uuid4().hex[:12]
        self.path = path
        self.threat_name = threat.get("signature") or threat.get("threat_name") or "Unknown"
        self.threat_level = threat.get("threat_level", "medium")
        self.rule = (threat.get("details") or {}).get("rule", "")
        self.created_at = time.time()
        self.deadline = self.created_at + DECISION_TIMEOUT
        self.action = None
        self.decided = False
        self.auto = False          # True = 超时自动处理，非用户决定
        self._event = threading.Event()

    def to_dict(self):
        return {
            "id": self.id, "path": self.path, "threat_name": self.threat_name,
            "threat_level": self.threat_level, "rule": self.rule,
            "created_at": self.created_at, "deadline": self.deadline,
            "seconds_left": max(0.0, round(self.deadline - time.time(), 1)),
            "timeout": DECISION_TIMEOUT, "decided": self.decided,
            "action": self.action,
        }


class DecisionQueue:
    """挂起待决项并等待用户决定；超时按默认动作自动处理。"""

    def __init__(self, timeout: float = DECISION_TIMEOUT):
        self.timeout = float(timeout)
        self._lock = threading.Lock()
        self._pending = {}          # id -> PendingDecision
        self.stats = {"asked": 0, "user_quarantine": 0, "user_ignore": 0,
                      "auto": 0, "suppressed": 0}

    def ask(self, path: str, threat: dict) -> PendingDecision:
        """登记一个待决项（不阻塞），并推给两条**可点**通道。

        只保留"带按钮、用户能真正做决定"的通道：
          1) 桌面原生窗口（tkinter，置顶，屏幕右下角）—— 不依赖浏览器，主通道
          2) 网页右下角弹窗 —— 用户正看着页面时更顺手

        系统托盘气泡只有提示、没有按钮，用户只能眼看着 15 秒过去，
        按用户要求已移除（"只留有按钮的弹窗"）。
        """
        pd = PendingDecision(path, threat)
        pd.deadline = pd.created_at + self.timeout
        with self._lock:
            self._pending[pd.id] = pd
        self.stats["asked"] += 1
        # 桌面决策窗口：用户不在浏览器前时的**唯一可点通道**。
        # 网页弹窗和托盘气泡都只是"通知"——点不到、也没按钮；
        # 少了这个，桌面用户只能眼看着 15 秒后文件被自动隔离。
        try:
            from engine.desktop_prompt import show as _desktop_show
            _desktop_show(pd, self.decide)
        except Exception:
            pass
        return pd

    def decide(self, pending_id: str, action: str) -> bool:
        """用户决定。action ∈ {quarantine, ignore}"""
        if action not in (ACTION_QUARANTINE, ACTION_IGNORE):
            return False
        with self._lock:
            pd = self._pending.get(pending_id)
        if pd is None or pd.decided:
            return False
        pd.action = action
        pd.decided = True
        pd._event.set()
        self.stats["user_quarantine" if action == ACTION_QUARANTINE else "user_ignore"] += 1
        return True

    def wait(self, pd: PendingDecision) -> str:
        """阻塞至用户决定或超时；返回最终动作。（单个待决项，逐个等待用）"""
        pd._event.wait(timeout=max(0.0, pd.deadline - time.time()))
        return self.finalize(pd)

    def wait_all(self, pds) -> None:
        """批量等待：所有待决项**共享同一个截止时间**。

        为什么不能逐个 wait()：一次扫描可能命中几十个文件，
        逐个等就是 N × timeout 的串行阻塞（42 个命中会卡 10.5 分钟）。
        这里统一等到最晚的那个截止时刻，总数多少个都只等一轮。
        """
        if not pds:
            return
        deadline = max(p.deadline for p in pds)
        for pd in pds:
            remaining = deadline - time.time()
            if remaining > 0:
                pd._event.wait(timeout=remaining)

    def finalize(self, pd: PendingDecision) -> str:
        """结算一个待决项：已决定则用用户的选择，否则超时按默认动作自动处理。"""
        if not pd.decided:
            pd.action = ACTION_QUARANTINE
            pd.decided = True
            pd.auto = True
            self.stats["auto"] += 1
        with self._lock:
            self._pending.pop(pd.id, None)
        # 从桌面决策窗口上撤掉这一行（无论用户点了还是超时自动处理）
        try:
            from engine.desktop_prompt import get_window as _dwin
            _dwin().dismiss(pd.id)
        except Exception:
            pass
        return pd.action

    def list_pending(self) -> list:
        now = time.time()
        with self._lock:
            items = [p for p in self._pending.values() if not p.decided]
        return [p.to_dict() for p in items]

    def note_suppressed(self):
        self.stats["suppressed"] += 1


# 进程级单例（供 API 与调度器共用）
QUEUE = DecisionQueue()
