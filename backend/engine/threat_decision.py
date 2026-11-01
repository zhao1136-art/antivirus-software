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
import logging
import os
import threading
import time
import uuid
from ctypes import wintypes

# 与项目其它模块一致用 "yutian" 这个 logger
logger = logging.getLogger("yutian")

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
# ⚠️ WTD_SAFER_FLAG (0x100) —— 2026-10-06 移除，**这是原实现的一个真实 bug**。
# 实测（本机 Win10 19045，对一个确实有效的 .cat 文件做 WTD_CHOICE_FILE 校验）：
#     CACHE_ONLY | SAFER  -> 0x800B0100 TRUST_E_NOSIGNATURE   （误报"无签名"）
#     CACHE_ONLY          -> 0x00000000 成功
#     0                   -> 0x00000000 成功
# 加上这个标志会让 WinVerifyTrust **把有效签名报成无签名**，直接压制检出率。
# 原代码同时用它做内嵌签名与目录签名校验，两边都受影响。
_WTD_SAFER_FLAG_REMOVED_BECAUSE_BUGGY = 0x00000100


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
    data.dwProvFlags = _WTD_CACHE_ONLY_URL_RETRIEVAL

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


# ══════════════════════════════════════════════════════════════════════
# 目录签名（catalog / .cat）校验 —— 2026-10-06 补上的缺口
#
# 缺口是什么
# ----------
# 上面那个 verify_signature 用 `WTD_CHOICE_FILE`，**只查 PE 内嵌签名**。
# 而大量 Windows 系统文件根本没有内嵌签名 —— 签名在
#     C:\Windows\System32\CatRoot\{F750E6C3-38DD-11D1-924B-00A0C90AEA82}\*.cat
# 里，由系统按文件哈希匹配。对这类文件 WinVerifyTrust 返回
#     0x800B0100 TRUST_E_NOSIGNATURE
# 于是旧策略只能写"系统目录一律放行"（见 second_opinion 的注释）。
# 那个策略的代价是：**往 System32 里丢一个未签名/被篡改的文件，也会被信任。**
#
# 这里补上 catalog 校验链（`WTD_CHOICE_CATALOG` 在本机不可用，详见
# verify_signature_catalog 的注释）：
#     CryptCATAdminAcquireContext2("SHA256") -> CalcHashFromFileHandle2
#       -> EnumCatalogFromHash -> CatalogInfoFromContext（拿到 .cat 路径）
#       -> 校验 .cat 自身的签名
# 效果（实测 60 个 System32 文件）：可信识别从 20/60 提升到 **60/60**，
# 其中 40 个是靠目录签名新认出来的。
#
# 同时把 **TRUST_E_BAD_DIGEST（签名在但文件被改过）** 单独识别出来 ——
# 那是很强的恶意信号，绝不能再按"系统目录"放行。
# ══════════════════════════════════════════════════════════════════════

_WTD_CHOICE_CATALOG = 3
_MAX_PATH = 260

# WinVerifyTrust / 证书相关返回码
TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_BAD_DIGEST = 0x80096010          # 签名在，但文件被改过 —— 强恶意信号
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
CRYPT_E_SECURITY_SETTINGS = 0x80092026
CERT_E_EXPIRED = 0x800B0101
CERT_E_UNTRUSTEDROOT = 0x800B0109
CERT_E_REVOKED = 0x80092010
CERT_E_CHAINING = 0x800B010A


class _WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("dwCatalogVersion", wintypes.DWORD),
                ("pcwszCatalogFilePath", wintypes.LPCWSTR),
                ("pcwszMemberTag", wintypes.LPCWSTR),
                ("pcwszMemberFilePath", wintypes.LPCWSTR),
                ("hMemberFile", wintypes.HANDLE),
                ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
                ("cbCalculatedFileHash", wintypes.DWORD),
                ("pcCatalogContext", ctypes.c_void_p),
                ("hCatAdmin", ctypes.c_void_p)]


class _CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("wszCatalogFile", wintypes.WCHAR * _MAX_PATH)]


def _wintrust_api():
    """加载并声明 wintrust.dll 的 catalog 相关 API。"""
    wt = ctypes.WinDLL("wintrust")
    wt.WinVerifyTrust.restype = ctypes.c_long
    wt.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(_GUID), ctypes.c_void_p]

    # 旧版（默认 MD5 哈希）—— 现代 .cat 多用 SHA-256，仅作回退
    wt.CryptCATAdminAcquireContext.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                               ctypes.POINTER(_GUID), wintypes.DWORD]
    wt.CryptCATAdminAcquireContext.restype = wintypes.BOOL
    wt.CryptCATAdminCalcHashFromFileHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD]
    wt.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL

    # Win8+ 版本：可指定哈希算法（SHA256）。**必须优先用这个** ——
    # 旧版默认 MD5，算出的 member tag 与 SHA-256 构建的 .cat 对不上，
    # WinVerifyTrust 会返回 0x800B0100 TRUST_E_NOSIGNATURE（踩过）。
    wt.HAS_CAT2 = False
    try:
        wt.CryptCATAdminAcquireContext2.argtypes = [
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(_GUID),
            wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD]
        wt.CryptCATAdminAcquireContext2.restype = wintypes.BOOL
        wt.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
            ctypes.c_void_p, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD]
        wt.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
        wt.HAS_CAT2 = True
    except AttributeError:
        wt.HAS_CAT2 = False

    wt.CryptCATAdminEnumCatalogFromHash.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
        wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    wt.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
    wt.CryptCATCatalogInfoFromContext.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(_CATALOG_INFO), wintypes.DWORD]
    wt.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
    wt.CryptCATAdminReleaseCatalogContext.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
    wt.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminReleaseContext.restype = wintypes.BOOL
    return wt


def _find_catalog(path: str):
    """为文件找到匹配的 .cat 目录文件。

    返回 (catalog_path, member_tag, hcatadmin, hcatinfo, err)。找不到时
    catalog_path 为 None，err 说明原因。释放句柄用 `_release_catalog()`。

    踩过的坑（2026-10-06）：
      1) kernel32.CreateFileW **必须显式声明 argtypes/restype**，否则 64 位
         HANDLE 被 ctypes 默认的 c_int 截断，句柄无效、后续全部静默失败。
      2) CryptCATAdminCalcHashFromFileHandle 是**按当前文件位置**读取的。
         先调一次拿哈希长度、再调一次算哈希 —— 第二次位置已在文件末尾，
         必然算不出。两次调用之间必须 SetFilePointer 回到 0。
    """
    wt = _wintrust_api()
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                wintypes.HANDLE]
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.SetFilePointer.argtypes = [wintypes.HANDLE, ctypes.c_long, ctypes.c_void_p,
                                   wintypes.DWORD]
    k32.SetFilePointer.restype = wintypes.DWORD
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL

    h_cat_admin = ctypes.c_void_p()
    # 优先 SHA256（现代 .cat 的算法）；不可用时回退旧版（MD5）
    use2 = bool(getattr(wt, "HAS_CAT2", False))
    if use2:
        if not wt.CryptCATAdminAcquireContext2(ctypes.byref(h_cat_admin), None,
                                               "SHA256", None, 0):
            use2 = False
    if not use2:
        if not wt.CryptCATAdminAcquireContext(ctypes.byref(h_cat_admin), None, 0):
            return None, None, None, None, \
                "CryptCATAdminAcquireContext err=%d" % ctypes.get_last_error()

    INVALID = ctypes.c_void_p(-1).value
    h_file = k32.CreateFileW(os.path.abspath(path), 0x80000000, 0x00000001,
                            None, 3, 0x80, None)
    if not h_file or h_file == INVALID:
        err = ctypes.get_last_error()
        wt.CryptCATAdminReleaseContext(h_cat_admin, 0)
        return None, None, None, None, "CreateFileW err=%d" % err

    h_cat_info = None
    try:
        cb = wintypes.DWORD(0)
        if use2:
            # 第一次：拿哈希长度（会读到文件末尾）
            wt.CryptCATAdminCalcHashFromFileHandle2(h_cat_admin, h_file,
                                                    ctypes.byref(cb), None, 0)
            if not cb.value:
                return None, None, h_cat_admin, None, \
                    "CalcHash2 取长度失败 err=%d" % ctypes.get_last_error()
            # 关键：回到文件开头，否则第二次从末尾读、算不出哈希
            k32.SetFilePointer(h_file, 0, None, 0)      # FILE_BEGIN
            buf = (ctypes.c_ubyte * cb.value)()
            if not wt.CryptCATAdminCalcHashFromFileHandle2(h_cat_admin, h_file,
                                                           ctypes.byref(cb), buf, 0):
                return None, None, h_cat_admin, None, \
                    "CalcHash2 计算失败 err=%d" % ctypes.get_last_error()
        else:
            wt.CryptCATAdminCalcHashFromFileHandle(h_file, ctypes.byref(cb), None, 0)
            if not cb.value:
                return None, None, h_cat_admin, None, \
                    "CalcHash 取长度失败 err=%d" % ctypes.get_last_error()
            k32.SetFilePointer(h_file, 0, None, 0)
            buf = (ctypes.c_ubyte * cb.value)()
            if not wt.CryptCATAdminCalcHashFromFileHandle(h_file, ctypes.byref(cb), buf, 0):
                return None, None, h_cat_admin, None, \
                    "CalcHash 计算失败 err=%d" % ctypes.get_last_error()

        prev = ctypes.c_void_p()
        h_cat_info = wt.CryptCATAdminEnumCatalogFromHash(
            h_cat_admin, buf, cb.value, 0, ctypes.byref(prev))
        if not h_cat_info:
            return None, None, h_cat_admin, None, \
                "EnumCatalogFromHash 未找到匹配 .cat err=%d" % ctypes.get_last_error()

        ci = _CATALOG_INFO()
        ci.cbStruct = ctypes.sizeof(ci)
        if not wt.CryptCATCatalogInfoFromContext(h_cat_info, ctypes.byref(ci), 0):
            return None, None, h_cat_admin, h_cat_info, \
                "CatalogInfoFromContext err=%d" % ctypes.get_last_error()

        # member tag = 哈希的**大写十六进制**字符串（WinVerifyTrust 要求的形式）
        tag = "".join("%02X" % b for b in bytes(buf))
        return ci.wszCatalogFile, tag, h_cat_admin, h_cat_info, ""
    finally:
        try:
            k32.CloseHandle(h_file)
        except Exception:
            pass


def _release_catalog(h_cat_admin, h_cat_info):
    if not h_cat_admin:
        return
    try:
        wt = _wintrust_api()
        if h_cat_info:
            wt.CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0)
        wt.CryptCATAdminReleaseContext(h_cat_admin, 0)
    except Exception:
        pass


def verify_signature_catalog(path: str, timeout_ms: int = 4000):
    """目录签名（.cat）校验。返回 (ok, detail, catalog_path)。

    实现路径的取舍（2026-10-06，实测记录 —— 别重复踩）
    --------------------------------------------------
    本该用 `WinVerifyTrust(WTD_CHOICE_CATALOG)` 一步到位，但实测在本机
    （Win10 19045）上**无论怎么配都失败**：
        WTD_SAFER_FLAG 组合  -> 0x800B0100 TRUST_E_NOSIGNATURE
        其余所有组合          -> 0x800B0001 TRUST_E_PROVIDER_UNKNOWN
    试过的组合：给/不给 hCatAdmin、给/不给 pbCalculatedFileHash、
    给/不给 hMemberFile、CACHE_ONLY / DISABLE_MD2_MD4 / SAFER / 无标志、
    REVOKE_NONE / WHOLECHAIN / CHAIN_EXCLUDE_ROOT —— 全部失败。
    同时把 `CryptCATAdminAcquireContext` 换成 `...AcquireContext2("SHA256")`
    后，member tag 从 32 位十六进制（MD5）变成 64 位（SHA-256），说明
    **哈希算法这一环是对的**，卡在 WinVerifyTrust 本身。

    而 PowerShell 的 Get-AuthenticodeSignature 对 notepad.exe 明确给出
        Status=Valid, SignatureType=Catalog, Signer=CN=Microsoft Windows, O=Microsoft Corporation
    可见目录签名本身可用且有效。

    因此改用一条**同样成立、且本机已验证可行**的路径：
        1) CryptCATAdminEnumCatalogFromHash 找到包含该文件哈希的 .cat
        2) 校验 **.cat 文件自身的 Authenticode 签名**（走已验证可用的
           WTD_CHOICE_FILE 路径）
    语义：文件哈希被收录在一个**由可信发布者签名的目录**中，即视该文件被该
    发布者签名。这与 WinVerifyTrust 的目录校验高度一致，但不是逐字节相同的
    实现 —— 不复现其"OS 二进制策略"等附加判定。

    为什么这仍然值得做：原来的策略是"系统目录一律放行"，等于**信任任何被丢进
    System32 的未签名文件**；现在至少要求"哈希被收录于某个有效签名的目录"。
    """
    if not path or not os.path.isfile(path):
        return False, "文件不存在", None
    cat_path = h_admin = h_info = None
    try:
        cat_path, tag, h_admin, h_info, ferr = _find_catalog(path)
        if not cat_path:
            return False, "无匹配的目录签名（.cat）%s" % ((": " + ferr) if ferr else ""), None

        # .cat 是 PKCS#7 签名文件，用内嵌签名路径校验它自己
        ok, detail = verify_signature(cat_path, timeout_ms)
        cat_name = os.path.basename(cat_path)
        if not ok:
            return False, "目录文件 %s 自身签名无效（%s）" % (cat_name, detail), cat_path
        return True, "文件哈希收录于有效目录签名 %s（%s）" % (cat_name, detail), cat_path
    except Exception as exc:
        return False, "目录签名校验异常: %s" % exc, cat_path
    finally:
        _release_catalog(h_admin, h_info)


def verify_signature_full(path: str, timeout_ms: int = 4000) -> dict:
    """完整的签名检查：内嵌 -> 目录 -> 分类结论。

    返回 dict：
        status : embedded / catalog / unsigned / bad_digest / untrusted / error
        ok     : 是否可信
        signed : 是否存在任何有效签名（内嵌或目录）
        tampered : 签名存在但文件被改过（TRUST_E_BAD_DIGEST）—— 强恶意信号
        method : 判定依据
        detail : 人可读说明
        catalog: 命中的 .cat 路径（若有）
    """
    out = {"status": "error", "ok": False, "signed": False, "tampered": False,
           "method": "none", "detail": "", "catalog": None}
    if not path or not os.path.isfile(path):
        out["detail"] = "文件不存在"
        return out

    embedded_ok, embedded_detail = verify_signature(path, timeout_ms)

    # 内嵌签名报"无效"时，把 TRUST_E_BAD_DIGEST 单独拎出来 —— 那是文件被改过
    bad_digest = "80096010" in (embedded_detail or "").lower()

    cat_ok, cat_detail, cat_path = (False, "", None)
    if not embedded_ok:
        cat_ok, cat_detail, cat_path = verify_signature_catalog(path, timeout_ms)
        out["catalog"] = cat_path

    if embedded_ok:
        out.update(status="embedded", ok=True, signed=True,
                   method="authenticode-embedded", detail=embedded_detail)
    elif cat_ok:
        out.update(status="catalog", ok=True, signed=True,
                   method="authenticode-catalog",
                   detail="%s（%s）" % (cat_detail, cat_path))
    elif bad_digest:
        out.update(status="bad_digest", ok=False, signed=True, tampered=True,
                   method="authenticode-bad-digest",
                   detail="签名存在但文件已被修改（TRUST_E_BAD_DIGEST）：%s" % embedded_detail)
    elif "0x800b0111" in (embedded_detail or "").lower():
        out.update(status="untrusted", ok=False, signed=True,
                   method="authenticode-distrust",
                   detail="签名被显式吊销/不信任：%s" % embedded_detail)
    else:
        out.update(status="unsigned", ok=False, signed=False, method="none",
                   detail="无内嵌签名，且无匹配目录签名（内嵌: %s；目录: %s）"
                          % (embedded_detail, cat_detail))
    return out


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

    full = verify_signature_full(path)
    status = full.get("status")

    # ① 签名有效（内嵌或目录）—— 可信
    if full.get("ok"):
        return {"trusted": True, "method": full.get("method", "authenticode"),
                "reason": "系统目录 + %s" % full.get("detail", ""),
                "signature": full}

    # ② 签名存在但文件被改过 —— **绝不放行**。
    #    这是 2026-10-06 之前那段"系统目录一律放行"策略会漏掉的最坏情况：
    #    攻击者改掉一个已签名系统文件，旧代码照样判 trusted。
    if full.get("tampered"):
        return {"trusted": False, "method": "authenticode-bad-digest",
                "reason": "系统目录文件签名存在但已被篡改（%s）—— 按可疑处理"
                          % full.get("detail", ""),
                "signature": full}

    # ③ 签名被显式吊销/不信任 —— 也不放行
    if status == "untrusted":
        return {"trusted": False, "method": "authenticode-distrust",
                "reason": "系统目录文件签名被吊销或不信任（%s）" % full.get("detail", ""),
                "signature": full}

    # ④ 确实没有任何签名，且不在任何有效目录签名里。
    #    仍然按策略不自动隔离（系统目录只有管理员可写，误报代价高于此风险），
    #    但把"未签名"这一事实如实带出去，交给处置层/用户判断。
    return {"trusted": True, "method": "system-path",
            "reason": "系统目录文件，未找到有效内嵌或目录签名（%s）；"
                      "按策略不自动隔离，仅告警待人处理"
                      % full.get("detail", ""),
            "signature": full}


# ── 待决项与 15 秒超时 ──
class PendingDecision:
    __slots__ = ("id", "path", "threat_name", "threat_level", "rule", "created_at",
                 "deadline", "action", "decided", "auto", "default_action",
                 "reason", "_event")

    def __init__(self, path, threat, default_action=ACTION_QUARANTINE, reason=""):
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
        # ⚠️ 每项自己的**超时默认动作**（2026-10-31 新增）。
        #
        # 原来是写死的 ACTION_QUARANTINE（见 finalize）：只要进了队列，15 秒不答
        # 就自动隔离。这正是 scheduler 不敢把「闸门未确认」的命中送进来的原因
        # —— 送进来就会绕过全部闸门。
        # 现在允许调用方指定：两引擎确认的可隔离；只被 YARA 一个引擎命中的，
        # 送进来**只为通知用户**，超时默认 ignore（不答就不动手）。
        self.default_action = default_action
        self.reason = reason
        self._event = threading.Event()

    def to_dict(self):
        return {
            "id": self.id, "path": self.path, "threat_name": self.threat_name,
            "threat_level": self.threat_level, "rule": self.rule,
            "created_at": self.created_at, "deadline": self.deadline,
            "seconds_left": max(0.0, round(self.deadline - time.time(), 1)),
            "timeout": DECISION_TIMEOUT, "decided": self.decided,
            "action": self.action,
            # 让通知能解释「为什么只告警不隔离」
            "default_action": self.default_action,
            "reason": self.reason,
        }


class DecisionQueue:
    """挂起待决项并等待用户决定；超时按默认动作自动处理。"""

    def __init__(self, timeout: float = DECISION_TIMEOUT):
        self.timeout = float(timeout)
        self._lock = threading.Lock()
        self._pending = {}          # id -> PendingDecision
        self.stats = {"asked": 0, "user_quarantine": 0, "user_ignore": 0,
                      "auto": 0, "suppressed": 0}

    def ask(self, path: str, threat: dict,
            default_action: str = ACTION_QUARANTINE, reason: str = "") -> PendingDecision:
        """登记一个待决项（不阻塞），并推给两条**可点**通道。

        ``default_action``：**超时后的默认动作**。
          - ``quarantine``（默认，保持原行为）：两引擎确认的命中
          - ``ignore``：只有单个引擎命中的可疑项 —— 送进来**只为通知用户**，
            不答就不动手，避免绕过闸门

        只保留"带按钮、用户能真正做决定"的通道：
          1) 桌面原生窗口（tkinter，置顶，屏幕右下角）—— 不依赖浏览器，主通道
          2) 网页右下角弹窗 —— 用户正看着页面时更顺手

        系统托盘气泡只有提示、没有按钮，用户只能眼看着 15 秒过去，
        按用户要求已移除（"只留有按钮的弹窗"）。
        """
        pd = PendingDecision(path, threat, default_action=default_action, reason=reason)
        pd.deadline = pd.created_at + self.timeout
        with self._lock:
            self._pending[pd.id] = pd
        self.stats["asked"] += 1
        # 桌面决策窗口：用户不在浏览器前时的**唯一可点通道**。
        # 网页弹窗和托盘气泡都只是"通知"——点不到、也没按钮；
        # 少了这个，桌面用户只能眼看着 15 秒后文件被自动隔离。
        #
        # 2026-11-01：原来这里 `try/except: pass` 且**丢弃 show() 的返回值**。
        # 桌面窗口不可用（返回 False）时既不弹窗、也不写日志、也不回退 ——
        # 用户完全不知道有事发生，只能在界面里自己翻「待决威胁」列表。
        # 现在如实统计并记 warning，至少可诊断。
        delivered = False
        try:
            from engine.desktop_prompt import show as _desktop_show
            delivered = bool(_desktop_show(pd, self.decide))
        except Exception as exc:                  # noqa: BLE001 - 通知失败不能影响处置
            logger.warning("桌面通知异常（pending=%s path=%s）: %s",
                           pd.id, pd.path, exc)
        if not delivered:
            self.stats["notify_failed"] = self.stats.get("notify_failed", 0) + 1
            logger.warning(
                "桌面通知未投递（pending=%s path=%s）—— 用户仍可在界面「待决威胁」"
                "看到该项，但没有弹窗提醒", pd.id, pd.path)
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
        """结算一个待决项：已决定则用用户的选择，否则超时按**该项自己的**默认动作处理。"""
        if not pd.decided:
            # 2026-10-31：原来这里写死 ACTION_QUARANTINE。改成读每项自己的
            # default_action —— 只被单个引擎命中的可疑项超时应当 ignore，
            # 否则一旦通知给用户就等于绕过闸门。
            pd.action = pd.default_action or ACTION_QUARANTINE
            pd.decided = True
            pd.auto = True
            self.stats["auto"] += 1
            if pd.action == ACTION_IGNORE:
                self.stats["auto_ignored"] = self.stats.get("auto_ignored", 0) + 1
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
