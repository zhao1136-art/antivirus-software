"""
御天 AMSI Provider 注册 / 注销管理

用法:
    python amsi_manager.py status      # 查询状态（含完整性校验）
    python amsi_manager.py register    # 注册（需管理员）
    python amsi_manager.py unregister  # 注销
    python amsi_manager.py repair      # 先注销再注册（修复半注册状态）
    python amsi_manager.py verify      # 调 AmsiInitialize 验证 AMSI 是否健康


⚠️ 为什么原实现是错的（2026-10-04 修正）
========================================
原实现只写了一条键：

    HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{GUID}   默认值 = DLL 全路径

**这样注册之后，AMSI 不是变强，而是全系统失效。**

原因：Windows 加载 AMSI Provider 走的是 **COM**。amsi.dll 的流程是
    1. 枚举 HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers 下的 GUID
    2. 对每个 GUID 调 CoCreateInstance(GUID)
而 CoCreateInstance 要求该 GUID 已经在

    HKLM\\SOFTWARE\\Classes\\CLSID\\{GUID}\\InprocServer32

注册过。只写 Providers 键 = 每次扫描都去实例化一个**不存在的 COM 类**，
于是 AmsiInitialize / AmsiScanBuffer 直接失败。

实测症状（本机）：AmsiInitialize 返回 0x80070002 ERROR_FILE_NOT_FOUND
（健康系统应返回 S_OK），PowerShell / VBS / Office 的 AMSI 内容扫描
**被静默跳过** —— 比"没注册"更糟，是一个实打实的安全缺口。

正确注册需要三处（对照火绒 hramsi.dll 的注册方式）：

    HKLM\\SOFTWARE\\Classes\\CLSID\\{GUID}
        (默认值)          = Provider 名称          ← 注意：是名称，不是路径
    HKLM\\SOFTWARE\\Classes\\CLSID\\{GUID}\\InprocServer32
        (默认值)          = DLL 全路径
        ThreadingModel    = Both
    HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{GUID}
        (默认值)          = Provider 名称          ← 同样不是路径

32 位 AMSI 消费者（x86 PowerShell / Office / wscript）需要
Wow6432Node 下同样的 CLSID 两处，并指向 **x86 版** DLL。

另外：注销时**绝不能删除 Providers 父键**。火绒退出时就是把整个
HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers 删掉了，导致全系统 AMSI 失效
（别的 Provider 的注册也一并被清掉）。本模块只删自己那条 GUID。

关于 DLL 自身的 DllRegisterServer
---------------------------------
engine/native_guard/amsi_provider.dll 确实是一个合法的 COM 进程内服务器
（导出了 DllGetClassObject / DllCanUnloadNow / DllRegisterServer /
DllUnregisterServer），但它自己的 DllRegisterServer **也只写了 Providers
一条**，没有写 COM CLSID。而当前机器上没有 C++ 工具链、无法重编，
所以本模块：优先调用它的 DllRegisterServer，**再自己补齐 COM 两处**；
注销时两边都清。等哪天能重编 DLL，把 DLL 里的注册也补全后，本模块
依然兼容（重复写同样的键，幂等）。
"""

import os
import sys
import ctypes
import winreg

# ── 常量 ────────────────────────────────────────────────────────────────
AMSI_CLSID = "{5E2D2B3C-4F1A-4A7B-8E0D-9C3D1E2F3A4B}"
PROVIDER_NAME = "YutianAmsiProvider"          # 写入注册表的"名称"（不是路径）
PROVIDERS_KEY = r"SOFTWARE\Microsoft\AMSI\Providers"
CLSID_ROOT = r"SOFTWARE\Classes\CLSID"
THREADING_MODEL = "Both"

KEY_WOW64_64KEY = getattr(winreg, "KEY_WOW64_64KEY", 0x0100)
KEY_WOW64_32KEY = getattr(winreg, "KEY_WOW64_32KEY", 0x0200)

VIEWS = (("x64", KEY_WOW64_64KEY), ("x86", KEY_WOW64_32KEY))


# ── 路径定位 ────────────────────────────────────────────────────────────
def _base_dir() -> str:
    """打包后取 sys._MEIPASS，开发模式取本文件所在目录。"""
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))
    return os.path.dirname(os.path.abspath(__file__))


def dll_path(arch: str = "x64") -> str:
    """定位 amsi_provider.dll（arch = x64 / x86）。"""
    base = _base_dir()
    names = ["amsi_provider.dll"] if arch == "x64" else ["amsi_provider_x86.dll", "x86/amsi_provider.dll"]
    candidates = []
    for n in names:
        candidates.append(os.path.join(base, "engine", "native_guard", n))
        candidates.append(os.path.join(base, "native_guard", n))
    for c in candidates:
        if os.path.isfile(c):
            return os.path.normpath(c)
    return os.path.normpath(candidates[0])


def _dll_path() -> str:
    """向后兼容旧名字。"""
    return dll_path("x64")


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ── DLL 导出调用 ────────────────────────────────────────────────────────
def _call_dll_export(path: str, export: str):
    """LoadLibrary 后调用 DLL 的某个无参导出（如 DllRegisterServer）。

    返回 (ok, detail)。注意 LoadLibrary 成功本身也证明了 DLL 可加载，
    这样可以在写注册表之前挡住"非 COM DLL"。
    """
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.LoadLibraryW.restype = ctypes.c_void_p
        k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
        h = k32.LoadLibraryW(path)
        if not h:
            return False, f"LoadLibrary 失败 err={ctypes.get_last_error()}"
        k32.GetProcAddress.restype = ctypes.c_void_p
        k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        addr = k32.GetProcAddress(ctypes.c_void_p(h), export.encode("ascii"))
        if not addr:
            return False, f"未导出 {export}（不是合法的 COM 进程内服务器？）"
        fn = ctypes.CFUNCTYPE(ctypes.c_long)(addr)
        hr = fn()
        return hr == 0, f"{export} hr=0x{hr & 0xffffffff:08x}"
    except Exception as e:
        return False, f"{export} 调用异常: {type(e).__name__}: {e}"


def dll_capabilities(path: str) -> dict:
    """检查 DLL 是否具备 COM 进程内服务器所需的导出。"""
    need = ("DllGetClassObject", "DllRegisterServer", "DllUnregisterServer")
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.LoadLibraryW.restype = ctypes.c_void_p
        k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
        h = k32.LoadLibraryW(path)
        if not h:
            return {n: None for n in need} | {"_load": False}
        k32.GetProcAddress.restype = ctypes.c_void_p
        k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        out = {"_load": True}
        for n in need:
            out[n] = bool(k32.GetProcAddress(ctypes.c_void_p(h), n.encode("ascii")))
        return out
    except Exception:
        return {n: None for n in need} | {"_load": False}


# ── 注册表写入 ──────────────────────────────────────────────────────────
def _set_sz(root, subkey: str, name, value: str, view: int) -> None:
    with winreg.CreateKeyEx(root, subkey, 0, winreg.KEY_WRITE | view) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)


def _write_clsid(view: int, dll: str) -> None:
    """写 COM CLSID 两处（名称 + InprocServer32）。"""
    _set_sz(winreg.HKEY_LOCAL_MACHINE,
            f"{CLSID_ROOT}\\{AMSI_CLSID}", "", PROVIDER_NAME, view)
    _set_sz(winreg.HKEY_LOCAL_MACHINE,
            f"{CLSID_ROOT}\\{AMSI_CLSID}\\InprocServer32", "", dll, view)
    _set_sz(winreg.HKEY_LOCAL_MACHINE,
            f"{CLSID_ROOT}\\{AMSI_CLSID}\\InprocServer32", "ThreadingModel",
            THREADING_MODEL, view)
    # 让 AMSI 能展示本 Provider 的名字
    try:
        _set_sz(winreg.HKEY_LOCAL_MACHINE,
                f"{PROVIDERS_KEY}\\{AMSI_CLSID}", "", PROVIDER_NAME, view)
    except OSError:
        pass


def _delete_tree(root, subkey: str, view: int) -> bool:
    """删除一个键（必要时递归）。返回是否删掉了东西。"""
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_ALL_ACCESS | view) as k:
            pass
    except FileNotFoundError:
        return False
    except OSError:
        return False

    def _rec(hive, path):
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS | view) as k:
                while True:
                    try:
                        sub = winreg.EnumKey(k, 0)
                    except OSError:
                        break
                    _rec(hive, path + "\\" + sub)
        except OSError:
            pass
        try:
            winreg.DeleteKeyEx(hive, path, view, 0)
        except AttributeError:
            winreg.DeleteKey(hive, path)
        except OSError:
            pass

    _rec(root, subkey)
    return True


# ── 公开 API ────────────────────────────────────────────────────────────
def register() -> dict:
    """完整注册 AMSI Provider。需要管理员权限。

    顺序：先确认 DLL 是合法 COM 服务器 → 调它的 DllRegisterServer
    （拿到它认为正确的部分）→ 再补齐 COM CLSID 两处。
    """
    if not is_admin():
        return {"success": False, "error": "需要管理员权限运行"}

    dll = _dll_path()
    if not os.path.isfile(dll):
        return {"success": False, "error": f"amsi_provider.dll 不存在: {dll}"}

    caps = dll_capabilities(dll)
    if not caps.get("DllGetClassObject"):
        # 关键保护：不是 COM 进程内服务器就绝不注册，否则会把 AMSI 弄坏
        return {"success": False,
                "error": "amsi_provider.dll 未导出 DllGetClassObject，"
                         "不是合法的 COM 进程内服务器，拒绝注册（避免破坏 AMSI）",
                "caps": caps}

    steps = []
    ok, detail = _call_dll_export(dll, "DllRegisterServer")
    steps.append({"step": "DllRegisterServer", "ok": ok, "detail": detail})

    try:
        for view_name, view in VIEWS:
            if view_name == "x86":
                x86 = dll_path("x86")
                if not os.path.isfile(x86):
                    steps.append({"step": "x86 视图", "ok": True,
                                  "detail": "无 x86 DLL，跳过（32 位 AMSI 消费者不会被覆盖）"})
                    continue
                _write_clsid(view, x86)
                steps.append({"step": "x86 视图", "ok": True, "detail": x86})
            else:
                _write_clsid(view, dll)
                steps.append({"step": "x64 视图", "ok": True, "detail": dll})
    except PermissionError:
        return {"success": False, "error": "无写入 HKLM 权限，请以管理员运行",
                "steps": steps}
    except Exception as e:
        return {"success": False, "error": f"{type(e).__name__}: {e}", "steps": steps}

    st = status()
    return {"success": bool(st.get("ok")), "clsid": AMSI_CLSID,
            "name": PROVIDER_NAME, "dll": dll, "steps": steps, "status": st}


def unregister() -> dict:
    """注销本 Provider。

    ⚠️ 只删自己那条 GUID 和 CLSID，**绝不删除 Providers 父键**
       （父键是所有 Provider 共享的；删掉它会让全系统 AMSI 失效）。
    """
    if not is_admin():
        return {"success": False, "error": "需要管理员权限运行"}

    steps = []
    dll = _dll_path()
    if os.path.isfile(dll):
        ok, detail = _call_dll_export(dll, "DllUnregisterServer")
        steps.append({"step": "DllUnregisterServer", "ok": ok, "detail": detail})

    for view_name, view in VIEWS:
        removed_clsid = _delete_tree(winreg.HKEY_LOCAL_MACHINE,
                                     f"{CLSID_ROOT}\\{AMSI_CLSID}", view)
        removed_prov = _delete_tree(winreg.HKEY_LOCAL_MACHINE,
                                    f"{PROVIDERS_KEY}\\{AMSI_CLSID}", view)
        steps.append({"step": f"{view_name} 视图", "ok": True,
                      "detail": f"CLSID删除={removed_clsid} Providers条目删除={removed_prov}"})

    return {"success": True, "steps": steps, "status": status()}


def repair() -> dict:
    """先注销再注册 —— 用于修复"只注册了一半"的坏状态。"""
    u = unregister()
    r = register()
    return {"success": bool(r.get("success")), "unregister": u, "register": r}


def status() -> dict:
    """查询注册状态，并校验完整性。"""
    result = {"registered": False, "ok": False, "name": PROVIDER_NAME,
              "clsid": AMSI_CLSID, "providers": [], "issues": []}

    # 1) Providers 键下都有谁
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, PROVIDERS_KEY, 0,
                           winreg.KEY_READ | KEY_WOW64_64KEY)
    except FileNotFoundError:
        result["issues"].append(f"注册表键不存在: HKLM\\{PROVIDERS_KEY}"
                                "（正常的 Windows 至少有 Defender 或第三方 Provider）")
        k = None
    except OSError as e:
        result["issues"].append(f"打开 Providers 键失败: {e}")
        k = None

    if k:
        with k:
            i = 0
            while True:
                try:
                    guid = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(k, guid) as sub:
                        val, _ = winreg.QueryValueEx(sub, "")
                except OSError:
                    val = "<无默认值>"
                result["providers"].append({"clsid": guid, "value": val})
                if guid.upper() == AMSI_CLSID.upper():
                    result["registered"] = True
                    result["providers_value"] = val

    # 2) COM CLSID 两处是否齐
    cls = None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            f"{CLSID_ROOT}\\{AMSI_CLSID}", 0,
                            winreg.KEY_READ | KEY_WOW64_64KEY) as kk:
            cls, _ = winreg.QueryValueEx(kk, "")
    except OSError:
        pass
    result["clsid_default"] = cls

    inproc = None
    thr = None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            f"{CLSID_ROOT}\\{AMSI_CLSID}\\InprocServer32", 0,
                            winreg.KEY_READ | KEY_WOW64_64KEY) as kk:
            inproc, _ = winreg.QueryValueEx(kk, "")
            try:
                thr, _ = winreg.QueryValueEx(kk, "ThreadingModel")
            except OSError:
                pass
    except OSError:
        pass
    result["inprocserver32"] = inproc
    result["threading_model"] = thr

    # 3) 完整性判定
    if result["registered"]:
        if not cls:
            result["issues"].append("已写 Providers 键，但 COM CLSID 未注册 —— "
                                    "AMSI 会因 CoCreateInstance 失败而整体失效")
        if not inproc:
            result["issues"].append("缺少 InprocServer32 —— AMSI 找不到 provider DLL")
        elif not os.path.isfile(inproc):
            result["issues"].append(f"InprocServer32 指向的 DLL 不存在: {inproc}")
        if result.get("providers_value", "").strip().lower().endswith(".dll"):
            result["issues"].append("Providers 键默认值写成了 DLL 路径；"
                                    "Windows 约定这里应是 Provider 名称")
        result["ok"] = (bool(cls) and bool(inproc)
                        and os.path.isfile(inproc or "")
                        and not result["issues"])
    else:
        result["ok"] = False

    return result


def verify_amsi() -> dict:
    """直接调 amsi.dll 验证 AMSI 是否健康（S_OK 才算正常）。"""
    out = {"available": False, "hr": None, "hr_hex": None, "healthy": False}
    try:
        amsi = ctypes.WinDLL("amsi.dll")
        amsi.AmsiInitialize.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
        amsi.AmsiInitialize.restype = ctypes.c_long
        ctx = ctypes.c_void_p()
        hr = amsi.AmsiInitialize("yutian-amsi-verify", ctypes.byref(ctx))
        out["available"] = True
        out["hr"] = hr
        out["hr_hex"] = f"0x{hr & 0xffffffff:08x}"
        out["healthy"] = (hr == 0)
        if hr == 0:
            amsi.AmsiUninitialize(ctx)
        elif hr & 0xffffffff == 0x80070002:
            out["hint"] = ("ERROR_FILE_NOT_FOUND —— AMSI 找不到可用的 Provider 注册"
                           "（Providers 键缺失，或 GUID 没有对应的 COM CLSID）")
        elif hr & 0xffffffff == 0x80070103:
            out["hint"] = ("ERROR_NO_MORE_ITEMS —— Providers 键存在但里面一个 "
                           "Provider 都没有")
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


# ── CLI ─────────────────────────────────────────────────────────────────
def _main() -> None:
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    if action == "register":
        print("注册:", register())
    elif action == "unregister":
        print("注销:", unregister())
    elif action == "repair":
        print("修复:", repair())
    elif action == "verify":
        print("AMSI 健康检查:", verify_amsi())
    else:
        st = status()
        print("状态:", st)
        print("AMSI 健康检查:", verify_amsi())
        if st.get("issues"):
            print("问题:")
            for x in st["issues"]:
                print("   -", x)


if __name__ == "__main__":
    _main()
