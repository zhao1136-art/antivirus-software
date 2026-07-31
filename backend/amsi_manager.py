"""
AMSI Provider 注册/注销管理脚本

用法:
    python amsi_manager.py register    # 注册 AMSI Provider（需管理员）
    python amsi_manager.py unregister  # 注销
    python amsi_manager.py status      # 查询状态

AMSI Provider 机制:
    PowerShell/VBS/宏执行脚本内容前，系统调用所有已注册 Provider 的 Scan()。
    返回 AMSI_RESULT_DETECTED (32768) 即阻止脚本执行 → 无文件攻击事中拦截。
"""
import os
import sys
import winreg

AMSI_CLSID = "{5E2D2B3C-4F1A-4A7B-8E0D-9C3D1E2F3A4B}"
AMSI_KEY = r"SOFTWARE\Microsoft\AMSI\Providers"
REG_KEY = AMSI_KEY + "\\" + AMSI_CLSID


def _dll_path() -> str:
    """定位 amsi_provider.dll"""
    base = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base, "engine", "native_guard", "amsi_provider.dll"),
        os.path.join(base, "native_guard", "amsi_provider.dll"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            return os.path.normpath(p)
    return candidates[0]


def is_admin() -> bool:
    import ctypes
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def register() -> dict:
    if not is_admin():
        return {"success": False, "error": "需要管理员权限运行"}
    dll = _dll_path()
    if not os.path.isfile(dll):
        return {"success": False, "error": f"amsi_provider.dll 不存在: {dll}"}
    try:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, REG_KEY, 0, winreg.KEY_WRITE) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, dll)
        return {"success": True, "clsid": AMSI_CLSID, "dll": dll}
    except PermissionError:
        return {"success": False, "error": "无写入 HKLM 权限，请以管理员运行"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def unregister() -> dict:
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, REG_KEY)
        return {"success": True}
    except FileNotFoundError:
        return {"success": True, "note": "未注册"}
    except PermissionError:
        return {"success": False, "error": "无写入 HKLM 权限，请以管理员运行"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def status() -> dict:
    result = {"registered": False, "providers": []}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, AMSI_KEY) as pk:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(pk, i)
                    with winreg.OpenKey(pk, name) as sub:
                        dll, _ = winreg.QueryValueEx(sub, "")
                    result["providers"].append({"clsid": name, "dll": dll})
                    if name == AMSI_CLSID:
                        result["registered"] = True
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    return result


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    if action == "register":
        print("注册:", register())
    elif action == "unregister":
        print("注销:", unregister())
    else:
        print("状态:", status())
