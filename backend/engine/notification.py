"""
系统弹窗通知 - 检测到威胁时弹出 Windows 原生消息框
"""
import ctypes
import threading

MB_OK = 0x00000000
MB_ICONWARNING = 0x00000030
MB_ICONERROR = 0x00000010
MB_ICONINFORMATION = 0x00000040
MB_SYSTEMMODAL = 0x00001000
MB_TOPMOST = 0x00040000


def _show_message_box(title: str, message: str, icon: int = MB_ICONWARNING):
    """弹出 Windows 原生消息框"""
    try:
        ctypes.windll.user32.MessageBoxW(
            0, message, title,
            MB_OK | icon | MB_SYSTEMMODAL | MB_TOPMOST
        )
    except Exception:
        pass  # 非 Windows 或调用失败时静默忽略


def threat_alert(threats: list, quarantined: int = 0):
    """检测到威胁后弹窗通知（后台线程调用，不阻塞主进程）"""
    if not threats:
        return

    count = len(threats)
    # 取前 5 个威胁名显示
    names = []
    for t in threats[:5]:
        name = t.get("signature", "") or t.get("threat_name", "") or "未知威胁"
        path = t.get("path", "")
        if path:
            fname = path.rsplit("\\", 1)[-1] if "\\" in path else path
            names.append(f"{fname}: {name}")
        else:
            names.append(name)

    detail = "\n".join(names)
    if count > 5:
        detail += f"\n... 等共 {count} 个威胁"

    if quarantined > 0:
        msg = f"扫描完成，发现 {count} 个威胁\n已隔离 {quarantined} 个文件\n\n{detail}"
    else:
        msg = f"扫描完成，发现 {count} 个威胁\n\n{detail}"

    # 在后台线程中弹窗，避免阻塞调度器
    t = threading.Thread(
        target=_show_message_box,
        args=("御天 - 发现威胁", msg),
        daemon=True
    )
    t.start()