"""
USB 自动扫描模块
通过 WMI 监听 Win32_VolumeChangeEvent 检测新接入的 USB 设备 → 自动扫描
"""
import os
import sys
import time
import threading
import json
from typing import Optional


class UsbAutoScanner:
    """USB 设备自动扫描器"""

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._scan_callback = None  # 扫描回调: func(drive_letter) -> dict
        self._on_threat = None  # 威胁告警回调
        self._scanned_drives = set()  # 已扫描的驱动器

    def set_callbacks(self, scan_callback=None, on_threat=None):
        """
        设置回调
        :param scan_callback: 扫描函数，接受盘符如 "D:\\"，返回扫描结果 dict
        :param on_threat: 发现威胁时回调
        """
        self._scan_callback = scan_callback
        self._on_threat = on_threat

    def start(self):
        if not sys.platform == "win32" or self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="USB-Monitor")
        self._thread.start()

    def stop(self):
        self._running = False

    def _get_removable_drives(self) -> list:
        """获取当前的可移动驱动器列表"""
        drives = []
        if sys.platform != "win32":
            return drives
        import ctypes
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                letter = chr(ord('A') + i)
                path = letter + ":\\"
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(path)
                if drive_type == 2:  # DRIVE_REMOVABLE
                    drives.append(path)
        return drives

    def _get_drive_volume_name(self, drive: str) -> str:
        """获取驱动器卷标"""
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(256)
            ctypes.windll.kernel32.GetVolumeInformationW(
                drive, buf, 256, None, None, None, None, 0
            )
            return buf.value or ""
        except Exception:
            return ""

    def _get_drive_info(self, drive: str) -> dict:
        """获取驱动器详细信息"""
        info = {"drive": drive, "label": self._get_drive_volume_name(drive)}
        try:
            import shutil
            usage = shutil.disk_usage(drive)
            info["total_gb"] = round(usage.total / (1024**3), 2)
            info["free_gb"] = round(usage.free / (1024**3), 2)
        except Exception:
            pass
        return info

    def _on_device_change(self, new_drives: list):
        """检测到新设备接入时处理"""
        old_drives = set(self._scanned_drives)
        current = set(new_drives)
        new_devices = current - old_drives

        for drive in new_devices:
            info = self._get_drive_info(drive)
            print(f"[USB Scanner] 检测到新设备: {info['drive']} ({info.get('label', '')})")

            # 触发扫描
            if self._scan_callback:
                try:
                    result = self._scan_callback(drive)
                    if result:
                        threats = result.get("threats", []) or result.get("infected", []) or []
                        if threats and self._on_threat:
                            self._on_threat({
                                "drive": drive,
                                "threats": threats,
                                "info": info,
                            })
                except Exception as e:
                    print(f"[USB Scanner] 扫描失败: {e}")

        self._scanned_drives = current

    def _monitor_loop(self):
        """后台 WMI 监控循环"""
        # 初始化已扫描列表
        self._scanned_drives.update(self._get_removable_drives())

        # 尝试使用 WMI 事件监听
        wmi_available = False
        try:
            import win32com.client
            wmi_available = True
        except ImportError:
            pass

        if wmi_available:
            self._wmi_monitor()
        else:
            self._poll_monitor()

    def _wmi_monitor(self):
        """WMI 事件监听方式（无需轮询）"""
        try:
            import win32com.client

            wmi = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            svc = wmi.ConnectServer(".", "root\\cimv2")

            # 订阅 VolumeChangeEvent
            query = "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"
            sink = win32com.client.WithEvents(svc, WMIEventSink)

            # 使用 ExecNotificationQuery 订阅事件
            events = svc.ExecNotificationQuery(query)

            while self._running:
                try:
                    event = events.NextEvent(2000)  # 最多等2秒
                    if event and self._running:
                        # 延迟一小段时间等系统完成挂载
                        time.sleep(1)
                        current = self._get_removable_drives()
                        self._on_device_change(current)
                except Exception:
                    time.sleep(1)
        except Exception:
            # 回退到轮询方式
            self._poll_monitor()

    def _poll_monitor(self):
        """轮询方式检测 USB 插拔（兼容无 pywin32 的环境）"""
        while self._running:
            try:
                current = set(self._get_removable_drives())
                previous = set(self._scanned_drives)
                if current != previous:
                    self._on_device_change(list(current))
                time.sleep(3)
            except Exception:
                time.sleep(3)


class WMIEventSink:
    """WMI 事件接收器（占位，实际通过 ExecNotificationQuery 同步方式处理）"""
    pass


# 单例
_usb_scanner: Optional[UsbAutoScanner] = None


def get_usb_scanner() -> UsbAutoScanner:
    global _usb_scanner
    if _usb_scanner is None:
        _usb_scanner = UsbAutoScanner()
    return _usb_scanner
