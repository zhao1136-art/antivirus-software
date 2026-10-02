"""
御天 断网急救工具

修复 LSP、DNS、HOSTS 恶意篡改，恢复网络连接。
"""
import os
import sys
import time
import json
import socket
import subprocess
import threading
import shutil
from datetime import datetime
from pathlib import Path

IS_WINDOWS = sys.platform == 'win32'

DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data"
)
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_BACKUP = os.path.join(DATA_DIR, "hosts_backup.txt")
LOG_FILE = os.path.join(DATA_DIR, "logs", "network_repair.log")


class NetworkRepair:
    """断网急救工具"""

    def __init__(self):
        self._repair_history: list[dict] = []
        self._lock = threading.Lock()
        self._last_check: dict = {}
        os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)

    def _log(self, msg: str):
        t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{t}] {msg}\n")
        except Exception:
            pass

    # ── 网络诊断 ──

    def check_network(self) -> dict:
        """全面检查网络状态"""
        result = {
            "dns_ok": False,
            "ping_ok": False,
            "internet_ok": False,
            "hosts_ok": True,
            "hosts_entries": 0,
            "lsp_ok": True,
            "details": []
        }

        # 1. Ping 网关
        try:
            r = subprocess.run(
                ["ping", "-n", "1", "223.5.5.5"],
                capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
            )
            result["ping_ok"] = r.returncode == 0
            result["details"].append("Ping 外网: " + ("正常" if result["ping_ok"] else "失败"))
        except Exception:
            result["ping_ok"] = False
            result["details"].append("Ping 外网: 异常")

        # 2. DNS 解析
        try:
            socket.getaddrinfo("www.baidu.com", 80, timeout=3)
            result["dns_ok"] = True
            result["details"].append("DNS 解析: 正常")
        except Exception:
            result["dns_ok"] = False
            result["details"].append("DNS 解析: 异常")

        # 3. 互联网连通性
        result["internet_ok"] = result["ping_ok"] and result["dns_ok"]
        result["details"].append("互联网连通: " + ("正常" if result["internet_ok"] else "异常"))

        # 4. HOSTS 文件检查
        try:
            if os.path.exists(HOSTS_PATH):
                with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                suspicious = [l for l in lines if l.strip() and not l.strip().startswith("#")
                              and ("127.0.0.1" not in l.split()[:1] if l.split() else True)]
                # 实际检查恶意条目
                mal_entries = 0
                for l in lines:
                    s = l.strip()
                    if s and not s.startswith("#"):
                        parts = s.split()
                        if len(parts) >= 2:
                            ip, domain = parts[0], parts[1]
                            if ip not in ("127.0.0.1", "::1", "0.0.0.0", "255.255.255.255"):
                                if domain not in ("localhost", "localhost.localdomain"):
                                    mal_entries += 1
                result["hosts_entries"] = len([l for l in lines if l.strip() and not l.strip().startswith("#")])
                result["hosts_ok"] = mal_entries == 0
                result["details"].append(f"HOSTS 文件: {'正常' if result['hosts_ok'] else f'发现 {mal_entries} 个可疑条目'}")
            else:
                result["hosts_ok"] = False
                result["details"].append("HOSTS 文件: 不存在")
        except Exception as e:
            result["hosts_ok"] = False
            result["details"].append(f"HOSTS 检查异常: {e}")

        # 5. LSP 检查 (netsh winsock show catalog)
        try:
            r = subprocess.run(
                ["netsh", "winsock", "show", "catalog"],
                capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW
            )
            # 简单检查是否有明显异常
            result["lsp_ok"] = " winsock" in r.stdout.lower() or "目录" in r.stdout
            result["details"].append("LSP (Winsock): " + ("正常" if result["lsp_ok"] else "可能异常"))
        except Exception:
            result["lsp_ok"] = False
            result["details"].append("LSP (Winsock): 检查失败")

        self._last_check = result
        return result

    # ── 修复操作 ──

    def repair_hosts(self) -> dict:
        """修复 HOSTS 文件（备份后重置为默认）"""
        try:
            # 备份当前 HOSTS
            if os.path.exists(HOSTS_PATH):
                shutil.copy2(HOSTS_PATH, HOSTS_BACKUP)

            # 写入默认 HOSTS
            default_hosts = (
                "# Copyright (c) 1993-2009 Microsoft Corp.\r\n"
                "#\r\n"
                "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n"
                "#\r\n"
                "# localhost name resolution is handled within DNS itself.\r\n"
                "#\t127.0.0.1       localhost\r\n"
                "#\t::1             localhost\r\n"
                "\r\n"
                "127.0.0.1\tlocalhost\r\n"
                "::1\tlocalhost\r\n"
            )
            # 保留用户自定义的 127.0.0.1 屏蔽条目
            if os.path.exists(HOSTS_BACKUP):
                with open(HOSTS_BACKUP, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        s = line.strip()
                        if s and not s.startswith("#"):
                            parts = s.split()
                            if len(parts) >= 2 and parts[0] in ("127.0.0.1", "::1", "0.0.0.0"):
                                default_hosts += line

            with open(HOSTS_PATH, "w", encoding="utf-8") as f:
                f.write(default_hosts)

            self._log("HOSTS 文件已修复")
            self._add_history("hosts", "成功", "HOSTS 文件已重置为默认配置")
            return {"success": True, "message": "HOSTS 文件已修复"}
        except Exception as e:
            self._log(f"HOSTS 修复失败: {e}")
            return {"success": False, "error": str(e)}

    def repair_dns(self) -> dict:
        """刷新 DNS 缓存"""
        try:
            subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW
            )
            self._log("DNS 缓存已刷新")
            self._add_history("dns", "成功", "DNS 缓存已刷新")
            return {"success": True, "message": "DNS 缓存已刷新"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def repair_lsp(self) -> dict:
        """重置 Winsock/LSP"""
        try:
            subprocess.run(
                ["netsh", "winsock", "reset"],
                capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW
            )
            subprocess.run(
                ["netsh", "int", "ip", "reset"],
                capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW
            )
            self._log("LSP/Winsock 已重置")
            self._add_history("lsp", "成功", "LSP (Winsock) 已重置，可能需要重启")
            return {"success": True, "message": "LSP/Winsock 已重置，建议重启电脑"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def repair_all(self) -> dict:
        """一键修复所有网络问题"""
        results = {}
        results["hosts"] = self.repair_hosts()
        results["dns"] = self.repair_dns()
        results["lsp"] = self.repair_lsp()
        success = all(r.get("success") for r in results.values())
        self._log("一键断网急救完成")
        return {"success": success, "results": results}

    # ── 历史记录 ──

    def _add_history(self, action: str, status: str, detail: str):
        with self._lock:
            self._repair_history.insert(0, {
                "time": datetime.now().isoformat(),
                "action": action,
                "status": status,
                "detail": detail
            })
            if len(self._repair_history) > 50:
                self._repair_history = self._repair_history[:50]

    def get_history(self) -> list[dict]:
        with self._lock:
            return list(self._repair_history)

    def get_status(self) -> dict:
        return {
            "enabled": True,
            "last_check": self._last_check,
            "history_count": len(self._repair_history)
        }