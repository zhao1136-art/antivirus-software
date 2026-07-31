"""
安盾 原生防护引擎 - Python ctypes 绑定层
直接加载 native_guard.dll，零延迟调用四大对抗模块

相比 native_bridge.py（子进程模式）：
- 延迟从 ~15-50ms 降至 ~0.1-1ms
- 支持高频轮询（进程注入/无文件攻击需要毫秒级采样）
- 有状态维护（无需反复创建子进程）
"""

import os
import sys
import json
import ctypes
from typing import Optional, Any

# DLL 查找路径
_DLL_NAME = "native_guard.dll"


def _find_dll() -> Optional[str]:
    """查找 native_guard.dll 文件路径"""
    base = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base, "native_guard", _DLL_NAME),
        os.path.join(base, "native_guard", "x64", _DLL_NAME),
        os.path.join(base, "native_guard", "x86", _DLL_NAME),
    ]
    if getattr(sys, 'frozen', False):
        try:
            candidates.append(os.path.join(sys._MEIPASS, "engine", "native_guard", _DLL_NAME))
        except Exception:
            pass
    for p in candidates:
        if os.path.isfile(p):
            return os.path.normpath(p)
    return None


# ========================================================================
# 原生防护引擎类
# ========================================================================

class NativeGuard:
    """安盾原生防护引擎 - ctypes 绑定"""

    def __init__(self, dll_path: Optional[str] = None):
        self._dll: Optional[ctypes.CDLL] = None
        self._loaded = False

        path = dll_path or _find_dll()
        if not path:
            raise RuntimeError(
                f"[-] native_guard.dll 未找到。\n"
                f"    请在 {os.path.dirname(os.path.abspath(__file__))}/native_guard/ 下放置编译好的 DLL\n"
                f"    编译命令: g++ -O2 -shared -o native_guard.dll *.cpp "
                f"-ladvapi32 -lws2_32 -liphlpapi -lpsapi -lole32 -lntdll -lwintrust "
                f"-static-libgcc -static-libstdc++"
            )

        self._load(path)

    def _load(self, path: str):
        """加载 DLL 并设置函数签名"""
        self._dll = ctypes.windll.LoadLibrary(path)

        # 所有返回 char* 的函数都用 c_void_p，避免 ctypes 自动释放
        # 然后手动调用 guard_free_string 释放 C 侧内存
        VOID_FUNCS = [
            "guard_version", "guard_self_test",
            "guard_inject_scan_memory", "guard_inject_scan_all",
            "guard_inject_enum_modules", "guard_inject_enum_all_modules",
            "guard_inject_scan_threads",
            "guard_fileless_scan_cmdlines", "guard_fileless_check_wmi",
            "guard_persist_scan_all",
            "guard_net_enum_tcp", "guard_net_enum_with_risk",
            # ETW 事中检测
            "guard_etw_start", "guard_etw_stop", "guard_etw_status",
            "guard_etw_get_events",
        ]
        for fname in VOID_FUNCS:
            func = getattr(self._dll, fname)
            func.restype = ctypes.c_void_p

        # 参数类型设置
        self._dll.guard_inject_scan_memory.argtypes = [ctypes.c_uint32]
        self._dll.guard_inject_enum_modules.argtypes = [ctypes.c_uint32]
        self._dll.guard_inject_dump_memory.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
        self._dll.guard_inject_dump_memory.restype = ctypes.c_int

        self._dll.guard_free_string.argtypes = [ctypes.c_void_p]
        self._dll.guard_free_string.restype = None

        self._loaded = True

    def _call(self, func_name: str, *args) -> Any:
        """调用 C++ 函数并解析 JSON 结果（正确处理 C 字符串内存）"""
        if not self._loaded or self._dll is None:
            return None
        try:
            func = getattr(self._dll, func_name)
            raw_ptr = func(*args)
            if not raw_ptr:
                return None
            # 将 void* 转换为 Python bytes
            raw_bytes = ctypes.c_char_p(raw_ptr).value
            # 尝试 UTF-8 解码；如果失败则用替换字符
            try:
                text = raw_bytes.decode('utf-8')
            except UnicodeDecodeError:
                text = raw_bytes.decode('utf-8', errors='replace')
            # 安全网：确保 JSON 中无未转义的控制字符
            # 某些 WMI/注册表数据可能携带控制字符绕过 C++ json_escape
            import re as _re
            text = _re.sub(r'[\x00-\x1f\x7f]',
                          lambda m: f'\\u{ord(m.group(0)):04x}', text)
            result = json.loads(text)
            # 必须显式释放 C 侧 alloc_str 分配的内存
            self._dll.guard_free_string(raw_ptr)
            return result
        except json.JSONDecodeError as e:
            print(f"[NativeGuard] JSON 解析失败: {e}")
            return None
        except AttributeError as e:
            print(f"[NativeGuard] 函数 {func_name} 未找到: {e}")
            return None
        except Exception as e:
            print(f"[NativeGuard] 调用 {func_name} 失败: {e}")
            return None

    # ====================================================================
    # 通用接口
    # ====================================================================

    @property
    def available(self) -> bool:
        return self._loaded

    def version(self) -> dict:
        return self._call("guard_version")

    def self_test(self) -> dict:
        return self._call("guard_self_test")

    # ====================================================================
    # 进程注入对抗
    # ====================================================================

    def scan_process_memory(self, pid: int) -> dict:
        """
        扫描指定进程内存，识别匿名可执行区域
        :param pid: 目标进程 ID
        :returns: {pid, memory_regions: [{addr, size, protect, risk, ...}], risk_level}
        """
        return self._call("guard_inject_scan_memory", ctypes.c_uint32(pid))

    def scan_all_memory(self) -> dict:
        """
        扫描所有进程内存
        :returns: {processes: [{pid, name, risk, detail}], total_high_risk}
        """
        return self._call("guard_inject_scan_all")

    def enum_modules(self, pid: int) -> dict:
        """
        枚举指定进程的加载模块，校验签名和路径
        :param pid: 目标进程 ID
        :returns: {pid, modules: [{name, path, risk, signed, flags}], risk_level}
        """
        return self._call("guard_inject_enum_modules", ctypes.c_uint32(pid))

    def enum_all_modules(self) -> dict:
        """
        枚举所有进程的加载模块
        :returns: {processes: [{pid, name, risk, detail}], total_suspicious}
        """
        return self._call("guard_inject_enum_all_modules")

    def scan_threads(self) -> dict:
        """
        枚举系统线程，检测远程注入线程
        :returns: {threads: [{tid, pid, process, start_addr, suspicious, reason}], risk_level}
        """
        return self._call("guard_inject_scan_threads")

    def dump_memory(self, pid: int, output_path: str) -> bool:
        """
        内存转储（Minidump）
        :param pid: 目标进程 ID
        :param output_path: 输出文件路径
        :returns: True 成功 / False 失败
        """
        result = self._dll.guard_inject_dump_memory(
            ctypes.c_uint32(pid),
            ctypes.c_char_p(output_path.encode('utf-8'))
        )
        return result == 0

    # ====================================================================
    # 无文件攻击对抗
    # ====================================================================

    def scan_cmdlines(self) -> dict:
        """
        扫描所有进程命令行，检测 LOLBins 可疑执行
        :returns: {processes: [{pid, name, cmdline, parent, risk, patterns}], total_suspicious}
        """
        return self._call("guard_fileless_scan_cmdlines")

    def check_wmi_consumers(self) -> dict:
        """
        检测 WMI 事件消费者（持久化后门）
        :returns: {wmi_consumers: [{type, name, query/script, risk}], total}
        """
        return self._call("guard_fileless_check_wmi")

    # ====================================================================
    # 持久化木马对抗
    # ====================================================================

    def scan_persistence(self) -> dict:
        """
        全覆盖扫描所有持久化通道
        覆盖: Run/RunOnce, Services, ActiveSetup, IFEO, 屏保, 启动文件夹,
              AppInit_DLLs, Winlogon, BootExecute, 打印监视器, BHO, LSA等
        :returns: {items: [{category, location, name, command, risk}], total_high, total_suspicious}
        """
        return self._call("guard_persist_scan_all")

    # ====================================================================
    # 网络侧补强
    # ====================================================================

    def enum_tcp_connections(self) -> dict:
        """
        枚举系统全部 TCP 连接（IPv4 + IPv6）
        :returns: {connections: [{pid, process, path, family, local, remote, state, outbound}], total}
        """
        return self._call("guard_net_enum_tcp")

    def enum_tcp_with_risk(self) -> dict:
        """
        枚举 TCP 连接并标记恶意端口
        :returns: {connections: [{pid, process, local, remote, risk, reason, port_label}], total, high_risk}
        """
        return self._call("guard_net_enum_with_risk")

    # ====================================================================
    # ETW 事中检测（升级一）
    # ====================================================================

    def etw_start(self) -> dict:
        """
        启动 ETW Threat-Intelligence 事中检测
        :returns: {success, status}
        """
        return self._call("guard_etw_start")

    def etw_stop(self) -> dict:
        """停止 ETW 检测"""
        return self._call("guard_etw_stop")

    def etw_status(self) -> dict:
        """ETW 状态"""
        return self._call("guard_etw_status")

    def etw_get_events(self) -> dict:
        """
        获取 ETW 捕获的可疑事件（获取后清空队列）
        :returns: {events: [{event_id, source_pid, target_pid, start_addr, source_module, suspicious}]}
        """
        return self._call("guard_etw_get_events")


# ========================================================================
# 单例
# ========================================================================

_guard_instance: Optional[NativeGuard] = None


def get_native_guard() -> Optional[NativeGuard]:
    """获取 NativeGuard 单例（自动查找 DLL）"""
    global _guard_instance
    if _guard_instance is None:
        try:
            _guard_instance = NativeGuard()
            print(f"[NativeGuard] 已加载: {_find_dll()}")
        except RuntimeError as e:
            print(f"[NativeGuard] {e}")
            _guard_instance = None
    return _guard_instance


# ========================================================================
# 便捷工具函数（供其他模块直接调用）
# ========================================================================

def quick_inject_scan() -> dict:
    """快速进程注入检测 — 一键扫描所有进程的注入迹象"""
    guard = get_native_guard()
    if not guard:
        return {"error": "native_guard.dll not loaded"}
    result = {
        "memory_scan": guard.scan_all_memory(),
        "module_scan": guard.enum_all_modules(),
        "thread_scan": guard.scan_threads(),
    }
    return result


def quick_fileless_scan() -> dict:
    """快速无文件攻击检测 — 命令行 + WMI"""
    guard = get_native_guard()
    if not guard:
        return {"error": "native_guard.dll not loaded"}
    return {
        "cmdlines": guard.scan_cmdlines(),
        "wmi": guard.check_wmi_consumers(),
    }


def quick_network_scan(c2_intel=None) -> dict:
    """快速网络扫描 — 枚举 TCP + C2 匹配"""
    guard = get_native_guard()
    if not guard:
        return {"error": "native_guard.dll not loaded"}
    
    result = guard.enum_tcp_with_risk()
    if not result:
        return {"error": "network scan failed"}

    # 如果有 C2 情报引擎，做额外匹配
    if c2_intel and "connections" in result:
        for conn in result["connections"]:
            remote = conn.get("remote", "")
            if ":" in remote:
                ip = remote.rsplit(":", 1)[0].strip("[]")
                try:
                    c2_result = c2_intel.lookup_ip(ip)
                    if c2_result and c2_result.get("is_c2"):
                        conn["c2_match"] = True
                        conn["c2_family"] = c2_result.get("family", "")
                except Exception:
                    pass
        result["c2_matched"] = True

    return result


# ========================================================================
# 命令行测试入口
# ========================================================================

if __name__ == "__main__":
    import pprint

    guard = get_native_guard()
    if not guard:
        print("[-] native_guard.dll 加载失败")
        sys.exit(1)

    print(f"[+] 版本: {guard.version()}")
    print(f"[+] 自检: {guard.self_test()}")

    print("\n===== 1. 进程注入扫描 =====")
    result = guard.scan_all_memory()
    print(f"高风险进程: {result.get('total_high_risk', 'N/A')}")

    print("\n===== 2. 线程注入检测 =====")
    result = guard.scan_threads()
    print(f"可疑远程线程: {result.get('total_suspicious', 'N/A')}")

    print("\n===== 3. 无文件攻击 =====")
    result = guard.scan_cmdlines()
    print(f"可疑 LOLBin: {result.get('total_suspicious', 'N/A')}")

    print("\n===== 4. WMI 持久化 =====")
    result = guard.check_wmi_consumers()
    print(f"WMI 消费者: {result.get('total', 'N/A')}")

    print("\n===== 5. 持久化通道 =====")
    result = guard.scan_persistence()
    print(f"持久化项: {result.get('total', 'N/A')}, 高风险: {result.get('total_high', 'N/A')}")

    print("\n===== 6. 网络连接 =====")
    result = guard.enum_tcp_connections()
    print(f"TCP 连接总数: {result.get('total', 'N/A')}")

    print("\n===== 7. 网络风险 =====")
    result = guard.enum_tcp_with_risk()
    print(f"高风险连接: {result.get('high_risk', 'N/A')}")
