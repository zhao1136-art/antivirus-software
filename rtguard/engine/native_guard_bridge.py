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
    # ── native_guard.dll 启用策略 ──
    # 历史崩溃根因已定位并修复：
    #   1) 调用约定不匹配：导出为 __cdecl，而桥接层用 windll(__stdcall) 调用，
    #      栈不平衡触发 0xC0000005；已改用 ctypes.CDLL（见 _load）。
    #   2) ETW 未启动时访问未初始化临界区；已在 etw_guard.cpp 各查询导出
    #      前加 ensure_locks()，并重新编译。
    # 默认启用。若需临时关闭以回退 Python 引擎，可设 YUTIAN_NATIVE_GUARD=0。
    if os.environ.get("YUTIAN_NATIVE_GUARD", "").strip() == "0":
        return None
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
    """御天原生防护引擎 - ctypes 绑定"""

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
        # 关键修复：native_guard 的导出函数均使用 C 默认 __cdecl 调用约定，
        # 而 ctypes.windll 按 __stdcall 约定调用。调用约定不匹配会导致栈不平衡，
        # 触发访问违规 0xC0000005（进程级崩溃，Python try/except 无法捕获）。
        # 必须改用 ctypes.CDLL（cdecl）加载。已用隔离探针逐个验证所有导出。
        self._dll = ctypes.CDLL(path)
        self._funcs: set = set()   # 实际存在的导出函数名（缺失时优雅降级）

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
            # ETW 事中检测（多 Provider 升级）
            "guard_etw_start", "guard_etw_stop", "guard_etw_status",
            "guard_etw_get_events",
            "guard_etw_get_correlations",   # 事件关联引擎（攻击链）
            "guard_etw_process_tree",       # 进程树行为评分（带 int 参数）
            "guard_etw_health",             # Provider 健康监控
            "guard_scan_amsi_tamper",       # AMSI 篡改扫描
            "guard_scan_etw_tamper",        # ETW 自身防篡改扫描
        ]
        for fname in VOID_FUNCS:
            try:
                func = getattr(self._dll, fname)
            except AttributeError:
                print(f"[NativeGuard] 导出函数缺失（DLL 版本过旧，已降级）: {fname}")
                continue
            func.restype = ctypes.c_void_p
            self._funcs.add(fname)

        # 参数类型设置（仅对存在的函数设置，避免 DLL 版本不匹配时加载失败）
        def _set_argtypes(name, types):
            if name in self._funcs:
                getattr(self._dll, name).argtypes = types

        _set_argtypes("guard_inject_scan_memory", [ctypes.c_uint32])
        _set_argtypes("guard_inject_enum_modules", [ctypes.c_uint32])
        _set_argtypes("guard_inject_dump_memory", [ctypes.c_uint32, ctypes.c_char_p])
        _set_argtypes("guard_etw_process_tree", [ctypes.c_int])
        if "guard_inject_dump_memory" in self._funcs:
            self._dll.guard_inject_dump_memory.restype = ctypes.c_int

        self._dll.guard_free_string.argtypes = [ctypes.c_void_p]
        self._dll.guard_free_string.restype = None

        self._loaded = True

    def _call(self, func_name: str, *args) -> Any:
        """调用 C++ 函数并解析 JSON 结果（正确处理 C 字符串内存）"""
        if not self._loaded or self._dll is None:
            return None
        if func_name not in self._funcs:
            print(f"[NativeGuard] 函数 {func_name} 在当前 DLL 中不存在")
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
    # ETW 事中检测（升级一：多 Provider 覆盖 + 架构增强）
    # ====================================================================

    def etw_start(self) -> dict:
        """
        启动 ETW 事中检测（多 Provider 会话）
        覆盖: Threat-Intelligence / Kernel-Process / Kernel-File / Kernel-Registry /
              DNS-Client / PowerShell / WMI-Activity / DotNETRuntime / Sysmon
        :returns: {success, ...}
        """
        return self._call("guard_etw_start")

    def etw_stop(self) -> dict:
        """停止 ETW 检测（事件已持久化到内存映射，重启后可恢复）"""
        return self._call("guard_etw_stop")

    def etw_status(self) -> dict:
        """
        ETW 状态（含各 Provider 捕获统计）
        :returns: {running, session_active, events_captured, suspicious,
                   queue_size, recovered_history,
                   providers: [{id, name, enabled, enable_ok, captured, suspicious}]}
        """
        return self._call("guard_etw_status")

    def etw_get_events(self) -> dict:
        """
        获取 ETW 捕获的可疑事件（获取后清空队列，含恢复的历史事件）
        :returns: {events: [{provider, provider_id, event_id, source_pid,
                             target_pid, parent_pid, image, image_name,
                             detail, rule, severity, ts, suspicious, recovered}]}
        """
        return self._call("guard_etw_get_events")

    def etw_get_correlations(self) -> dict:
        """
        事件关联引擎：获取攻击链事件（获取后清空）
        如 MALWARE_INSTALL_CHAIN / OFFICE_MACRO_CHAIN / LSASS_DUMP_CHAIN 等
        :returns: {correlations: [{pid, name, chain, severity, ts, detail}]}
        """
        return self._call("guard_etw_get_correlations")

    def etw_process_tree(self, top_n: int = 20) -> dict:
        """
        进程树行为评分：输出风险分最高的进程及子树聚合分
        :param top_n: 输出前 N 个进程（默认 20，范围 1-200）
        :returns: {processes: [{pid, parent_pid, name, image,
                                own_score, tree_score, first_seen}], total}
        """
        return self._call("guard_etw_process_tree", ctypes.c_int(top_n))

    def etw_health(self) -> dict:
        """
        Provider 健康监控：会话存活 + 事件流动（自保护）
        :returns: {running, session_active, flowing, events_since_last_poll,
                   total_captured, total_suspicious, ever_started}
        """
        return self._call("guard_etw_health")

    def scan_amsi_tamper(self) -> dict:
        """
        AMSI 篡改扫描：检测各进程 amsi.dll!AmsiScanBuffer 是否被 Inline Hook
        :returns: {tampered, scanned, hooked: [{pid, process, addr}], details: [...]}
        """
        return self._call("guard_scan_amsi_tamper")

    def scan_etw_tamper(self) -> dict:
        """
        ETW 自身防篡改扫描：检测 ntdll!EtwEventWrite 是否被 Patch + 会话存活
        :returns: {tampered, session_active, detail}
        """
        return self._call("guard_scan_etw_tamper")


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
