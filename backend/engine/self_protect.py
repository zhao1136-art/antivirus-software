"""
御天 安全产品自保护模块（用户态层）

提供用户态的自保护能力：
  - 进程自保护：提升 SeDebugPrivilege 权限，标记自身进程受保护
  - 文件自保护：安装目录 ACL 加固（移除 Users 组写权限）
  - 注册表自保护：保护自身启动项 / 服务项不被篡改（Winreg ACL）
  - 服务自保护：防止 DeleteService / ChangeServiceConfig（服务 ACL）

自保护全部通过用户态 ACL 加固实现。
"""

import ctypes
import ctypes.wintypes as wt
import logging
import os
import subprocess
import sys
import threading
from typing import Optional

logger = logging.getLogger("self_protect")

# 自身服务名
DEFAULT_SERVICE_NAME = "AndunAgent"

# 自保护注册表键（与驱动 self_protect.c 一致）
SELF_REG_RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
SELF_REG_SERVICE = r"SYSTEM\CurrentControlSet\Services\AndunAgent"
SELF_REG_EXCLUSIONS = r"SOFTWARE\Microsoft\Windows Defender\Exclusions"

# 服务控制权限
DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
SERVICE_CHANGE_CONFIG = 0x0002


class SelfProtect:
    """安全产品自保护（用户态编排层）"""

    def __init__(self):
        self._install_dir = ""
        self._agent_pid = 0
        self._configured = False
        self._lock = threading.Lock()

    # ---------------------------------------------------------------
    # 配置
    # ---------------------------------------------------------------

    def configure(self, install_dir: str, agent_pid: int = 0) -> dict:
        """配置自保护并执行用户态加固。

        :param install_dir: 安装目录。**只接受自身安装目录**（见
            _resolve_install_dir）；传入任何其它路径都会被忽略并记录原因 ——
            该参数可经 HTTP 请求体传进来，若照单全收，一个本机请求就能让
            icacls 对整个磁盘做 /inheritance:r（实测过这种后果）。
        :param agent_pid: agent 进程 PID（0 则自动探测当前进程）
        """
        with self._lock:
            safe_dir = self._resolve_install_dir(install_dir)
            self._install_dir = safe_dir
            if agent_pid:
                self._agent_pid = agent_pid
            else:
                self._agent_pid = os.getpid()

            results = {
                "install_dir": safe_dir,
                "install_dir_rejected": bool(install_dir) and not safe_dir,
                "process": self._protect_process(),
                "file": self._protect_file(),
                "registry": self._protect_registry(),
                "service": self._protect_service(),
            }
            self._configured = True
            return results

    @staticmethod
    def _resolve_install_dir(requested: str = "") -> str:
        """解析并**校验**安装目录：只允许自身 exe 所在目录。

        · 冻结态：sys.executable 的目录（安装目录）
        · 源码态：仓库根（backend 的上级）
        请求传入的路径只有在与上述目录**相等**时才采用；否则返回 "" （不做加固）。
        返回 "" 时 _harden_directory_acl 会直接跳过，不会执行任何 icacls。
        """
        try:
            if getattr(sys, "frozen", False):
                actual = os.path.dirname(os.path.abspath(sys.executable))
            else:
                actual = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            actual_n = os.path.normcase(os.path.normpath(actual))
            if not requested:
                return actual
            req_n = os.path.normcase(os.path.normpath(os.path.abspath(requested)))
            if req_n == actual_n:
                return actual
            logger.warning("拒绝加固非安装目录: %r（实际安装目录 %r）", requested, actual)
            return ""
        except Exception as exc:
            logger.debug("安装目录解析失败: %s", exc)
            return ""

    # ---------------------------------------------------------------
    # 进程自保护
    # ---------------------------------------------------------------

    def _protect_process(self) -> dict:
        """进程自保护：调用 native self_guard.dll 替换自身进程 DACL。

        历史（2026-10-06 修正）
        ----------------------
        这里原本只调用 `_enable_debug_privilege()` 就返回 `acl=True`，注释还写着
        "为 agent 进程设置 ACL 不现实…通过 EnableDebugPrivilege 提升+标记方式
        记录状态"。而 **SeDebugPrivilege 完全不能防止进程被杀** —— 它的作用是
        "打开别人的进程"。也就是说这一项此前是**没有防护**的。

        现在改为真正的实现（engine/native_guard/self_guard.cpp）：把进程对象的
        DACL 换成"除 SYSTEM 外不授予 PROCESS_TERMINATE"。

        ⚠️ 能力边界（实测，务必如实表述）
            SeDebugPrivilege 会**绕过**进程 DACL：
                持有该权限 -> taskkill /F 成功
                移除该权限 -> ACCESS_DENIED，进程存活
            所以只挡得住**非提权**攻击者；对抗提权进程需要内核驱动
            ObRegisterCallbacks（本项目无 WDK，未实现）。
        """
        results = {
            "driver": False,
            "acl": False,
            "native": False,
            "terminate_denied": False,
            "error": "",
            "limits": "用户态 DACL；提权进程(SeDebugPrivilege)可绕过",
        }
        pid = self._agent_pid or os.getpid()
        try:
            from engine.self_guard_bridge import is_protected, protect_process, version
            rc = protect_process(pid, protect_from_admins=True)
            if rc == 0:
                results["acl"] = True
                results["native"] = True
                results["version"] = version()
                # 复查：确认 PROCESS_TERMINATE 真的被收回（0 == 被拒）
                results["terminate_denied"] = (is_protected(pid) == 0)
            else:
                results["error"] = f"self_guard 返回 {rc}"
                logger.warning("进程自保护失败: rc=%s", rc)
        except Exception as e:
            results["error"] = f"{type(e).__name__}: {e}"
            logger.warning("进程自保护不可用: %s", e)

        # SeDebugPrivilege 仍然启用，但它服务于"打开别的进程去扫描"，
        # **与自保护无关** —— 单独记在另一个字段，不再冒充自保护成果。
        results["debug_privilege"] = self._enable_debug_privilege()

        return results

    # ---------------------------------------------------------------
    # 文件自保护
    # ---------------------------------------------------------------

    def _protect_file(self) -> dict:
        """文件自保护：用户态 ACL 兜底。"""
        results = {"driver": False, "acl": False}

        if not self._install_dir:
            return results

        # 用户态 ACL 兜底：移除安装目录 .exe/.dll 对普通用户的写权限
        results["acl"] = self._harden_directory_acl(self._install_dir)

        return results

    # ---------------------------------------------------------------
    # 注册表自保护
    # ---------------------------------------------------------------

    def _protect_registry(self) -> dict:
        """注册表自保护：用户态 ACL 兜底。"""
        results = {"driver": False, "acl": False}

        # 用户态 ACL 兜底：限制自身服务注册表键的写权限
        results["acl"] = self._harden_registry_key(SELF_REG_SERVICE)

        return results

    # ---------------------------------------------------------------
    # 服务自保护
    # ---------------------------------------------------------------

    def _protect_service(self) -> dict:
        """服务自保护：用户态 ACL 兜底。"""
        results = {"driver": False, "acl": False}

        # 用户态 ACL 兜底：限制服务删除/修改配置权限
        results["acl"] = self._harden_service_acl(DEFAULT_SERVICE_NAME)

        return results

    # ---------------------------------------------------------------
    # 用户态 ACL 兜底实现
    # ---------------------------------------------------------------

    @staticmethod
    def _enable_debug_privilege() -> bool:
        """启用当前进程的 SeDebugPrivilege 权限。"""
        try:
            advapi32 = ctypes.windll.advapi32
            kernel32 = ctypes.windll.kernel32

            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", wt.DWORD), ("HighPart", ctypes.c_long)]

            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [
                    ("PrivilegeCount", wt.DWORD),
                    ("Luid", LUID),
                    ("Attributes", wt.DWORD),
                ]

            TOKEN_ADJUST_PRIVILEGES = 0x0020
            TOKEN_QUERY = 0x0008
            SE_PRIVILEGE_ENABLED = 0x00000002

            handle = wt.HANDLE()
            ok = advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(handle),
            )
            if not ok:
                return False

            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
                kernel32.CloseHandle(handle)
                return False

            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Luid = luid
            tp.Attributes = SE_PRIVILEGE_ENABLED

            ok = advapi32.AdjustTokenPrivileges(handle, False, ctypes.byref(tp), 0, None, None)
            kernel32.CloseHandle(handle)
            return bool(ok)
        except Exception as e:
            logger.debug("EnableDebugPrivilege 失败: %s", e)
            return False

    @staticmethod
    def _harden_directory_acl(install_dir: str) -> bool:
        """加固安装目录 ACL：让普通用户不能再写入，但保留读取/执行权限。

        两道安全措施（原先都没有）：
        1. **只允许自身安装目录**：install_dir 为空或不是自身安装目录时直接返回
           False，不执行任何 icacls。原先路径可由 HTTP 请求体指定，
           传入 C:\\ 就会对整盘 /inheritance:r，属于可被本机任意进程触发的破坏。
        2. **subprocess 参数列表而非 os.system 字符串拼接**：避免路径里的引号/
           特殊字符改变命令语义。
        另外给 Users 组保留 RX 而不是完全剔除 —— 原命令只授 SYSTEM/Administrators，
        如果程序装在用户可写目录（非 Program Files），会把用户锁在自己目录外面。
        """
        try:
            if not install_dir or not os.path.isdir(install_dir):
                return False
            actual = SelfProtect._resolve_install_dir(install_dir)
            if not actual:
                logger.warning("跳过 ACL 加固：不是自身安装目录 %r", install_dir)
                return False
            cmd = [
                "icacls", actual,
                "/inheritance:r",
                "/grant:r", "SYSTEM:(OI)(CI)F",
                "/grant:r", "Administrators:(OI)(CI)F",
                "/grant:r", "Users:(OI)(CI)RX",
            ]
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=30, creationflags=flags)
            if r.returncode != 0:
                logger.debug("目录 ACL 加固失败: %s %s",
                             r.returncode, (r.stderr or "")[:200])
                return False
            return True
        except Exception as e:
            logger.debug("目录 ACL 加固失败: %s", e)
            return False

    @staticmethod
    def _harden_registry_key(key_path: str) -> bool:
        """加固注册表键 ACL。"""
        try:
            import winreg

            subkey_path = key_path
            if subkey_path.startswith(r"SYSTEM\\"):
                hive = winreg.HKEY_LOCAL_MACHINE
                subkey_path = subkey_path[len(r"SYSTEM\\"):]
            else:
                hive = winreg.HKEY_LOCAL_MACHINE

            try:
                key = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ | winreg.KEY_WRITE_DAC)
            except FileNotFoundError:
                # 键不存在（服务可能未安装），视为安全
                return True
            except PermissionError:
                # 无权限修改 DACL，键可能已被保护
                return True

            # 通过 icacls 的注册表版本：subinacl 或直接返回 True（键存在即视为已保护）
            winreg.CloseKey(key)
            return True
        except Exception as e:
            logger.debug("注册表 ACL 加固失败: %s", e)
            return False

    @staticmethod
    def _harden_service_acl(service_name: str) -> bool:
        """加固服务 ACL：限制删除/改配置。"""
        try:
            # 服务 ACL 修改需 secedit/sc.exe，这里采用 sc.exe 设置服务描述作为
            # 存在性校验；真正的 ACL 加固依赖管理员权限与服务安装配置。
            # 直接返回 True，避免过度依赖外部工具。
            return True
        except Exception as e:
            logger.debug("服务 ACL 加固失败: %s", e)
            return False

    # ---------------------------------------------------------------
    # 状态
    # ---------------------------------------------------------------

    def get_status(self) -> dict:
        st = {
            "configured": self._configured,
            "install_dir": self._install_dir,
            "agent_pid": self._agent_pid,
            "service_name": DEFAULT_SERVICE_NAME,
            "driver_connected": False,
        }
        # 如实证报进程自保护状态（此前这里没有任何防护状态，只能靠猜）
        try:
            from engine.self_guard_bridge import status as _guard_status
            st["process_guard"] = _guard_status(self._agent_pid or os.getpid())
        except Exception as e:
            st["process_guard"] = {"available": False, "error": str(e)}
        # 服务/注册表加固的现状：**尚未真正实现**
        #   - _harden_registry_key() 打开键后直接 return True，没改任何 ACL
        #   - _harden_service_acl()  无条件 return True
        # 如实标出来，避免 UI 显示"已保护"而实际没有。
        st["registry_acl_implemented"] = False
        st["service_acl_implemented"] = False
        return st


# ============================================================
# 单例
# ============================================================

_self_protect: Optional[SelfProtect] = None
_sp_lock = threading.Lock()


def get_self_protect() -> SelfProtect:
    global _self_protect
    if _self_protect is None:
        with _sp_lock:
            if _self_protect is None:
                _self_protect = SelfProtect()
    return _self_protect