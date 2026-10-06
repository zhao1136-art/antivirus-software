/*
 * self_guard.cpp —— 御天自保护（进程 DACL 加固）
 * =====================================================================
 *
 * 目的
 * ----
 * 对抗恶意进程结束防护（防 kill）。Python 侧原本的 self_protect.py 只有
 * EnableDebugPrivilege —— **该权限完全不能防止被杀**，等于没有防护
 * （见 engine/self_protect.py 第 77-85 行的自述："这里通过 EnableDebugPrivilege
 * 提升+标记方式记录状态"）。这里给出真正生效的用户态实现。
 *
 * 原理
 * ----
 * 替换目标进程对象的安全描述符 DACL，**不授予 PROCESS_TERMINATE**：
 *     SYSTEM          : PROCESS_ALL_ACCESS         （系统必须能管）
 *     Administrators  : 可配置 —— 强模式下也不给 TERMINATE
 *     Everyone(其余)  : 只给 QUERY_LIMITED / VM_READ / SYNCHRONIZE / READ_CONTROL
 *
 * 刻意**只用 ALLOW ACE、不用 DENY ACE**：访问权"未授予即拒绝"，这样不必和
 * "DENY 优先级高于 ALLOW"的规则搏斗（若用 DENY Everyone，连 SYSTEM 都会被挡）。
 *
 * ⚠️ 能力的真实边界（务必知情，别当成万无一失）
 * ---------------------------------------------------------------------
 * 实测（2026-10-06，本机管理员会话）：**SeDebugPrivilege 会绕过进程 DACL。**
 *     (a) 持有 SeDebugPrivilege 时        OpenProcess(PROCESS_TERMINATE) -> 成功
 *     (b) 显式移除 SeDebugPrivilege 之后   OpenProcess(PROCESS_TERMINATE) -> err=5 ACCESS_DENIED
 * 因此本模块：
 *     ✅ 能挡住**非提权**的恶意进程（同用户运行的常见恶意软件）
 *     ✅ 能挡住普通用户/受限进程的 taskkill
 *     ❌ 挡不住任何**提权**进程 —— 只要能启用 SeDebugPrivilege 就能绕过
 *     ❌ 挡不住内核态攻击
 * 要对抗提权攻击者，必须靠内核驱动 `ObRegisterCallbacks` 在句柄层面剥离
 * PROCESS_TERMINATE（本机无 WDK，无法构建，故未实现）。
 *
 * 因此本模块定位是"抬高门槛"，不是"绝对不可杀"。请如实对外表述。
 *
 * 导出的 C API
 * ------------
 *   int  YutianProtectProcess(DWORD pid, int protectFromAdmins);
 *   int  YutianUnprotectProcess(DWORD pid);
 *   int  YutianIsProcessProtected(DWORD pid);
 *   const char* YutianSelfGuardVersion(void);
 * 返回 0 表示成功，非 0 为 Win32 错误码；-1 表示参数/前置条件错误。
 */

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>

#define SELFGUARD_API extern "C" __declspec(dllexport)

/* 访问掩码（显式列出，避免依赖 winnt.h 的宏在不同 SDK 下的差异） */
#define MY_PROCESS_TERMINATE              0x0001
#define MY_PROCESS_VM_READ                0x0010
#define MY_PROCESS_QUERY_INFORMATION      0x0400
#define MY_PROCESS_QUERY_LIMITED_INFO     0x1000
#define MY_READ_CONTROL                   0x00020000
#define MY_WRITE_DAC                      0x00040000
#define MY_SYNCHRONIZE                    0x00100000
#define MY_PROCESS_ALL_ACCESS             0x001FFFFF

/* 无 TERMINATE 的受限掩码 */
#define MASK_RESTRICTED_USER  (MY_PROCESS_QUERY_LIMITED_INFO | MY_PROCESS_VM_READ | \
                               MY_SYNCHRONIZE | MY_READ_CONTROL)
#define MASK_RESTRICTED_ADMIN (MY_PROCESS_QUERY_LIMITED_INFO | MY_SYNCHRONIZE | MY_READ_CONTROL)

/*
 * 构造一个 DACL 并安装到进程对象上。
 * protectFromAdmins != 0 时，连 Administrators 也拿不到 PROCESS_TERMINATE。
 */
static int install_dacl(HANDLE hProcess, int protectFromAdmins)
{
    PSID pSystem = NULL, pAdmins = NULL, pEveryone = NULL;
    PACL pAcl = NULL;
    DWORD aclSize;
    int rc = -1;

    /* 用 SDDL 取众所周知的 SID，比手工 AllocateAndInitializeSid 更不易出错 */
    if (!ConvertStringSidToSidW(L"S-1-5-18", &pSystem))      goto cleanup;  /* SYSTEM */
    if (!ConvertStringSidToSidW(L"S-1-5-32-544", &pAdmins))   goto cleanup;  /* Administrators */
    if (!ConvertStringSidToSidW(L"S-1-1-0", &pEveryone))      goto cleanup;  /* Everyone */

    /*
     * ACL 大小按 SID 实长精确计算：ACL 头 + 每个 ACE 头 + SID 长度。
     * 固定缓冲区在 32/64 位或 SID 形态变化时有踩踏风险，这里算准。
     */
    aclSize = sizeof(ACL)
            + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(pSystem))
            + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(pAdmins))
            + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(pEveryone));

    pAcl = (PACL)LocalAlloc(LPTR, aclSize);
    if (!pAcl) { rc = (int)GetLastError(); goto cleanup; }

    if (!InitializeAcl(pAcl, aclSize, ACL_REVISION)) { rc = (int)GetLastError(); goto cleanup; }

    /* 顺序无关紧要（全部是 ALLOW ACE，不存在 DENY 抢先的问题） */
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, MY_PROCESS_ALL_ACCESS, pSystem)) {
        rc = (int)GetLastError(); goto cleanup;
    }
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION,
                             protectFromAdmins ? MASK_RESTRICTED_ADMIN : MY_PROCESS_ALL_ACCESS,
                             pAdmins)) {
        rc = (int)GetLastError(); goto cleanup;
    }
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, MASK_RESTRICTED_USER, pEveryone)) {
        rc = (int)GetLastError(); goto cleanup;
    }

    /*
     * SetSecurityInfo 的返回值是 **Win32 错误码**，ERROR_SUCCESS(0) 才是成功。
     * 这里别写成 if(!ret) 判失败 —— 那是把成功当失败（原型阶段踩过）。
     */
    {
        DWORD err = SetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                                    NULL, NULL, pAcl, NULL);
        rc = (err == ERROR_SUCCESS) ? 0 : (int)err;
    }

cleanup:
    if (pAcl)     LocalFree(pAcl);
    if (pSystem)  LocalFree(pSystem);
    if (pAdmins)  LocalFree(pAdmins);
    if (pEveryone) LocalFree(pEveryone);
    return rc;
}

/* 打开进程：优先全权；失败退到 WRITE_DAC（受限 DACL 下普通用户只能拿到这个） */
static HANDLE open_for_dacl(DWORD pid)
{
    HANDLE h = OpenProcess(MY_PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) h = OpenProcess(MY_WRITE_DAC | MY_READ_CONTROL, FALSE, pid);
    return h;
}

SELFGUARD_API int YutianProtectProcess(DWORD pid, int protectFromAdmins)
{
    if (pid == 0) return -1;
    HANDLE h = open_for_dacl(pid);
    if (!h) return (int)GetLastError();
    int rc = install_dacl(h, protectFromAdmins);
    CloseHandle(h);
    return rc;
}

/*
 * 解除保护：把 DACL 换成"Everyone 全权"。
 * 注意：强模式下普通管理员没有 WRITE_DAC，但 SeDebugPrivilege 会绕过 DACL，
 * 所以提权用户仍能调用本函数 —— 这就是留给运维/卸载的逃生通道。
 */
SELFGUARD_API int YutianUnprotectProcess(DWORD pid)
{
    if (pid == 0) return -1;
    HANDLE h = open_for_dacl(pid);
    if (!h) return (int)GetLastError();

    PSID pEveryone = NULL;
    PACL pAcl = NULL;
    int rc = -1;
    DWORD aclSize;

    if (!ConvertStringSidToSidW(L"S-1-1-0", &pEveryone)) { rc = (int)GetLastError(); goto cleanup; }
    aclSize = sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(pEveryone));
    pAcl = (PACL)LocalAlloc(LPTR, aclSize);
    if (!pAcl) { rc = (int)GetLastError(); goto cleanup; }
    if (!InitializeAcl(pAcl, aclSize, ACL_REVISION)) { rc = (int)GetLastError(); goto cleanup; }
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, MY_PROCESS_ALL_ACCESS, pEveryone)) {
        rc = (int)GetLastError(); goto cleanup;
    }
    {
        DWORD err = SetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                                    NULL, NULL, pAcl, NULL);
        rc = (err == ERROR_SUCCESS) ? 0 : (int)err;
    }

cleanup:
    if (pAcl)      LocalFree(pAcl);
    if (pEveryone) LocalFree(pEveryone);
    CloseHandle(h);
    return rc;
}

/*
 * 查询：当前调用方能否取得 PROCESS_TERMINATE。
 * 返回  1 = 能取得（视为**未**受保护）
 *       0 = 被拒绝（受保护）
 *      <0 = 其它错误（取负的错误码）
 */
SELFGUARD_API int YutianIsProcessProtected(DWORD pid)
{
    if (pid == 0) return -1;
    HANDLE h = OpenProcess(MY_PROCESS_TERMINATE, FALSE, pid);
    if (h) { CloseHandle(h); return 1; }
    DWORD err = GetLastError();
    return (err == ERROR_ACCESS_DENIED) ? 0 : -(int)err;
}

SELFGUARD_API const char* YutianSelfGuardVersion(void)
{
    return "self_guard/1.0 (user-mode DACL; SeDebugPrivilege bypasses)";
}
