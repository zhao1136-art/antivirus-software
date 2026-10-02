/**
 * 进程注入对抗模块
 * 
 * 检测能力:
 * 1. VirtualQueryEx 扫描所有进程内存 → 识别匿名可执行(RWX)区域
 * 2. EnumProcessModules 校验DLL签名/路径/黑名单
 * 3. 枚举系统线程 → 检测远程注入线程
 */
#include "native_guard.h"

// ========================================================================
// 1. 匿名可执行内存扫描 (VirtualQueryEx)
// ========================================================================

// 常见恶意模块名称黑名单
static const char* MALICIOUS_DLL_NAMES[] = {
    "winhacker.dll", "inject.dll", "reflective.dll", "loader.dll",
    "mimi.exe", "mimikatz.exe", "payload.dll", "beacon.dll",
    "cobaltstrike.dll", "metsrv.dll", "evil.dll", "hook.dll",
    nullptr
};

// 系统关键进程列表（不应加载第三方 DLL）
static const char* SYSTEM_CRITICAL_PROCS[] = {
    "lsass.exe", "winlogon.exe", "services.exe", "svchost.exe",
    "csrss.exe", "smss.exe", "spoolsv.exe", "explorer.exe", "taskhost.exe",
    nullptr
};

// 系统路径前缀
static bool is_system_path(const std::string& path) {
    std::string low = to_lower(path);
    return low.find("\\system32\\") != std::string::npos ||
           low.find("\\syswow64\\") != std::string::npos ||
           low.find("\\windows\\") != std::string::npos;
}

// 检查是否为已知恶意 DLL 名称
static bool is_malicious_dll_name(const std::string& dllName) {
    std::string low = to_lower(dllName);
    for (int i = 0; MALICIOUS_DLL_NAMES[i]; i++) {
        if (low == MALICIOUS_DLL_NAMES[i]) return true;
    }
    return false;
}

// 检查进程是否为系统关键进程
static bool is_critical_process(const std::string& procName) {
    std::string low = to_lower(procName);
    for (int i = 0; SYSTEM_CRITICAL_PROCS[i]; i++) {
        if (low == SYSTEM_CRITICAL_PROCS[i]) return true;
    }
    return false;
}

// 数字签名验证（WinVerifyTrust）
static bool verify_digital_signature(const std::string& filePath) {
    std::wstring wPath = utf8_to_wide(filePath);
    
    WINTRUST_FILE_INFO fileInfo;
    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = wPath.c_str();
    
    WINTRUST_DATA wvtData;
    ZeroMemory(&wvtData, sizeof(wvtData));
    wvtData.cbStruct = sizeof(wvtData);
    wvtData.dwUnionChoice = WTD_CHOICE_FILE;
    wvtData.pFile = &fileInfo;
    wvtData.dwUIChoice = WTD_UI_NONE;
    wvtData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wvtData.dwStateAction = WTD_STATEACTION_IGNORE;
    wvtData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    
    GUID guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guid, &wvtData);
    
    return (status == ERROR_SUCCESS);
}

/**
 * 扫描指定进程的内存，识别匿名可执行区域
 * JSON: {"memory_regions":[{...}]}
 */
extern "C" __declspec(dllexport) char* guard_inject_scan_memory(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        return alloc_str("{\"pid\":0,\"memory_regions\":[],\"risk\":\"no_access\",\"error\":\"OpenProcess failed\"}");
    }

    std::string json = "{\"pid\":" + std::to_string(pid) + ",\"memory_regions\":[";
    bool first = true;
    int suspiciousCount = 0;
    int rwxCount = 0;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T result = VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi));
        if (result == 0) break;

        // 关注可执行内存
        bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (isExecutable) {
            // 获取该区域对应模块名（如果有）
            wchar_t modPath[MAX_PATH] = {0};
            DWORD modLen = GetMappedFileNameW(hProc, mbi.BaseAddress, modPath, MAX_PATH);
            bool hasFileMapping = (modLen > 0);

            DWORD protect = mbi.Protect;
            bool isRWX = (protect == PAGE_EXECUTE_READWRITE);
            bool isPrivate = (mbi.Type == MEM_PRIVATE);
            bool isImage = (mbi.Type == MEM_IMAGE);
            bool isMapped = (mbi.Type == MEM_MAPPED);

            // 可疑规则:
            //   RWX + 匿名(无文件映射) = 高可疑（Shellcode/反射注入）
            //   RWX + IMAGE = 疑似（正常IMAGE不应RWX）
            //   匿名可执行 + 大小 > 1MB = 高可疑
            std::string risk = "safe";
            if (isRWX && !hasFileMapping && isPrivate) {
                risk = "high";    // RWX 匿名内存 = 经典 Shellcode/反射注入
            } else if (isRWX && isImage) {
                risk = "suspicious";  // 正常 PE 不应 RWX
            } else if (isExecutable && !hasFileMapping && isPrivate && mbi.RegionSize > 1024 * 1024) {
                risk = "high";    // 大块匿名可执行内存
            } else if (isExecutable && !hasFileMapping && isPrivate) {
                risk = "suspicious";
            }

            // 收集熵值：扫描内容中 NULL 字节比例（Shellcode 通常非空率 > 70%）
            double nonNullRatio = 0.0;
            if (isRWX || !hasFileMapping) {
                SIZE_T scanSize = mbi.RegionSize < 4096 ? mbi.RegionSize : 4096;
                BYTE* buffer = (BYTE*)malloc(scanSize);
                if (buffer) {
                    SIZE_T bytesRead = 0;
                    if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer, scanSize, &bytesRead) && bytesRead > 0) {
                        SIZE_T nonNull = 0;
                        for (SIZE_T i = 0; i < bytesRead; i++) {
                            if (buffer[i] != 0) nonNull++;
                        }
                        nonNullRatio = (double)nonNull / (double)bytesRead;
                        // 高熵 + RWX = 强化可疑
                        if (nonNullRatio > 0.7 && risk == "suspicious") risk = "high";
                    }
                    free(buffer);
                }
            }

            if (risk != "safe") {
                if (!first) json += ",";
                first = false;
                suspiciousCount++;

                std::string modName;
                if (hasFileMapping) {
                    // 转换设备路径到逻辑路径
                    char logicalPath[MAX_PATH] = {0};
                    if (GetLogicalDriveStringsA(MAX_PATH, logicalPath)) {
                        // 使用 QueryDosDevice 映射
                        char dosPath[MAX_PATH];
                        if (GetMappedFileNameA(hProc, mbi.BaseAddress, dosPath, MAX_PATH)) {
                            modName = dosPath;
                        }
                    }
                }

                char buf[1024];
                snprintf(buf, sizeof(buf),
                    "{\"addr\":\"0x%llX\",\"size\":%llu,\"protect\":\"%s\",\"type\":\"%s\","
                    "\"risk\":\"%s\",\"module\":\"%s\",\"has_file_map\":%s,\"non_null_ratio\":%.3f}",
                    (unsigned long long)mbi.BaseAddress, (unsigned long long)mbi.RegionSize,
                    isRWX ? "RWX" : (protect & PAGE_EXECUTE_READ ? "RX" : (protect & PAGE_EXECUTE_WRITECOPY ? "WX" : "X")),
                    isPrivate ? "PRIVATE" : (isImage ? "IMAGE" : "MAPPED"),
                    risk, json_escape(modName).c_str(),
                    hasFileMapping ? "true" : "false", nonNullRatio);
                json += buf;
            }

            if (isRWX) rwxCount++;
        }

        addr += mbi.RegionSize;
    }

    CloseHandle(hProc);

    json += "],\"risk_level\":\"";
    if (suspiciousCount > 2) json += "high";
    else if (suspiciousCount > 0) json += "suspicious";
    else json += "safe";
    json += "\",\"suspicious_regions\":" + std::to_string(suspiciousCount);
    json += ",\"rwx_regions\":" + std::to_string(rwxCount) + "}";

    return alloc_str(json.c_str());
}

/**
 * 扫描所有进程内存（批量）
 */
extern "C" __declspec(dllexport) char* guard_inject_scan_all() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return alloc_str("{\"error\":\"snapshot failed\",\"processes\":[]}");

    std::string json = "{\"processes\":[";
    bool first = true;
    int totalHigh = 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            // 跳过空闲和系统进程
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

            // 为每个进程执行内存扫描
            char* memResult = guard_inject_scan_memory(pe.th32ProcessID);
            if (memResult) {
                // 提取 risk_level
                const char* riskMarker = "\"risk_level\":\"";
                const char* p = strstr(memResult, riskMarker);
                std::string risk = "safe";
                if (p) {
                    p += strlen(riskMarker);
                    const char* end = strchr(p, '\"');
                    if (end) risk = std::string(p, end - p);
                }

                if (risk == "high" || risk == "suspicious") {
                    if (!first) json += ",";
                    first = false;
                    std::string pname = wide_to_utf8(pe.szExeFile);
                    // 直接拼接，避免 snprintf 固定缓冲截断内嵌的 detail（内存扫描 JSON 常超 512B）
                    json += "{\"pid\":" + std::to_string(pe.th32ProcessID);
                    json += ",\"name\":\""; json += json_escape(pname); json += "\"";
                    json += ",\"risk\":\""; json += risk; json += "\"";
                    json += ",\"detail\":"; json += (memResult ? memResult : "{}");
                    json += "}";
                    if (risk == "high") totalHigh++;
                }
                guard_free_string(memResult);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    json += "],\"total_high_risk\":" + std::to_string(totalHigh) + "}";
    return alloc_str(json.c_str());
}

// ========================================================================
// 2. 枚举进程模块 + 签名校验 (EnumProcessModules)
// ========================================================================

/**
 * 枚举指定进程的所有加载模块，校验数字签名和路径合法性
 */
extern "C" __declspec(dllexport) char* guard_inject_enum_modules(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        return alloc_str("{\"pid\":0,\"modules\":[],\"risk\":\"no_access\"}");
    }

    std::string json = "{\"pid\":" + std::to_string(pid) + ",\"modules\":[";
    bool first = true;
    int suspiciousCount = 0;
    std::string procName = get_process_name_by_pid(pid);
    bool isCritical = is_critical_process(procName);

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD numModules = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < numModules; i++) {
            wchar_t modPath[MAX_PATH_LEN];
            if (!GetModuleFileNameExW(hProc, hMods[i], modPath, MAX_PATH_LEN))
                continue;

            std::string path = wide_to_utf8(modPath);
            std::string name = path;
            size_t slashPos = path.rfind('\\');
            if (slashPos != std::string::npos) name = path.substr(slashPos + 1);

            // 风险判定
            std::string risk = "safe";
            std::vector<std::string> flags;

            // 1) 恶意名称黑名单
            if (is_malicious_dll_name(name)) {
                risk = "high";
                flags.push_back("malicious_name");
            }

            // 2) 系统关键进程加载了非系统路径的 DLL
            if (isCritical && !is_system_path(path) && risk != "high") {
                risk = "high";
                flags.push_back("non_system_dll_in_critical_process");
            }

            // 3) 数字签名验证
            bool hasSignature = verify_digital_signature(path);
            if (!hasSignature && isCritical && !is_system_path(path)) {
                flags.push_back("unsigned");
            } else if (!hasSignature && risk == "safe") {
                flags.push_back("unsigned");
            }

            // 4) 从临时目录加载的 DLL
            std::string lowPath = to_lower(path);
            if (lowPath.find("\\temp\\") != std::string::npos ||
                lowPath.find("\\appdata\\local\\temp") != std::string::npos) {
                if (risk == "safe") risk = "suspicious";
                flags.push_back("temp_path");
            }

            // 5) DLL 路径伪装（系统 DLL 但从非标准路径加载）
            if (lowPath.find("\\system32\\") == std::string::npos &&
                lowPath.find("\\syswow64\\") == std::string::npos &&
                (name == "kernel32.dll" || name == "ntdll.dll" || 
                 name == "user32.dll" || name == "advapi32.dll" ||
                 name == "ws2_32.dll")) {
                risk = "high";
                flags.push_back("system_dll_hijack");
            }

            if (risk != "safe") {
                if (!first) json += ",";
                first = false;
                suspiciousCount++;

                // 构建 flags 数组 JSON
                std::string flagsJson = "[";
                for (size_t f = 0; f < flags.size(); f++) {
                    if (f > 0) flagsJson += ",";
                    flagsJson += "\"" + flags[f] + "\"";
                }
                flagsJson += "]";

                char buf[2048];
                snprintf(buf, sizeof(buf),
                    "{\"name\":\"%s\",\"path\":\"%s\",\"risk\":\"%s\",\"signed\":%s,\"flags\":%s}",
                    json_escape(name).c_str(), json_escape(path).c_str(),
                    risk, hasSignature ? "true" : "false", flagsJson.c_str());
                json += buf;
            }
        }
    }

    CloseHandle(hProc);

    json += "],\"risk_level\":\"";
    if (suspiciousCount > 0) json += "high";
    else json += "safe";
    json += "\",\"suspicious_modules\":" + std::to_string(suspiciousCount) + "}";

    return alloc_str(json.c_str());
}

/**
 * 枚举所有进程的模块
 */
extern "C" __declspec(dllexport) char* guard_inject_enum_all_modules() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return alloc_str("{\"error\":\"snapshot failed\",\"processes\":[]}");

    std::string json = "{\"processes\":[";
    bool first = true;
    int totalSuspicious = 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

            char* modResult = guard_inject_enum_modules(pe.th32ProcessID);
            if (modResult) {
                const char* riskMarker = "\"risk_level\":\"";
                const char* p = strstr(modResult, riskMarker);
                std::string risk = "safe";
                if (p) {
                    p += strlen(riskMarker);
                    const char* end = strchr(p, '\"');
                    if (end) risk = std::string(p, end - p);
                }

                if (risk != "safe") {
                    if (!first) json += ",";
                    first = false;
                    char buf[512];
                    snprintf(buf, sizeof(buf),
                        "{\"pid\":%lu,\"name\":\"%s\",\"risk\":\"%s\",\"detail\":%s}",
                        pe.th32ProcessID, json_escape(wide_to_utf8(pe.szExeFile)).c_str(),
                        risk.c_str(), modResult);
                    json += buf;
                    totalSuspicious++;
                }
                guard_free_string(modResult);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    json += "],\"total_suspicious\":" + std::to_string(totalSuspicious) + "}";
    return alloc_str(json.c_str());
}

// ========================================================================
// 3. 远程线程检测（v2 - 白名单调优版）
// ========================================================================

// 进程模块范围 + 元信息
struct ModRange {
    uintptr_t base;
    uintptr_t end;
    std::string name;    // 模块名（小写）
    bool isSystem;       // 是否位于 System32/SysWOW64/Windows 目录
};

/**
 * 枚举系统线程，检测远程注入线程（v2 调优版）
 *
 * 误报来源分析与处理：
 * 1. ASLR + 线程池: Windows 线程池线程(TppWorkerThread)入口在 ntdll.dll 内，
 *    若 EnumProcessModules 失败(无权限)会导致整个进程模块表为空 → 全部误报。
 *    处理: 无法枚举模块的进程降级处理，仅报 suspicious 而非 high。
 * 2. RtlUserThreadStart: 所有用户线程入口都是 ntdll 的 RtlUserThreadStart，
 *    它属于 ntdll.dll 模块范围 → 天然安全。
 * 3. 系统进程(System/smss/csrss): 无法 OpenProcess → 模块表空。
 *    处理: 白名单进程直接跳过。
 * 4. 真正可疑特征: 入口地址落在「匿名私有可执行内存」(MEM_PRIVATE+EXECUTE)，
 *    且不在任何已知模块内 → 这才是远程注入/Shellcode 的典型形态。
 */
extern "C" __declspec(dllexport) char* guard_inject_scan_threads() {
    // ---- 预取 ntdll 关键系统线程入口（所有进程共享这些地址） ----
    HMODULE hLocalNtdll = GetModuleHandleW(L"ntdll.dll");
    uintptr_t rtlUserThreadStart = 0, tppWorkerThread = 0, tppTimerpThread = 0;
    if (hLocalNtdll) {
        rtlUserThreadStart = (uintptr_t)GetProcAddress(hLocalNtdll, "RtlUserThreadStart");
        tppWorkerThread = (uintptr_t)GetProcAddress(hLocalNtdll, "TppWorkerThread");
        tppTimerpThread = (uintptr_t)GetProcAddress(hLocalNtdll, "TppTimerpThread");
    }

    // ---- 第一步：建立 {pid → 模块范围列表} 映射 ----
    HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnap == INVALID_HANDLE_VALUE)
        return alloc_str("{\"error\":\"snapshot failed\",\"threads\":[]}");

    std::map<DWORD, std::vector<ModRange>> processModules;
    std::set<DWORD> unreadableProcs;  // 无法读取模块的进程（降级处理）

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hProcSnap, &pe)) {
        do {
            if (pe.th32ProcessID == 0) continue;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (!hProc) { unreadableProcs.insert(pe.th32ProcessID); continue; }

            std::vector<ModRange> modRanges;
            HMODULE hMods[1024];
            DWORD cbNeeded = 0;
            if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
                DWORD numMods = cbNeeded / sizeof(HMODULE);
                if (numMods > 1024) numMods = 1024;
                for (DWORD i = 0; i < numMods; i++) {
                    MODULEINFO mi;
                    if (GetModuleInformation(hProc, hMods[i], &mi, sizeof(mi))) {
                        ModRange mr;
                        mr.base = (uintptr_t)mi.lpBaseOfDll;
                        mr.end = mr.base + mi.SizeOfImage;
                        // 获取模块名
                        wchar_t modPath[MAX_PATH_LEN];
                        if (GetModuleFileNameExW(hProc, hMods[i], modPath, MAX_PATH_LEN)) {
                            std::string p = wide_to_utf8(modPath);
                            size_t slash = p.rfind('\\');
                            mr.name = to_lower(slash != std::string::npos ? p.substr(slash + 1) : p);
                            mr.isSystem = is_system_path(p);
                        } else {
                            mr.name = "";
                            mr.isSystem = false;
                        }
                        modRanges.push_back(mr);
                    }
                }
            } else {
                unreadableProcs.insert(pe.th32ProcessID);
            }
            CloseHandle(hProc);
            processModules[pe.th32ProcessID] = modRanges;
        } while (Process32NextW(hProcSnap, &pe));
    }
    CloseHandle(hProcSnap);

    // ---- 第二步：枚举系统线程 ----
    HANDLE hThrSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThrSnap == INVALID_HANDLE_VALUE)
        return alloc_str("{\"error\":\"thread snapshot failed\",\"threads\":[]}");

    // 加载 NtQueryInformationThread 一次
    typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    auto NtQueryInformationThread = (pNtQueryInformationThread)
        GetProcAddress(hLocalNtdll, "NtQueryInformationThread");

    std::string json = "{\"threads\":[";
    bool first = true;
    int suspiciousThreads = 0;   // 高可疑
    int unknownThreads = 0;      // 无法判定（降级，不告警）
    int safeThreads = 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(hThrSnap, &te) && NtQueryInformationThread) {
        do {
            DWORD ownerPid = te.th32OwnerProcessID;
            if (ownerPid == 0) continue;

            // 系统关键进程白名单（无法读取模块，直接跳过）
            std::string ownerName = get_process_name_by_pid(ownerPid);
            std::string ownerLow = to_lower(ownerName);
            static const char* SYSTEM_PROC_WHITELIST[] = {
                "system", "system idle process", "smss.exe", "csrss.exe",
                "wininit.exe", "registry", "memory compression",
                nullptr
            };
            bool isSystemProc = false;
            for (int i = 0; SYSTEM_PROC_WHITELIST[i]; i++) {
                if (ownerLow == SYSTEM_PROC_WHITELIST[i]) { isSystemProc = true; break; }
            }
            if (isSystemProc) { safeThreads++; continue; }

            // 获取线程入口地址
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread) continue;

            PVOID startAddress = nullptr;
            ULONG retLen = 0;
            NTSTATUS status = NtQueryInformationThread(hThread, 0x09, &startAddress, sizeof(PVOID), &retLen);
            CloseHandle(hThread);
            if (status != 0 || startAddress == nullptr) continue;

            uintptr_t addr = (uintptr_t)startAddress;

            // ============ 判定逻辑 ============
            // 1) 已知 ntdll 系统线程入口（线程池/用户线程包装）→ 绝对安全
            if ((rtlUserThreadStart && addr == rtlUserThreadStart) ||
                (tppWorkerThread && addr == tppWorkerThread) ||
                (tppTimerpThread && addr == tppTimerpThread)) {
                safeThreads++;
                continue;
            }

            // 2) 模块范围匹配
            bool inModule = false;
            std::string moduleName;
            bool inSystemModule = false;
            auto it = processModules.find(ownerPid);
            if (it != processModules.end()) {
                for (auto& mr : it->second) {
                    if (addr >= mr.base && addr < mr.end) {
                        inModule = true;
                        moduleName = mr.name;
                        inSystemModule = mr.isSystem;
                        break;
                    }
                }
            }

            if (inModule) {
                safeThreads++;  // 入口在已加载模块内（含系统DLL/自身EXE）→ 安全
                continue;
            }

            // 3) 模块枚举失败的进程（无权限）→ 降级，不误报为可疑
            if (unreadableProcs.find(ownerPid) != unreadableProcs.end()) {
                unknownThreads++;
                continue;
            }

            // 4) 核心判断：入口地址所在内存区域类型
            //    只有「匿名私有 + 可执行」才是注入特征
            std::string regionType = "unknown";
            bool isExecutable = false;
            bool isPrivate = false;
            {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ownerPid);
                if (hProc) {
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) != 0) {
                        isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                        isPrivate = (mbi.Type == MEM_PRIVATE);
                        if (mbi.Type == MEM_PRIVATE) regionType = "PRIVATE";
                        else if (mbi.Type == MEM_IMAGE) regionType = "IMAGE";
                        else if (mbi.Type == MEM_MAPPED) regionType = "MAPPED";
                    }
                    CloseHandle(hProc);
                }
            }

            // 匿名私有可执行内存中的入口 → 真正的注入/Shellcode 特征
            if (isExecutable && isPrivate) {
                if (!first) json += ",";
                first = false;
                suspiciousThreads++;

                char buf[1024];
                snprintf(buf, sizeof(buf),
                    "{\"tid\":%lu,\"pid\":%lu,\"process\":\"%s\",\"start_addr\":\"0x%llX\","
                    "\"suspicious\":true,\"risk\":\"high\","
                    "\"reason\":\"anonymous_executable_memory\",\"region_type\":\"%s\"}",
                    te.th32ThreadID, ownerPid, json_escape(ownerName).c_str(),
                    (unsigned long long)addr, regionType.c_str());
                json += buf;
                continue;
            }

            // 5) 其余情况（IMAGE 区域未匹配模块 / 不可执行区域）→ 不告警，归入 safe
            safeThreads++;

        } while (Thread32Next(hThrSnap, &te));
    }

    CloseHandle(hThrSnap);

    json += "],\"total_suspicious\":" + std::to_string(suspiciousThreads);
    json += ",\"total_safe\":" + std::to_string(safeThreads);
    json += ",\"total_unknown\":" + std::to_string(unknownThreads);
    json += ",\"risk_level\":\"";
    if (suspiciousThreads > 0) json += "high";
    else json += "safe";
    json += "\"}";

    return alloc_str(json.c_str());
}

/**
 * 内存转储（Minidump）— 供 Python 层调用
 */
extern "C" __declspec(dllexport) int guard_inject_dump_memory(DWORD pid, const char* outputPath) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return -1;

    HANDLE hFile = CreateFileA(outputPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProc);
        return -2;
    }

    BOOL result = MiniDumpWriteDump(hProc, pid, hFile, MiniDumpWithDataSegs, nullptr, nullptr, nullptr);

    CloseHandle(hFile);
    CloseHandle(hProc);

    return result ? 0 : -3;
}
