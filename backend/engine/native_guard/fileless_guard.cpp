/**
 * 无文件攻击对抗模块
 *
 * 检测能力:
 * 1. 全进程命令行采集（NtQueryInformationProcess → PEB.CommandLine）
 * 2. LOLBins 监控：powershell/mshta/wmic/rundll32/cscript 的可疑执行
 * 3. WMI 事件消费者检测
 */
#include "native_guard.h"

// LOLBins 清单
struct LOLBinEntry {
    const char* procName;       // 进程名（小写）
    const char* description;    // 描述
};

static const LOLBinEntry LOLBINS[] = {
    {"powershell.exe",     "PowerShell 脚本主机"},
    {"pwsh.exe",           "PowerShell Core"},
    {"mshta.exe",          "HTA 脚本主机"},
    {"wmic.exe",           "WMI 命令行"},
    {"rundll32.exe",       "DLL 加载器"},
    {"cscript.exe",        "CScript 脚本主机"},
    {"wscript.exe",        "WScript 脚本主机"},
    {"regsvr32.exe",       "COM 注册工具"},
    {"certutil.exe",       "证书工具"},
    {"msiexec.exe",        "MSI 安装器"},
    {"bitsadmin.exe",      "BITS 管理工具"},
    {"cmstp.exe",          "连接管理器"},
    {"reg.exe",            "注册表控制台工具"},
    {"sc.exe",             "服务控制工具"},
    {"schtasks.exe",       "计划任务工具"},
    {nullptr, nullptr}
};

// LOLBins 可疑命令行特征
struct LOLBinPattern {
    const char* keyword;    // 特征关键词（小写）
    const char* description;
};

static const LOLBinPattern LOLBIN_PATTERNS[] = {
    {"-enc",                "Base64 编码执行 (PowerShell)"},
    {"-encodedcommand",     "Base64 编码命令 (PowerShell)"},
    {"-windowstyle hidden","隐藏窗口执行"},
    {"-w hidden",           "隐藏窗口（缩写）"},
    {"-nop",                "不加载配置文件"},
    {"-noprofile",          "不加载配置文件（全称）"},
    {"-e ",                 "Base64 简写"},
    {"frombase64string",    "Base64 解码 (C#/PowerShell)"},
    {"downloadstring",      "远程下载并执行 (Net.WebClient)"},
    {"invoke-expression",   "动态执行表达式"},
    {"iex(",                "Invoke-Expression 简写"},
    {"invoke-webrequest",   "远程 Web 请求"},
    {"iwr(",                "Invoke-WebRequest 简写"},
    {"start-process",       "启动新进程"},
    {"createobject",        "COM 对象创建"},
    {"xmlhttprequest",      "XMLHTTP 请求"},
    {"adodb.stream",        "ADO 数据流（常用于文件下载）"},
    {"wscript.shell",       "WScript.Shell COM"},
    {" shell",              "Shell 执行（rundll32）"},
    {nullptr, nullptr}
};

/**
 * 读取进程命令行
 * 优先使用 ProcessCommandLineInformation (NT API, Win8+),
 * 回退到 PEB 手动读取（兼容 Win7）
 */
static std::string get_process_cmdline(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return "";

    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
        HANDLE, DWORD, PVOID, ULONG, PULONG);

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) { CloseHandle(hProc); return ""; }

    auto NtQueryInformationProcess = (pNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) { CloseHandle(hProc); return ""; }

    // 方法1: ProcessCommandLineInformation (0x1E) — Win8+
    // 直接返回 UNICODE_STRING 包含命令行
    BYTE cmdBuf[4096];
    ULONG retLen = 0;
    NTSTATUS status = NtQueryInformationProcess(hProc, 0x3C, cmdBuf, sizeof(cmdBuf) - 2, &retLen);
    // 0x3C = ProcessCommandLineInformation (Win10 20H1+)
    
    if (status == 0 && retLen > sizeof(short)) {
        // 结果是一个 UNICODE_STRING: {USHORT Length, USHORT MaxLen, PWSTR Buffer}
        USHORT strLen = *(USHORT*)cmdBuf;
        if (strLen > 0 && strLen < MAX_CMD_LINE) {
            // Buffer 指针在偏移 8 (64-bit) 或 4 (32-bit)
            PWSTR buffer = nullptr;
#ifdef _WIN64
            buffer = *(PWSTR*)(cmdBuf + 8);
#else
            buffer = *(PWSTR*)(cmdBuf + 4);
#endif
            if (buffer) {
                std::wstring result(buffer, strLen / sizeof(wchar_t));
                CloseHandle(hProc);
                return wide_to_utf8(result);
            }
        }
    }

    // 方法2: 回退到 PEB 手动读取
    // PROCESS_BASIC_INFORMATION (info class 0)
    struct PBI {
        NTSTATUS ExitStatus;
        PVOID PebBaseAddress;
        ULONG_PTR AffinityMask;
        LONG BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    };

    PBI pbi;
    retLen = 0;
    status = NtQueryInformationProcess(hProc, 0, &pbi, sizeof(pbi), &retLen);
    if (status != 0 || !pbi.PebBaseAddress) { CloseHandle(hProc); return ""; }

    // 手动读取 PEB 结构中的 ProcessParameters
    // PEB offset: 0x020 (64-bit) or 0x010 (32-bit) → ProcessParameters
    BYTE pebBuf[256];
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProc, pbi.PebBaseAddress, pebBuf, sizeof(pebBuf), &bytesRead)) {
        CloseHandle(hProc);
        return "";
    }

    // ProcessParameters 指针在 PEB 中的偏移
    UINT_PTR ppOffset = 0;
#ifdef _WIN64
    ppOffset = 0x20;
#else
    ppOffset = 0x10;
#endif
    PVOID processParams = nullptr;
    memcpy(&processParams, pebBuf + ppOffset, sizeof(PVOID));
    if (!processParams) { CloseHandle(hProc); return ""; }

    // 读取 RTL_USER_PROCESS_PARAMETERS
    // CommandLine UNICODE_STRING 偏移: 0x80 (64-bit) or 0x40 (32-bit)
    BYTE paramsBuf[256];
    if (!ReadProcessMemory(hProc, processParams, paramsBuf, sizeof(paramsBuf), &bytesRead)) {
        CloseHandle(hProc);
        return "";
    }

    UINT_PTR cmdLineOffset = 0;
#ifdef _WIN64
    cmdLineOffset = 0x80;
#else
    cmdLineOffset = 0x40;
#endif

    // 读取 CommandLine UNICODE_STRING {Length, MaximumLength, Buffer}
    USHORT cmdLen = *(USHORT*)(paramsBuf + cmdLineOffset);
    // Buffer 指针偏移 8 (64-bit) 或 4 (32-bit)
    PWSTR cmdBuffer = nullptr;
#ifdef _WIN64
    cmdBuffer = *(PWSTR*)(paramsBuf + cmdLineOffset + 8);
#else
    cmdBuffer = *(PWSTR*)(paramsBuf + cmdLineOffset + 4);
#endif

    if (cmdBuffer && cmdLen > 0 && cmdLen < MAX_CMD_LINE) {
        std::wstring wcmd(cmdLen / sizeof(wchar_t), L'\0');
        if (ReadProcessMemory(hProc, cmdBuffer, &wcmd[0], cmdLen, &bytesRead)) {
            CloseHandle(hProc);
            return wide_to_utf8(wcmd);
        }
    }

    CloseHandle(hProc);
    return "";
}

/**
 * LOLBins 可疑特征检测（基于命令行）
 */
static std::vector<std::string> check_lolbin_patterns(const std::string& cmdline) {
    std::vector<std::string> matches;
    std::string low = to_lower(cmdline);
    
    for (int i = 0; LOLBIN_PATTERNS[i].keyword; i++) {
        if (low.find(LOLBIN_PATTERNS[i].keyword) != std::string::npos) {
            matches.push_back(LOLBIN_PATTERNS[i].description);
        }
    }
    
    return matches;
}

/**
 * 检测是否为 LOLBin 进程
 */
static bool is_lolbin(const std::string& procName) {
    std::string low = to_lower(procName);
    for (int i = 0; LOLBINS[i].procName; i++) {
        if (low == LOLBINS[i].procName) return true;
    }
    return false;
}

/**
 * 扫描所有进程命令行，检测 LOLBins 可疑执行
 * JSON: {"processes":[{...}], "total_suspicious": N}
 */
extern "C" __declspec(dllexport) char* guard_fileless_scan_cmdlines() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return alloc_str("{\"error\":\"snapshot failed\",\"processes\":[]}");

    std::string json = "{\"processes\":[";
    bool first = true;
    int suspiciousCount = 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == 0) continue;

            std::string procName = wide_to_utf8(pe.szExeFile);
            std::string cmdline = get_process_cmdline(pe.th32ProcessID);

            // 判断是否为 LOLBin
            bool lolbin = is_lolbin(procName);
            std::vector<std::string> patternHits;
            
            if (lolbin && !cmdline.empty()) {
                patternHits = check_lolbin_patterns(cmdline);
            }

            // 额外检测: 父进程可疑
            std::string parentName = get_process_name_by_pid(pe.th32ParentProcessID);
            
            // LOLBin 被非正常父进程启动（如 explorer → powershell 正常，
            // 但 notepad → powershell 可疑）
            bool suspiciousParent = false;
            if (lolbin && !cmdline.empty()) {
                std::string parentLow = to_lower(parentName);
                // 正常父进程白名单
                if (parentLow != "explorer.exe" && parentLow != "svchost.exe" &&
                    parentLow != "services.exe" && !parentLow.empty() &&
                    parentLow != "winlogon.exe" && parentLow != "taskhost.exe") {
                    suspiciousParent = true;
                }
            }

            bool isSuspicious = (!patternHits.empty()) || suspiciousParent;

            if (isSuspicious || lolbin) {
                if (!first) json += ",";
                first = false;

                // 构建匹配特征 JSON 数组
                std::string patternsJson = "[";
                for (size_t p = 0; p < patternHits.size(); p++) {
                    if (p > 0) patternsJson += ",";
                    patternsJson += "\"" + json_escape(patternHits[p]) + "\"";
                }
                patternsJson += "]";

                std::string risk = patternHits.size() > 2 ? "high" : 
                                   (patternHits.size() > 0 ? "suspicious" : "safe");

                char buf[4096];
                snprintf(buf, sizeof(buf),
                    "{\"pid\":%lu,\"name\":\"%s\",\"cmdline\":\"%s\",\"parent_pid\":%lu,"
                    "\"parent_name\":\"%s\",\"is_lolbin\":%s,\"risk\":\"%s\","
                    "\"patterns\":%s,\"suspicious_parent\":%s}",
                    pe.th32ProcessID, json_escape(procName).c_str(),
                    json_escape(cmdline).c_str(), pe.th32ParentProcessID,
                    json_escape(parentName).c_str(),
                    lolbin ? "true" : "false", risk,
                    patternsJson.c_str(), suspiciousParent ? "true" : "false");
                json += buf;

                if (isSuspicious) suspiciousCount++;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    json += "],\"total_processes\":" + std::to_string(first ? 0 : suspiciousCount);
    json += ",\"total_suspicious\":" + std::to_string(suspiciousCount) + "}";
    return alloc_str(json.c_str());
}

// ========================================================================
// 2. WMI 事件消费者检测
// ========================================================================

/**
 * 检测 WMI 持久化事件消费者
 * 通过 WMI COM API 枚举 __EventFilter 和 __CommandLineEventConsumer
 */
extern "C" __declspec(dllexport) char* guard_fileless_check_wmi() {
    std::string json = "{\"wmi_consumers\":[";
    bool first = true;
    int totalConsumers = 0;

    // 使用 WMI 查询
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        json += "],\"error\":\"COM init failed\",\"total\":0}";
        return alloc_str(json.c_str());
    }

    // 设置 COM 安全
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                               RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                               nullptr, EOAC_NONE, nullptr);

    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr) || !pLoc) {
        CoUninitialize();
        json += "],\"error\":\"WMI locator failed\",\"total\":0}";
        return alloc_str(json.c_str());
    }

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(BSTR(L"ROOT\\Subscription"), nullptr, nullptr, nullptr,
                              0, nullptr, nullptr, &pSvc);
    if (FAILED(hr) || !pSvc) {
        pLoc->Release();
        CoUninitialize();
        json += "],\"error\":\"WMI connect failed\",\"total\":0}";
        return alloc_str(json.c_str());
    }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                            nullptr, EOAC_NONE);
    if (SUCCEEDED(hr)) {
        // 查询 __EventFilter
        IEnumWbemClassObject* pEnum = nullptr;
        hr = pSvc->ExecQuery(BSTR(L"WQL"),
                              BSTR(L"SELECT * FROM __EventFilter"),
                              WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                              nullptr, &pEnum);
        if (SUCCEEDED(hr) && pEnum) {
            IWbemClassObject* pObj = nullptr;
            ULONG returned = 0;
            while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && returned > 0) {
                VARIANT vtName, vtQuery, vtQueryLang;
                VariantInit(&vtName);
                VariantInit(&vtQuery);
                VariantInit(&vtQueryLang);

                pObj->Get(L"Name", 0, &vtName, nullptr, nullptr);
                pObj->Get(L"Query", 0, &vtQuery, nullptr, nullptr);
                pObj->Get(L"QueryLanguage", 0, &vtQueryLang, nullptr, nullptr);

                std::string name = vtName.vt == VT_BSTR ? wide_to_utf8(vtName.bstrVal) : "";
                std::string query = vtQuery.vt == VT_BSTR ? wide_to_utf8(vtQuery.bstrVal) : "";
                std::string queryLang = vtQueryLang.vt == VT_BSTR ? wide_to_utf8(vtQueryLang.bstrVal) : "";

                // 风险判定：非微软签名的 EventFilter 可疑
                std::string risk = query.find("Scripting") != std::string::npos || 
                                   query.find("CommandLine") != std::string::npos ? "high" : "suspicious";

                if (!first) json += ",";
                first = false;
                totalConsumers++;

                char buf[2048];
                snprintf(buf, sizeof(buf),
                    "{\"type\":\"EventFilter\",\"name\":\"%s\",\"query\":\"%s\","
                    "\"query_lang\":\"%s\",\"risk\":\"%s\"}",
                    json_escape(name).c_str(), json_escape(query).c_str(),
                    json_escape(queryLang).c_str(), risk);
                json += buf;

                VariantClear(&vtName);
                VariantClear(&vtQuery);
                VariantClear(&vtQueryLang);
                pObj->Release();
            }
            pEnum->Release();
        }

        // 查询 __CommandLineEventConsumer
        hr = pSvc->ExecQuery(BSTR(L"WQL"),
                              BSTR(L"SELECT * FROM CommandLineEventConsumer"),
                              WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                              nullptr, &pEnum);
        if (SUCCEEDED(hr) && pEnum) {
            IWbemClassObject* pObj = nullptr;
            ULONG returned = 0;
            while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && returned > 0) {
                VARIANT vtName, vtCmd, vtKill;
                VariantInit(&vtName);
                VariantInit(&vtCmd);
                VariantInit(&vtKill);

                pObj->Get(L"Name", 0, &vtName, nullptr, nullptr);
                pObj->Get(L"CommandLineTemplate", 0, &vtCmd, nullptr, nullptr);
                pObj->Get(L"KillAfterTimeout", 0, &vtKill, nullptr, nullptr);

                std::string name = vtName.vt == VT_BSTR ? wide_to_utf8(vtName.bstrVal) : "";
                std::string cmd = vtCmd.vt == VT_BSTR ? wide_to_utf8(vtCmd.bstrVal) : "";

                // 任何 CommandLineEventConsumer 都高度可疑（极少合法使用）
                std::string risk = "high";

                if (!first) json += ",";
                first = false;
                totalConsumers++;

                char buf[2048];
                snprintf(buf, sizeof(buf),
                    "{\"type\":\"CommandLineEventConsumer\",\"name\":\"%s\","
                    "\"command_template\":\"%s\",\"risk\":\"%s\"}",
                    json_escape(name).c_str(), json_escape(cmd).c_str(), risk);
                json += buf;

                VariantClear(&vtName);
                VariantClear(&vtCmd);
                VariantClear(&vtKill);
                pObj->Release();
            }
            pEnum->Release();
        }

        // 查询 __ActiveScriptEventConsumer
        hr = pSvc->ExecQuery(BSTR(L"WQL"),
                              BSTR(L"SELECT * FROM ActiveScriptEventConsumer"),
                              WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                              nullptr, &pEnum);
        if (SUCCEEDED(hr) && pEnum) {
            IWbemClassObject* pObj = nullptr;
            ULONG returned = 0;
            while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && returned > 0) {
                VARIANT vtName, vtScript, vtEngine;
                VariantInit(&vtName);
                VariantInit(&vtScript);
                VariantInit(&vtEngine);

                pObj->Get(L"Name", 0, &vtName, nullptr, nullptr);
                pObj->Get(L"ScriptText", 0, &vtScript, nullptr, nullptr);
                pObj->Get(L"ScriptingEngine", 0, &vtEngine, nullptr, nullptr);

                std::string name = vtName.vt == VT_BSTR ? wide_to_utf8(vtName.bstrVal) : "";
                std::string script = vtScript.vt == VT_BSTR ? wide_to_utf8(vtScript.bstrVal) : "";
                std::string engine = vtEngine.vt == VT_BSTR ? wide_to_utf8(vtEngine.bstrVal) : "";

                std::string risk = "high";

                if (!first) json += ",";
                first = false;
                totalConsumers++;

                char buf[4096];
                snprintf(buf, sizeof(buf),
                    "{\"type\":\"ActiveScriptEventConsumer\",\"name\":\"%s\","
                    "\"script\":\"%s\",\"engine\":\"%s\",\"risk\":\"%s\"}",
                    json_escape(name).c_str(), json_escape(script).c_str(),
                    json_escape(engine).c_str(), risk);
                json += buf;

                VariantClear(&vtName);
                VariantClear(&vtScript);
                VariantClear(&vtEngine);
                pObj->Release();
            }
            pEnum->Release();
        }
    }

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    json += "],\"total\":" + std::to_string(totalConsumers) + "}";
    return alloc_str(json.c_str());
}
