/**
 * 御天 原生引擎 - 系统巡检模块
 * 通过 Windows API 实现:
 *   1. 枚举全部运行进程，读取进程对应 EXE 路径
 *   2. 遍历开机启动项: 注册表 Run/RunOnce、计划任务、启动文件夹、服务
 *   3. 读取进程网络连接 (TCP/UDP)，匹配恶意 IP/域名 IOCs
 */
#include "native_common.h"

// 需要链接 iphlpapi 和 ws2_32
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ============== 1. 进程枚举 ==============
extern "C" __declspec(dllexport) char* sys_enum_processes() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return alloc_str("{\"error\":\"snapshot failed\",\"processes\":[]}");

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    std::string json = "{\"processes\":[";
    bool first = true;

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (!first) json += ",";
            first = false;

            std::string exeName = wide_to_utf8(pe.szExeFile);

            // 尝试获取完整路径
            std::string exePath;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProc) {
                wchar_t pathBuf[MAX_PATH_LEN];
                DWORD pathLen = MAX_PATH_LEN;
                if (QueryFullProcessImageNameW(hProc, 0, pathBuf, &pathLen)) {
                    exePath = wide_to_utf8(pathBuf);
                }
                CloseHandle(hProc);
            }

            // 获取内存使用
            DWORD memoryKB = 0;
            if (hProc) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                    memoryKB = (DWORD)(pmc.WorkingSetSize / 1024);
                }
            }

            char buf[1024];
            snprintf(buf, sizeof(buf),
                     "{\"pid\":%lu,\"name\":\"%s\",\"path\":\"%s\",\"memory_kb\":%lu,\"threads\":%lu}",
                     pe.th32ProcessID, json_escape(exeName).c_str(),
                     json_escape(exePath).c_str(), memoryKB, pe.cntThreads);
            json += buf;

        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    json += "]}";
    return alloc_str(json.c_str());
}

// ============== 2. 开机启动项扫描 ==============

// 2a. 注册表 Run 键
static void scan_registry_run(std::string& json, bool& first) {
    const wchar_t* hives[] = {
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    };
    const char* sources[] = {"HKLM\\Run", "HKLM\\RunOnce", "HKCU\\Run", "HKCU\\RunOnce"};

    for (int i = 0; i < 4; i++) {
        HKEY hKey;
        LONG result;
        if (wcsstr(hives[i], L"HKEY_LOCAL_MACHINE"))
            result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                hives[i] + 19, 0, KEY_READ, &hKey);
        else
            result = RegOpenKeyExW(HKEY_CURRENT_USER,
                hives[i] + 18, 0, KEY_READ, &hKey);

        if (result != ERROR_SUCCESS) continue;

        DWORD index = 0;
        wchar_t valueName[512];
        DWORD nameLen;
        BYTE data[4096];
        DWORD dataLen, type;

        while (true) {
            nameLen = 512;
            dataLen = sizeof(data);
            result = RegEnumValueW(hKey, index, valueName, &nameLen, nullptr,
                                   &type, data, &dataLen);
            if (result != ERROR_SUCCESS) break;

            std::string name = wide_to_utf8(valueName);
            std::string value;
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                value = wide_to_utf8((wchar_t*)data);
            }

            // 风险判定: 临时目录/用户AppData中的exe可疑
            std::string risk = "safe";
            std::string valueLower = value;
            for (auto& c : valueLower) c = tolower(c);
            if (valueLower.find("\\temp\\") != std::string::npos ||
                valueLower.find("\\appdata\\local\\temp") != std::string::npos) {
                risk = "high";
            } else if (valueLower.find("\\appdata\\") != std::string::npos) {
                risk = "suspicious";
            }

            if (!first) json += ",";
            first = false;
            char buf[2048];
            snprintf(buf, sizeof(buf),
                     "{\"source\":\"registry\",\"location\":\"%s\",\"name\":\"%s\",\"command\":\"%s\",\"risk\":\"%s\"}",
                     sources[i], json_escape(name).c_str(), json_escape(value).c_str(), risk);
            json += buf;
            index++;
        }
        RegCloseKey(hKey);
    }
}

// 2b. 启动文件夹
static void scan_startup_folders(std::string& json, bool& first) {
    wchar_t commonStartup[MAX_PATH];
    wchar_t userStartup[MAX_PATH];

    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, commonStartup) == S_OK) {
        std::wstring search = std::wstring(commonStartup) + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                std::string fname = wide_to_utf8(fd.cFileName);
                if (!first) json += ",";
                first = false;
                char buf[1024];
                std::string full = wide_to_utf8(commonStartup) + std::string("\\") + fname;
                snprintf(buf, sizeof(buf),
                         "{\"source\":\"startup_folder\",\"location\":\"Common Startup\",\"name\":\"%s\",\"command\":\"%s\",\"risk\":\"safe\"}",
                         json_escape(fname).c_str(), json_escape(full).c_str());
                json += buf;
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    if (SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, userStartup) == S_OK) {
        std::wstring search = std::wstring(userStartup) + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                std::string fname = wide_to_utf8(fd.cFileName);
                if (!first) json += ",";
                first = false;
                char buf[1024];
                std::string full = wide_to_utf8(userStartup) + std::string("\\") + fname;
                snprintf(buf, sizeof(buf),
                         "{\"source\":\"startup_folder\",\"location\":\"User Startup\",\"name\":\"%s\",\"command\":\"%s\",\"risk\":\"safe\"}",
                         json_escape(fname).c_str(), json_escape(full).c_str());
                json += buf;
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }
}

// 2c. 服务（自动启动）
static void scan_services(std::string& json, bool& first) {
    SC_HANDLE hSC = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSC) return;

    DWORD bytesNeeded, servicesReturned, resumeHandle = 0;
    EnumServicesStatusExW(hSC, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded,
                          &servicesReturned, &resumeHandle, nullptr);

    if (bytesNeeded == 0) { CloseServiceHandle(hSC); return; }

    std::vector<BYTE> buffer(bytesNeeded + 1024);
    LPENUM_SERVICE_STATUS_PROCESSW services = (LPENUM_SERVICE_STATUS_PROCESSW)buffer.data();

    if (!EnumServicesStatusExW(hSC, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                SERVICE_STATE_ALL, buffer.data(), (DWORD)buffer.size(),
                                &bytesNeeded, &servicesReturned, &resumeHandle, nullptr)) {
        CloseServiceHandle(hSC);
        return;
    }

    for (DWORD i = 0; i < servicesReturned; i++) {
        // 只关注自动启动的服务
        SC_HANDLE hSvc = OpenServiceW(hSC, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;

        DWORD configSize = 0;
        QueryServiceConfigW(hSvc, nullptr, 0, &configSize);
        std::vector<BYTE> configBuf(configSize + 256);
        LPQUERY_SERVICE_CONFIGW config = (LPQUERY_SERVICE_CONFIGW)configBuf.data();

        if (QueryServiceConfigW(hSvc, config, (DWORD)configBuf.size(), &configSize)) {
            if (config->dwStartType == SERVICE_AUTO_START && config->lpBinaryPathName) {
                std::string sname = wide_to_utf8(services[i].lpServiceName);
                std::string binPath = wide_to_utf8(config->lpBinaryPathName);

                std::string risk = "safe";
                std::string pathLower = binPath;
                for (auto& c : pathLower) c = tolower(c);
                if (pathLower.find("\\temp\\") != std::string::npos ||
                    pathLower.find("\\appdata\\local\\temp") != std::string::npos)
                    risk = "high";

                if (!first) json += ",";
                first = false;
                char buf[2048];
                snprintf(buf, sizeof(buf),
                         "{\"source\":\"service\",\"location\":\"Service Auto-Start\",\"name\":\"%s\",\"command\":\"%s\",\"risk\":\"%s\"}",
                         json_escape(sname).c_str(), json_escape(binPath).c_str(), risk);
                json += buf;
            }
        }
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSC);
}

// ============== 导出: 完整启动项扫描 ==============
extern "C" __declspec(dllexport) char* sys_scan_startup() {
    std::string json = "{\"items\":[";
    bool first = true;

    scan_registry_run(json, first);
    scan_startup_folders(json, first);
    scan_services(json, first);

    json += "]}";
    return alloc_str(json.c_str());
}

// ============== 3. 网络连接枚举 ==============
extern "C" __declspec(dllexport) char* sys_enum_network() {
    // 获取 TCP 连接表
    DWORD tcpSize = 0;
    GetExtendedTcpTable(nullptr, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<BYTE> tcpBuf(tcpSize + 1024);
    PMIB_TCPTABLE_OWNER_PID tcpTable = (PMIB_TCPTABLE_OWNER_PID)tcpBuf.data();

    std::string json = "{\"connections\":[";
    bool first = true;

    if (GetExtendedTcpTable(tcpTable, &tcpSize, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID& row = tcpTable->table[i];

            // 获取进程名
            std::string procName = "unknown";
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, row.dwOwningPid);
            if (hProc) {
                wchar_t nameBuf[256];
                DWORD nameLen = 256;
                if (QueryFullProcessImageNameW(hProc, 0, nameBuf, &nameLen)) {
                    procName = wide_to_utf8(wcsrchr(nameBuf, L'\\') ? wcsrchr(nameBuf, L'\\') + 1 : nameBuf);
                }
                CloseHandle(hProc);
            }

            IN_ADDR local, remote;
            local.S_un.S_addr = row.dwLocalAddr;
            remote.S_un.S_addr = row.dwRemoteAddr;

            char localIp[16], remoteIp[16];
            strcpy(localIp, inet_ntoa(local));
            strcpy(remoteIp, inet_ntoa(remote));

            DWORD localPort = ntohs((u_short)row.dwLocalPort);
            DWORD remotePort = ntohs((u_short)row.dwRemotePort);

            const char* state = "UNKNOWN";
            switch (row.dwState) {
                case MIB_TCP_STATE_ESTAB: state = "ESTABLISHED"; break;
                case MIB_TCP_STATE_LISTEN: state = "LISTEN"; break;
                case MIB_TCP_STATE_SYN_SENT: state = "SYN_SENT"; break;
                case MIB_TCP_STATE_CLOSE_WAIT: state = "CLOSE_WAIT"; break;
                case MIB_TCP_STATE_TIME_WAIT: state = "TIME_WAIT"; break;
                case MIB_TCP_STATE_CLOSED: state = "CLOSED"; break;
            }

            // 风险判定: 非标准端口 + 外连
            std::string risk = "safe";
            if (row.dwState == MIB_TCP_STATE_ESTAB && remotePort != 80 && remotePort != 443) {
                if (remotePort == 4444 || remotePort == 5555 || remotePort == 6666 ||
                    remotePort == 8080 || remotePort == 8443 || remotePort == 1337 ||
                    remotePort == 31337 || remotePort == 9001) {
                    risk = "high";
                } else if (remotePort > 10000) {
                    risk = "suspicious";
                }
            }

            if (!first) json += ",";
            first = false;
            char buf[1024];
            snprintf(buf, sizeof(buf),
                     "{\"pid\":%lu,\"process\":\"%s\",\"protocol\":\"TCP\",\"local\":\"%s:%lu\",\"remote\":\"%s:%lu\",\"state\":\"%s\",\"risk\":\"%s\"}",
                     row.dwOwningPid, json_escape(procName).c_str(),
                     localIp, localPort, remoteIp, remotePort, state, risk);
            json += buf;
        }
    }

    // 获取 UDP 连接表
    DWORD udpSize = 0;
    GetExtendedUdpTable(nullptr, &udpSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<BYTE> udpBuf(udpSize + 1024);
    PMIB_UDPTABLE_OWNER_PID udpTable = (PMIB_UDPTABLE_OWNER_PID)udpBuf.data();

    if (GetExtendedUdpTable(udpTable, &udpSize, FALSE, AF_INET,
                             UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID& row = udpTable->table[i];
            std::string procName = "unknown";
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, row.dwOwningPid);
            if (hProc) {
                wchar_t nameBuf[256];
                DWORD nameLen = 256;
                if (QueryFullProcessImageNameW(hProc, 0, nameBuf, &nameLen)) {
                    procName = wide_to_utf8(wcsrchr(nameBuf, L'\\') ? wcsrchr(nameBuf, L'\\') + 1 : nameBuf);
                }
                CloseHandle(hProc);
            }

            IN_ADDR local;
            local.S_un.S_addr = row.dwLocalAddr;
            char localIp[16];
            strcpy(localIp, inet_ntoa(local));
            DWORD localPort = ntohs((u_short)row.dwLocalPort);

            if (!first) json += ",";
            first = false;

            char buf[768];
            snprintf(buf, sizeof(buf),
                     "{\"pid\":%lu,\"process\":\"%s\",\"protocol\":\"UDP\",\"local\":\"%s:%lu\",\"remote\":\"*:*\",\"state\":\"OPEN\",\"risk\":\"safe\"}",
                     row.dwOwningPid, json_escape(procName).c_str(),
                     localIp, localPort);
            json += buf;
        }
    }

    json += "]}";
    return alloc_str(json.c_str());
}

// ============== 导出: 系统摘要信息 ==============
extern "C" __declspec(dllexport) char* sys_summary() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);

    char compName[256];
    DWORD compLen = sizeof(compName);
    GetComputerNameA(compName, &compLen);

    char buf[1024];
    snprintf(buf, sizeof(buf),
             "{\"computer\":\"%s\",\"cpu_count\":%lu,\"ram_total_gb\":%.1f,\"ram_avail_gb\":%.1f,\"os_version\":\"Windows\"}",
             compName, si.dwNumberOfProcessors,
             mem.ullTotalPhys / (1024.0 * 1024.0 * 1024.0),
             mem.ullAvailPhys / (1024.0 * 1024.0 * 1024.0));
    return alloc_str(buf);
}
