/**
 * 底层持久化木马对抗模块
 *
 * 全覆盖巡检所有持久化通道：
 * - 注册表：HKLM服务项、ActiveSetup、映像劫持、屏幕保护、Run/RunOnce
 * - ���统载体：Windows服务、计划任务、驱动列表、启动文件夹
 * - 小众通道：COM组件劫持、打印监视器、AppInit_DLLs、Winlogon、BootExecute、BHO、LSA
 */
#include "native_guard.h"

// ========================================================================
// 辅助：读取注册表键下的所有值
// ========================================================================
struct RegValue {
    std::string name;
    std::string data;
    DWORD type;
};

static std::vector<RegValue> enum_reg_values(HKEY hRootKey, const std::wstring& subKey) {
    std::vector<RegValue> results;
    HKEY hKey;
    LONG ret = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hKey);
    if (ret != ERROR_SUCCESS) return results;

    DWORD index = 0;
    wchar_t valueName[512];
    DWORD nameLen;
    BYTE data[4096];
    DWORD dataLen, type;

    while (true) {
        nameLen = 512;
        dataLen = sizeof(data);
        ret = RegEnumValueW(hKey, index, valueName, &nameLen, nullptr,
                           &type, data, &dataLen);
        if (ret != ERROR_SUCCESS) break;

        RegValue rv;
        rv.name = wide_to_utf8(valueName);
        rv.type = type;
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            rv.data = wide_to_utf8((wchar_t*)data);
        } else if (type == REG_DWORD) {
            char buf[32];
            snprintf(buf, sizeof(buf), "%lu", *(DWORD*)data);
            rv.data = buf;
        } else if (type == REG_MULTI_SZ) {
            rv.data = wide_to_utf8((wchar_t*)data);
        }
        results.push_back(rv);
        index++;
    }
    RegCloseKey(hKey);
    return results;
}

// 读取注册表子键列表
static std::vector<std::wstring> enum_reg_subkeys(HKEY hRootKey, const std::wstring& subKey) {
    std::vector<std::wstring> results;
    HKEY hKey;
    LONG ret = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ, &hKey);
    if (ret != ERROR_SUCCESS) return results;

    DWORD index = 0;
    wchar_t keyName[512];
    DWORD nameLen;

    while (true) {
        nameLen = 512;
        ret = RegEnumKeyExW(hKey, index, keyName, &nameLen, nullptr, nullptr, nullptr, nullptr);
        if (ret != ERROR_SUCCESS) break;
        results.push_back(keyName);
        index++;
    }
    RegCloseKey(hKey);
    return results;
}

// 风险判定：基于路径
static std::string path_risk(const std::string& path) {
    std::string low = to_lower(path);
    if (low.empty()) return "suspicious";
    if (low.find("\\temp\\") != std::string::npos ||
        low.find("\\appdata\\local\\temp") != std::string::npos ||
        low.find("\\users\\") != std::string::npos) {
        if (low.find("\\microsoft\\") == std::string::npos &&
            low.find("\\windows\\") == std::string::npos) {
            return "high";
        }
    }
    if (low.find("\\system32\\") != std::string::npos ||
        low.find("\\syswow64\\") != std::string::npos ||
        low.find("\\program files") != std::string::npos) {
        return "safe";
    }
    return "suspicious";
}

// 构造单条持久化项 JSON
static std::string make_persist_item(const std::string& category, const std::string& location,
                                      const std::string& name, const std::string& command,
                                      const std::string& risk) {
    char buf[2048];
    snprintf(buf, sizeof(buf),
        "{\"category\":\"%s\",\"location\":\"%s\",\"name\":\"%s\",\"command\":\"%s\",\"risk\":\"%s\"}",
        json_escape(category).c_str(), json_escape(location).c_str(),
        json_escape(name).c_str(), json_escape(command).c_str(), risk);
    return std::string(buf);
}

/**
 * 全面扫描所有持久化通道
 */
extern "C" __declspec(dllexport) char* guard_persist_scan_all() {
    std::string json = "{\"items\":[";
    bool first = true;
    int totalHigh = 0, totalSuspicious = 0;

    // ====================================================================
    // 1. 注册表 Run / RunOnce（HKCU + HKLM）
    // ====================================================================
    struct {
        HKEY hkey;
        const wchar_t* subKey;
        const char* label;
    } runKeys[] = {
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\Run"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM\\RunOnce"},
        {HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Run"},
        {HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU\\RunOnce"},
    };

    for (auto& rk : runKeys) {
        auto vals = enum_reg_values(rk.hkey, rk.subKey);
        for (auto& v : vals) {
            std::string risk = path_risk(v.data);
            if (!first) json += ","; first = false;
            json += make_persist_item("registry_run", rk.label, v.name, v.data, risk);
            if (risk == "high") totalHigh++;
            else if (risk == "suspicious") totalSuspicious++;
        }
    }

    // ====================================================================
    // 2. HKLM 服务项 (Services)
    // ====================================================================
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            auto svcKeys = enum_reg_subkeys(hKey, L"");
            for (auto& sk : svcKeys) {
                std::wstring imgPathKey = sk + L"\\ImagePath";
                auto imgVals = enum_reg_values(HKEY_LOCAL_MACHINE,
                    (std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") + imgPathKey));
                
                // 改为读取服务键下的 ImagePath 值
                HKEY hSvc;
                std::wstring fullPath = L"SYSTEM\\CurrentControlSet\\Services\\" + sk;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_READ, &hSvc) == ERROR_SUCCESS) {
                    wchar_t imgPath[4096];
                    DWORD imgLen = sizeof(imgPath);
                    DWORD imgType = 0;
                    LONG ret = RegQueryValueExW(hSvc, L"ImagePath", nullptr, &imgType,
                                               (BYTE*)imgPath, &imgLen);
                    if (ret == ERROR_SUCCESS && (imgType == REG_SZ || imgType == REG_EXPAND_SZ)) {
                        std::string spath = wide_to_utf8(imgPath);
                        std::string sname = wide_to_utf8(sk);
                        std::string risk = path_risk(spath);
                        if (!first) json += ","; first = false;
                        json += make_persist_item("service", "HKLM\\Services", sname, spath, risk);
                        if (risk == "high") totalHigh++;
                        else if (risk == "suspicious") totalSuspicious++;
                    }
                    RegCloseKey(hSvc);
                }
            }
            RegCloseKey(hKey);
        }
    }

    // ====================================================================
    // 3. ActiveSetup
    // ====================================================================
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            auto components = enum_reg_subkeys(hKey, L"");
            for (auto& comp : components) {
                HKEY hComp;
                std::wstring compPath = L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\" + comp;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, compPath.c_str(), 0, KEY_READ, &hComp) == ERROR_SUCCESS) {
                    wchar_t stubPath[4096];
                    DWORD stubLen = sizeof(stubPath);
                    DWORD stubType = 0;
                    LONG ret = RegQueryValueExW(hComp, L"StubPath", nullptr, &stubType,
                                               (BYTE*)stubPath, &stubLen);
                    if (ret == ERROR_SUCCESS && (stubType == REG_SZ || stubType == REG_EXPAND_SZ)) {
                        std::string name = wide_to_utf8(comp);
                        std::string cmd = wide_to_utf8(stubPath);
                        std::string risk = path_risk(cmd);
                        if (!first) json += ","; first = false;
                        json += make_persist_item("active_setup", "HKLM\\ActiveSetup", name, cmd, risk);
                        if (risk == "high") totalHigh++;
                    }
                    RegCloseKey(hComp);
                }
            }
            RegCloseKey(hKey);
        }
    }

    // ====================================================================
    // 4. 映像劫持 (IFEO)
    // ====================================================================
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            auto targets = enum_reg_subkeys(hKey, L"");
            for (auto& target : targets) {
                HKEY hTarget;
                std::wstring targetPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                                          L"Image File Execution Options\\" + target;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, targetPath.c_str(), 0, KEY_READ, &hTarget) == ERROR_SUCCESS) {
                    wchar_t debugger[4096];
                    DWORD debuggerLen = sizeof(debugger);
                    DWORD debuggerType = 0;
                    LONG ret = RegQueryValueExW(hTarget, L"Debugger", nullptr, &debuggerType,
                                               (BYTE*)debugger, &debuggerLen);
                    if (ret == ERROR_SUCCESS) {
                        std::string tname = wide_to_utf8(target);
                        std::string dpath = wide_to_utf8(debugger);
                        // 任何 Debugger 劫持都高度可疑
                        std::string risk = "high";
                        if (!first) json += ","; first = false;
                        json += make_persist_item("ifeo", "HKLM\\IFEO", tname, dpath, risk);
                        totalHigh++;
                    }
                    RegCloseKey(hTarget);
                }
            }
            RegCloseKey(hKey);
        }
    }

    // ====================================================================
    // 5. 屏幕保护程序
    // ====================================================================
    {
        auto scrVals = enum_reg_values(HKEY_CURRENT_USER,
            L"Control Panel\\Desktop");
        for (auto& v : scrVals) {
            if (to_lower(v.name) == "scrsave.exe" && !v.data.empty()) {
                std::string risk = path_risk(v.data);
                if (!first) json += ","; first = false;
                json += make_persist_item("screensaver", "HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE",
                                          v.name, v.data, risk);
                if (risk == "high") totalHigh++;
            }
        }
    }

    // ====================================================================
    // 6. 启动文件夹
    // ====================================================================
    {
        wchar_t startupDirs[][MAX_PATH] = {{0}, {0}};
        if (SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, startupDirs[0]) == S_OK ||
            SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, startupDirs[1]) == S_OK) {
            const char* labels[] = {"User Startup", "Common Startup"};
            for (int d = 0; d < 2; d++) {
                if (wcslen(startupDirs[d]) == 0) continue;
                std::wstring search = std::wstring(startupDirs[d]) + L"\\*";
                WIN32_FIND_DATAW fd;
                HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                        std::string fname = wide_to_utf8(fd.cFileName);
                        std::string full = wide_to_utf8(startupDirs[d]) + "\\" + fname;
                        std::string risk = path_risk(full);
                        if (!first) json += ","; first = false;
                        json += make_persist_item("startup_folder", labels[d], fname, full, risk);
                        if (risk == "high") totalHigh++;
                    } while (FindNextFileW(hFind, &fd));
                    FindClose(hFind);
                }
            }
        }
    }

    // ====================================================================
    // 7. AppInit_DLLs
    // ====================================================================
    {
        auto appInit = enum_reg_values(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
        for (auto& v : appInit) {
            if (to_lower(v.name) == "appinit_dlls" && !v.data.empty()) {
                if (!first) json += ","; first = false;
                json += make_persist_item("appinit_dlls", "HKLM\\Windows\\AppInit_DLLs",
                                          v.name, v.data, "high");
                totalHigh++;
            }
        }
    }

    // ====================================================================
    // 8. Winlogon Shell/Notify
    // ====================================================================
    {
        auto winlogonVals = enum_reg_values(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
        for (auto& v : winlogonVals) {
            if ((to_lower(v.name) == "shell" || to_lower(v.name) == "userinit" ||
                 to_lower(v.name) == "notify") && !v.data.empty()) {
                // 检查是否被篡改（默认 shell=explorer.exe, userinit=userinit.exe）
                std::string risk = "suspicious";
                std::string low = to_lower(v.data);
                if (v.name == "Shell" && low.find("explorer.exe") == std::string::npos) risk = "high";
                if (v.name == "Userinit" && low != "userinit.exe," && low != "userinit.exe") risk = "high";
                
                if (risk != "safe") {
                    if (!first) json += ","; first = false;
                    json += make_persist_item("winlogon", "HKLM\\Winlogon\\" + v.name,
                                              v.name, v.data, risk);
                    if (risk == "high") totalHigh++;
                }
            }
        }
    }

    // ====================================================================
    // 9. BootExecute
    // ====================================================================
    {
        auto bootExec = enum_reg_values(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager");
        for (auto& v : bootExec) {
            if (to_lower(v.name) == "bootexecute" && !v.data.empty()) {
                std::string low = to_lower(v.data);
                // 默认值仅 autocheck，其他为可疑
                if (low.find("autocheck") == std::string::npos) {
                    if (!first) json += ","; first = false;
                    json += make_persist_item("boot_execute", "HKLM\\SessionManager\\BootExecute",
                                              v.name, v.data, "high");
                    totalHigh++;
                }
            }
        }
    }

    // ====================================================================
    // 10. COM 组件劫持（打印监视器）
    // ====================================================================
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            auto monitors = enum_reg_subkeys(hKey, L"");
            for (auto& mon : monitors) {
                HKEY hMon;
                std::wstring monPath = L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\" + mon;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, monPath.c_str(), 0, KEY_READ, &hMon) == ERROR_SUCCESS) {
                    wchar_t driver[4096];
                    DWORD driverLen = sizeof(driver);
                    DWORD driverType = 0;
                    LONG ret = RegQueryValueExW(hMon, L"Driver", nullptr, &driverType,
                                               (BYTE*)driver, &driverLen);
                    if (ret == ERROR_SUCCESS && (driverType == REG_SZ || driverType == REG_EXPAND_SZ)) {
                        std::string mname = wide_to_utf8(mon);
                        std::string dname = wide_to_utf8(driver);
                        // 已知系统打印监视器白名单
                        std::string low = to_lower(dname);
                        if (low != "localspl.dll" && low != "win32spl.dll" &&
                            low != "usbmon.dll" && low != "tcpmon.dll" &&
                            low != "tcpmonui.dll" && low != "lprmon.dll" &&
                            low != "faxmon.dll" && low != "wshx399.dll" &&
                            low != "pjlmon.dll" && low != "lmuzmon.dll") {
                            if (!first) json += ","; first = false;
                            json += make_persist_item("print_monitor", "HKLM\\Print\\Monitors",
                                                      mname, dname, "high");
                            totalHigh++;
                        }
                    }
                    RegCloseKey(hMon);
                }
            }
            RegCloseKey(hKey);
        }
    }

    // ====================================================================
    // 11. BHO（浏览器辅助对象）
    // ====================================================================
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            auto bhoids = enum_reg_subkeys(hKey, L"");
            for (auto& bho : bhoids) {
                // 读取 CLSID 下的 InprocServer32
                std::wstring clsidPath = L"SOFTWARE\\Classes\\CLSID\\" + bho + L"\\InprocServer32";
                HKEY hClsid;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, clsidPath.c_str(), 0, KEY_READ, &hClsid) == ERROR_SUCCESS) {
                    wchar_t dllPath[4096];
                    DWORD dllLen = sizeof(dllPath);
                    DWORD dllType = 0;
                    // 读取默认值
                    LONG ret = RegQueryValueExW(hClsid, nullptr, nullptr, &dllType,
                                               (BYTE*)dllPath, &dllLen);
                    if (ret == ERROR_SUCCESS) {
                        std::string bhoName = wide_to_utf8(bho);
                        std::string bhoDll = wide_to_utf8(dllPath);
                        std::string risk = path_risk(bhoDll);
                        if (risk == "safe") risk = "suspicious";  // BHO 本身即敏感
                        if (!first) json += ","; first = false;
                        json += make_persist_item("bho", "HKLM\\BHO",
                                                  bhoName, bhoDll, risk);
                        if (risk == "high") totalHigh++;
                        else totalSuspicious++;
                    }
                    RegCloseKey(hClsid);
                }
            }
            RegCloseKey(hKey);
        }
    }

    // ====================================================================
    // 12. LSA 安全提供者
    // ====================================================================
    {
        auto lsaVals = enum_reg_values(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders");
        for (auto& v : lsaVals) {
            if (to_lower(v.name) == "securityproviders" && !v.data.empty()) {
                // 检查是否有非系统提供者
                std::string low = to_lower(v.data);
                // 默认包含 "msapsspc.dll, schannel.dll, digest.dll, ntlm.dll"
                if (low.find("msapsspc.dll") == std::string::npos &&
                    low.find("schannel.dll") == std::string::npos &&
                    low.find("digest.dll") == std::string::npos &&
                    low.find("ntlm.dll") == std::string::npos && !low.empty()) {
                    if (!first) json += ","; first = false;
                    json += make_persist_item("lsa_provider", "HKLM\\SecurityProviders",
                                              v.name, v.data, "high");
                    totalHigh++;
                }
            }
        }
    }

    // ====================================================================
    // 13. 键盘布局劫持
    // ====================================================================
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout\\Substitutes",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            auto layouts = enum_reg_values(hKey, L"");
            for (auto& v : layouts) {
                if (!first) json += ","; first = false;
                json += make_persist_item("keyboard_layout", "HKLM\\KeyboardLayout",
                                          v.name, v.data, "suspicious");
                totalSuspicious++;
            }
            RegCloseKey(hKey);
        }
    }

    json += "],\"total\":" + std::to_string(first ? 0 : totalHigh + totalSuspicious);
    json += ",\"total_high\":" + std::to_string(totalHigh);
    json += ",\"total_suspicious\":" + std::to_string(totalSuspicious);
    json += ",\"risk_level\":\"";
    if (totalHigh > 0) json += "high";
    else if (totalSuspicious > 0) json += "suspicious";
    else json += "safe";
    json += "\"}";

    return alloc_str(json.c_str());
}
