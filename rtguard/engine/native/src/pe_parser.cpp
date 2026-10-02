/**
 * 御天 原生引擎 - PE 文件完整静态解析模块
 * 原生 C++ 解析 PE32/PE32+，提取：DOS头/NT头/节表/导入表/熵值/字符串
 * 不依赖 LIEF 等外部库，纯 Win32 API + 手写解析器
 */
#include "native_common.h"

// ============== 高危 API 列表（用于导入表威胁检测）==============
static const char* HIGH_RISK_APIS[] = {
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
    "SetWindowsHookEx", "NtSetContextThread", "NtQueueApcThread",
    "CreateProcess", "WinExec", "ShellExecute", "NtCreateProcess",
    "NtCreateProcessEx", "NtCreateUserProcess",
    "OpenProcess", "NtOpenProcess", "ReadProcessMemory",
    "AdjustTokenPrivileges", "LookupPrivilegeValue",
    "CryptEncrypt", "CryptDecrypt",
    "URLDownloadToFile", "InternetOpenUrl",
    "RegSetValueEx", "RegCreateKeyEx",
    "StartService", "ControlService", "CreateService",
    "NtQuerySystemInformation", "NtSetInformationProcess",
    "LsaLogonUser", "LsaLookupAuthenticationPackage",
    "SamConnect", "SamOpenDomain",
    "NtUnmapViewOfSection", "NtMapViewOfSection",
    "TerminateProcess", "NtTerminateProcess",
    "RtlDecompressBuffer", "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory", "NtProtectVirtualMemory",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugString",
    "SetThreadContext", "GetThreadContext",
};

static bool is_high_risk_api(const char* name) {
    int count = sizeof(HIGH_RISK_APIS) / sizeof(HIGH_RISK_APIS[0]);
    for (int i = 0; i < count; i++) {
        if (_stricmp(name, HIGH_RISK_APIS[i]) == 0)
            return true;
    }
    return false;
}

// ============== 文件熵值计算（Shannon entropy - 识别加壳程序）==============
static double calculate_entropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;
    unsigned int counts[ENTROPY_BUCKETS] = {0};
    for (size_t i = 0; i < size; i++)
        counts[data[i]]++;

    double entropy = 0.0;
    for (int i = 0; i < ENTROPY_BUCKETS; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / (double)size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// ============== 节名称解析 ==============
static std::string section_name(const BYTE* name) {
    char buf[9] = {0};
    size_t len = 0;
    for (int i = 0; i < IMAGE_SIZEOF_SHORT_NAME; i++) {
        if (name[i] >= 0x20 && name[i] <= 0x7E) {
            buf[len++] = name[i];
        }
    }
    buf[len] = '\0';
    return std::string(buf);
}

// ============== 节属性检测 ==============
// IMAGE_SCN_MEM_EXECUTE = 0x20000000
// IMAGE_SCN_MEM_READ    = 0x40000000
// IMAGE_SCN_MEM_WRITE   = 0x80000000
static bool section_is_rwx(uint32_t characteristics) {
    return (characteristics & 0x20000000) && (characteristics & 0x80000000);
}

static bool section_is_executable(uint32_t characteristics) {
    return (characteristics & 0x20000000) != 0;
}

static bool section_is_writable(uint32_t characteristics) {
    return (characteristics & 0x80000000) != 0;
}

// ============== 字符串提取（寻找 C2 域名、后门指令）==============
static std::vector<std::string> extract_strings(const uint8_t* data, size_t size, size_t minLen = 4) {
    std::vector<std::string> result;
    std::string current;
    for (size_t i = 0; i < size; i++) {
        uint8_t c = data[i];
        if (c >= 0x20 && c <= 0x7E) {
            current += (char)c;
        } else {
            if (current.size() >= minLen) {
                // 过滤纯数字
                bool hasAlpha = false;
                for (char ch : current) {
                    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        ch == '.' || ch == '/' || ch == '-' || ch == '_' || ch == ':') {
                        hasAlpha = true;
                        break;
                    }
                }
                if (hasAlpha) result.push_back(current);
            }
            current.clear();
        }
        if (result.size() >= 200) break; // 限制提取数量
    }
    // 最后一个字符串
    if (current.size() >= minLen && result.size() < 200) {
        bool hasAlpha = false;
        for (char ch : current) {
            if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                ch == '.' || ch == '/' || ch == '-' || ch == '_' || ch == ':') {
                hasAlpha = true;
                break;
            }
        }
        if (hasAlpha) result.push_back(current);
    }
    return result;
}

// ============== 查找 URL/域名模式 ==============
static std::vector<std::string> find_urls_and_domains(const std::vector<std::string>& strings) {
    std::vector<std::string> result;
    for (const auto& s : strings) {
        // 简单启发式：含 .com .net .org .cn .io 等且长度合理
        if (s.size() >= 5 && s.size() <= 128) {
            bool hasDot = false;
            for (char c : s) if (c == '.') { hasDot = true; break; }
            if (!hasDot) continue;

            // 检查已知 TLD 后缀
            const char* tlds[] = {".com", ".net", ".org", ".cn", ".io", ".top", ".xyz",
                                  ".ru", ".cc", ".pw", ".tk", ".ga", ".ml"};
            bool match = false;
            for (const char* tld : tlds) {
                size_t tldLen = strlen(tld);
                if (s.size() > tldLen && s.substr(s.size() - tldLen) == tld) {
                    match = true; break;
                }
            }
            if (match) result.push_back(s);
            if (result.size() >= 50) break;
        }
    }
    return result;
}

// ============== 导出: 完整 PE 解析（JSON 输出）==============
extern "C" __declspec(dllexport) char* pe_parse_full(const char* filepath_utf8) {
    std::wstring wpath = utf8_to_wide(filepath_utf8);
    HANDLE hFile = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::string err = "{\"error\":\"cannot open file\",\"path\":\"" + json_escape(filepath_utf8) + "\"}";
        return alloc_str(err.c_str());
    }

    // 获取文件大小
    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hFile);
        return alloc_str("{\"error\":\"file too small\",\"valid_pe\":false}");
    }

    // 内存映射
    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return alloc_str("{\"error\":\"mapping failed\",\"valid_pe\":false}");
    }

    uint8_t* base = (uint8_t*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return alloc_str("{\"error\":\"view failed\",\"valid_pe\":false}");
    }

    size_t fileSize = (size_t)liSize.QuadPart;

    std::string json;
    json = "{\"path\":\"" + json_escape(filepath_utf8) + "\",";
    json += "\"file_size\":" + std::to_string(fileSize) + ",";

    // ===== DOS 头 =====
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew >= fileSize) {
        json += "\"valid_pe\":false,\"error\":\"not a valid PE file\"}";
        UnmapViewOfFile(base);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return alloc_str(json.c_str());
    }

    json += "\"valid_pe\":true,";
    json += "\"dos_e_lfanew\":" + std::to_string(dos->e_lfanew) + ",";

    // ===== NT 头 =====
    uint32_t* ntSig = (uint32_t*)(base + dos->e_lfanew);
    if (*ntSig != IMAGE_NT_SIGNATURE) {
        json += "\"valid_pe\":false,\"error\":\"invalid NT signature\"}";
        UnmapViewOfFile(base);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return alloc_str(json.c_str());
    }

    IMAGE_FILE_HEADER* fileHeader = (IMAGE_FILE_HEADER*)(ntSig + 1);
    bool is64 = false;
    uint16_t optMagic = *(uint16_t*)(fileHeader + 1);

    if (optMagic == 0x20b) {
        is64 = true;
        IMAGE_OPTIONAL_HEADER64* opt64 = (IMAGE_OPTIONAL_HEADER64*)(fileHeader + 1);
        json += "\"pe_type\":\"PE32+\",";
        json += "\"entry_point\":" + std::to_string(opt64->AddressOfEntryPoint) + ",";
        json += "\"image_base\":" + std::to_string(opt64->ImageBase) + ",";
        json += "\"subsystem\":" + std::to_string(opt64->Subsystem) + ",";
        json += "\"dll_characteristics\":" + std::to_string(opt64->DllCharacteristics) + ",";
        json += "\"size_of_image\":" + std::to_string(opt64->SizeOfImage) + ",";
        json += "\"size_of_headers\":" + std::to_string(opt64->SizeOfHeaders) + ",";
        json += "\"section_alignment\":" + std::to_string(opt64->SectionAlignment) + ",";
        json += "\"file_alignment\":" + std::to_string(opt64->FileAlignment) + ",";
        json += "\"size_of_code\":" + std::to_string(opt64->SizeOfCode) + ",";
    } else if (optMagic == 0x10b) {
        IMAGE_OPTIONAL_HEADER32* opt32 = (IMAGE_OPTIONAL_HEADER32*)(fileHeader + 1);
        json += "\"pe_type\":\"PE32\",";
        json += "\"entry_point\":" + std::to_string(opt32->AddressOfEntryPoint) + ",";
        json += "\"image_base\":" + std::to_string(opt32->ImageBase) + ",";
        json += "\"subsystem\":" + std::to_string(opt32->Subsystem) + ",";
        json += "\"dll_characteristics\":" + std::to_string(opt32->DllCharacteristics) + ",";
        json += "\"size_of_image\":" + std::to_string(opt32->SizeOfImage) + ",";
        json += "\"size_of_headers\":" + std::to_string(opt32->SizeOfHeaders) + ",";
        json += "\"section_alignment\":" + std::to_string(opt32->SectionAlignment) + ",";
        json += "\"file_alignment\":" + std::to_string(opt32->FileAlignment) + ",";
        json += "\"size_of_code\":" + std::to_string(opt32->SizeOfCode) + ",";
    } else {
        json += "\"pe_type\":\"unknown\",";
    }

    json += "\"machine\":" + std::to_string(fileHeader->Machine) + ",";
    json += "\"number_of_sections\":" + std::to_string(fileHeader->NumberOfSections) + ",";
    json += "\"characteristics\":" + std::to_string(fileHeader->Characteristics) + ",";
    json += "\"time_date_stamp\":" + std::to_string(fileHeader->TimeDateStamp) + ",";

    // ===== 节表 =====
    size_t optSize = (optMagic == 0x20b) ? sizeof(IMAGE_OPTIONAL_HEADER64)
                   : (optMagic == 0x10b) ? sizeof(IMAGE_OPTIONAL_HEADER32)
                   : 0;
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((uint8_t*)(fileHeader + 1) + fileHeader->SizeOfOptionalHeader);

    json += "\"sections\":[";
    bool firstSection = true;
    int rwxCount = 0, highEntropyCount = 0, execCount = 0, writeCount = 0;
    double maxEntropy = 0.0;

    for (int i = 0; i < fileHeader->NumberOfSections && i < MAX_SECTIONS; i++) {
        IMAGE_SECTION_HEADER* sec = &sections[i];
        std::string sname = section_name(sec->Name);
        bool isRwx = section_is_rwx(sec->Characteristics);
        bool isExec = section_is_executable(sec->Characteristics);
        bool isWrite = section_is_writable(sec->Characteristics);

        if (isRwx) rwxCount++;
        if (isExec) execCount++;
        if (isWrite) writeCount++;

        // 计算节熵值
        double entropy = 0.0;
        if (sec->PointerToRawData > 0 && sec->SizeOfRawData > 0 &&
            sec->PointerToRawData + sec->SizeOfRawData <= fileSize) {
            entropy = calculate_entropy(base + sec->PointerToRawData, sec->SizeOfRawData);
            if (entropy > maxEntropy) maxEntropy = entropy;
            if (entropy > 7.0) highEntropyCount++;
        }

        if (!firstSection) json += ",";
        firstSection = false;
        char buf[1024];
        snprintf(buf, sizeof(buf),
                 "{\"name\":\"%s\",\"virtual_size\":%u,\"virtual_addr\":%u,\"raw_size\":%u,\"raw_offset\":%u,"
                 "\"rwx\":%s,\"exec\":%s,\"write\":%s,\"entropy\":%.2f}",
                 json_escape(sname).c_str(), sec->Misc.VirtualSize, sec->VirtualAddress,
                 sec->SizeOfRawData, sec->PointerToRawData,
                 isRwx ? "true" : "false", isExec ? "true" : "false", isWrite ? "true" : "false",
                 entropy);
        json += buf;
    }
    json += "],";

    json += "\"rwx_sections\":" + std::to_string(rwxCount) + ",";
    json += "\"exec_sections\":" + std::to_string(execCount) + ",";
    json += "\"high_entropy_sections\":" + std::to_string(highEntropyCount) + ",";
    json += "\"max_entropy\":" + std::to_string((int)(maxEntropy * 100) / 100.0) + ",";

    // ===== 导入表 =====
    json += "\"imports\":[";
    bool firstImport = true;
    int highRiskCount = 0;

    // 获取 IMAGE_DATA_DIRECTORY[1] (导入表)
    uint32_t importRva = 0, importSize = 0;
    if (optMagic == 0x20b) {
        IMAGE_OPTIONAL_HEADER64* opt64 = (IMAGE_OPTIONAL_HEADER64*)(fileHeader + 1);
        importRva = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else if (optMagic == 0x10b) {
        IMAGE_OPTIONAL_HEADER32* opt32 = (IMAGE_OPTIONAL_HEADER32*)(fileHeader + 1);
        importRva = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    if (importRva > 0 && importSize > 0) {
        // RVA -> file offset
        uint32_t importOffset = 0;
        for (int i = 0; i < fileHeader->NumberOfSections; i++) {
            if (importRva >= sections[i].VirtualAddress &&
                importRva < sections[i].VirtualAddress + (std::max)(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData)) {
                importOffset = importRva - sections[i].VirtualAddress + sections[i].PointerToRawData;
                break;
            }
        }

        if (importOffset > 0 && importOffset < fileSize) {
            IMAGE_IMPORT_DESCRIPTOR* impDesc = (IMAGE_IMPORT_DESCRIPTOR*)(base + importOffset);
            int impIdx = 0;

            while (impDesc->Name != 0 && impIdx < 256) {
                // 解析 DLL 名
                uint32_t nameOffset = 0;
                for (int i = 0; i < fileHeader->NumberOfSections; i++) {
                    if (impDesc->Name >= sections[i].VirtualAddress &&
                        impDesc->Name < sections[i].VirtualAddress + (std::max)(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData)) {
                        nameOffset = impDesc->Name - sections[i].VirtualAddress + sections[i].PointerToRawData;
                        break;
                    }
                }

                std::string dllName = "unknown";
                if (nameOffset > 0 && nameOffset < fileSize)
                    dllName = (const char*)(base + nameOffset);

                // 解析导入函数名
                std::string funcNames;
                bool firstFunc = true;
                // IMAGE_IMPORT_DESCRIPTOR has anonymous union for OriginalFirstThunk/Characteristics
                DWORD* pCharacteristics = (DWORD*)impDesc;
                uint32_t thunkRva = pCharacteristics[0] ? pCharacteristics[0] : impDesc->FirstThunk;

                uint32_t thunkOffset = 0;
                for (int i = 0; i < fileHeader->NumberOfSections; i++) {
                    if (thunkRva >= sections[i].VirtualAddress &&
                        thunkRva < sections[i].VirtualAddress + (std::max)(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData)) {
                        thunkOffset = thunkRva - sections[i].VirtualAddress + sections[i].PointerToRawData;
                        break;
                    }
                }

                if (thunkOffset > 0 && thunkOffset < fileSize) {
                    int funcCount = 0;
                    while (funcCount < 200) {
                        uint32_t* thunkData;
                        if (is64) {
                            uint64_t* t64 = (uint64_t*)(base + thunkOffset);
                            if (*t64 == 0) break;
                            thunkData = (uint32_t*)t64; // 简化处理
                        } else {
                            uint32_t* t32 = (uint32_t*)(base + thunkOffset);
                            if (*t32 == 0) break;
                            thunkData = t32;
                        }
                        
                        if (*thunkData & 0x80000000) {
                            // 按序号导入，跳过
                            thunkOffset += is64 ? 8 : 4;
                            funcCount++;
                            continue;
                        }

                        uint32_t hintRva = *thunkData & 0x7FFFFFFF;
                        uint32_t hintOffset = 0;
                        for (int i = 0; i < fileHeader->NumberOfSections; i++) {
                            if (hintRva >= sections[i].VirtualAddress &&
                                hintRva < sections[i].VirtualAddress + (std::max)(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData)) {
                                hintOffset = hintRva - sections[i].VirtualAddress + sections[i].PointerToRawData;
                                break;
                            }
                        }

                        if (hintOffset > 0 && hintOffset + 2 < fileSize) {
                            IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + hintOffset);
                            std::string funcName = ibn->Name;
                            if (!firstFunc) funcNames += ",";
                            firstFunc = false;
                            funcNames += "\"" + json_escape(funcName) + "\"";
                            if (is_high_risk_api(ibn->Name)) highRiskCount++;
                        }
                        thunkOffset += is64 ? 8 : 4;
                        funcCount++;
                    }
                }

                if (funcNames.size() > 0) {
                    if (!firstImport) json += ",";
                    firstImport = false;
                    json += "{\"dll\":\"" + json_escape(dllName) + "\",\"functions\":[" + funcNames + "]}";
                }

                impDesc++;
                impIdx++;
            }
        }
    }
    json += "],";
    json += "\"high_risk_api_count\":" + std::to_string(highRiskCount) + ",";
    json += "\"import_count\":" + std::to_string(highRiskCount) + ","; // 给Python看的简化字段

    // ===== 字符串提取 =====
    auto strings = extract_strings(base, fileSize);
    auto urls = find_urls_and_domains(strings);

    json += "\"extracted_urls\":[";
    for (size_t i = 0; i < urls.size(); i++) {
        if (i > 0) json += ",";
        json += "\"" + json_escape(urls[i]) + "\"";
    }
    json += "],";
    json += "\"extracted_strings_count\":" + std::to_string(strings.size()) + ",";
    json += "\"suspicious_urls_count\":" + std::to_string(urls.size()) + ",";

    // ===== 完整性 =====
    json += "\"has_signature\":false,\"signature_count\":0}";

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return alloc_str(json.c_str());
}

// ============== 导出: 快速 PE 校验（仅判断是否有效 PE）==============
extern "C" __declspec(dllexport) char* pe_quick_check(const char* filepath_utf8) {
    std::wstring wpath = utf8_to_wide(filepath_utf8);
    HANDLE hFile = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return alloc_str("{\"is_pe\":false,\"error\":\"open failed\"}");
    }

    IMAGE_DOS_HEADER dos;
    DWORD read;
    if (!ReadFile(hFile, &dos, sizeof(dos), &read, nullptr) || read != sizeof(dos)) {
        CloseHandle(hFile);
        return alloc_str("{\"is_pe\":false,\"error\":\"read failed\"}");
    }

    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        return alloc_str("{\"is_pe\":false,\"error\":\"not DOS\"}");
    }

    SetFilePointer(hFile, dos.e_lfanew, nullptr, FILE_BEGIN);
    uint32_t ntSig;
    if (!ReadFile(hFile, &ntSig, sizeof(ntSig), &read, nullptr) || ntSig != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        return alloc_str("{\"is_pe\":false,\"error\":\"not PE\"}");
    }

    IMAGE_FILE_HEADER fh;
    if (!ReadFile(hFile, &fh, sizeof(fh), &read, nullptr)) {
        CloseHandle(hFile);
        return alloc_str("{\"is_pe\":false,\"error\":\"no file header\"}");
    }

    uint16_t magic;
    ReadFile(hFile, &magic, sizeof(magic), &read, nullptr);

    char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"is_pe\":true,\"type\":\"%s\",\"machine\":%u,\"sections\":%u}",
             magic == 0x20b ? "PE32+" : "PE32",
             fh.Machine, fh.NumberOfSections);
    CloseHandle(hFile);
    return alloc_str(buf);
}
