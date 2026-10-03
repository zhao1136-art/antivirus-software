/**
 * ETW 多 Provider 检测规则模块（升级二）
 *
 * 各 Provider 事件的分析器 + 启发式检测规则：
 *   - Kernel-Process : 进程链 / DLL 侧加载 / 可疑可执行文件
 *   - DNS-Client     : DGA 域名 / NXDOMAIN 信标
 *   - PowerShell     : 混淆脚本块
 *   - WMI-Activity   : 无文件持久化消费者
 *   - DotNETRuntime  : 可疑托管程序集加载
 *   - Sysmon         : LSASS 凭据访问 / 命名管道 / DNS（联动）
 *   - Kernel-File    : 高危文件操作（卷影复制/临时目录可执行）
 *   - Kernel-Registry: 持久化注册表键写入
 *
 * 设计原则：
 *   - 全部防御性解析（越界即放弃），任何解析失败都不崩溃、不抛异常；
 *   - 对官方 manifest 不稳定的 Provider 采用“payload 子串扫描”启发式，
 *     不依赖脆弱的字段偏移，跨系统版本稳健；
 *   - 命中规则才入队，未命中一律丢弃，控制队列噪音。
 */
#include "etw_guard.h"
#include <list>

// 便捷赋值：EtwEvent.rule 为 char[80]，用宏替代直接数组赋值
#define SET_RULE(ev, r) do { snprintf((ev).rule, sizeof((ev).rule), "%s", (r)); } while (0)

// 供 ETW 篡改扫描判断“曾经启动过”的标志（etw_guard.cpp 维护）
extern bool g_etwEverStarted;

// ========================================================================
// 小工具
// ========================================================================

// 读取 payload 内某偏移处的 UNICODE_STRING（Length/Buffer 指针）
//
// 安全约束（这条曾经导致主进程被访问违例带走）：
//   Buffer 是 payload 里存着的一个**指针值**，不受本进程控制。ETW 事件里的
//   UNICODE_STRING 常常来自目标进程（见 KPROC_START_IMAGE_OFF /
//   KPROC_LOAD_IMAGE_OFF / 模块链等调用点），那个地址在我们进程里是野指针，
//   直接解引用必然 0xC0000005 —— 实测崩溃在本函数读 buf[i]，
//   native_guard.dll 偏移 0xa3b1，两次运行同一偏移。
//   原实现只做了 `if (!buf) return false;`，即只查了 NULL，从未校验指针指向哪里。
//   而 `strLen > len - off` 那个边界是错的：它假设字符串紧跟在描述符之后位于
//   payload 内，可字符串实际在 buf 指向的地址，所以那个检查给的是虚假安全感。
//
// 现在的策略：只接受「Buffer 落在 payload 自身范围内」这一种情形，
// 其余一律判为不可用并返回 false，**绝不解引用外部指针**。
// 代价是拿不到远程进程里的名字（退化为空），但绝不会再崩掉整个进程 ——
// 对防护软件来说，丢一个名字远好过把自己带走。
static bool read_unicode_string_at(const BYTE* data, DWORD len, DWORD off,
                                   char* out, DWORD outSize) {
    if (outSize) out[0] = 0;
    if (!data || !outSize) return false;
    if (off > len || len - off < 16) return false;      // 防 off+16 溢出
    USHORT strLen = *(USHORT*)(data + off);             // Length
    if (strLen == 0) return false;
#ifdef _WIN64
    const BYTE* bufRaw = *(const BYTE* const*)(data + off + 8);
#else
    const BYTE* bufRaw = *(const BYTE* const*)(data + off + 4);
#endif
    if (!bufRaw) return false;

    // —— 唯一安全的情形：Buffer 指向 payload 内部 ——
    if (bufRaw < data || bufRaw >= data + len) return false;
    DWORD pos = (DWORD)(bufRaw - data);
    if (strLen > len - pos) return false;               // 字符串本身也必须落在 payload 内

    const wchar_t* buf = (const wchar_t*)bufRaw;
    DWORD chars = strLen / 2;
    if (chars >= outSize) chars = outSize - 1;
    DWORD i = 0;
    for (; i < chars; i++) {
        wchar_t wc = buf[i];
        out[i] = (wc < 0x80) ? (char)wc : '?';
    }
    out[i] = 0;
    return true;
}

// 读取 payload 内某偏移处的空结尾 ASCII 字符串
static bool read_cstr_at(const BYTE* data, DWORD len, DWORD off,
                         char* out, DWORD outSize) {
    out[0] = 0;
    if (!data || off >= len) return false;
    DWORD i = 0;
    while (off + i < len && i < outSize - 1) {
        char c = (char)data[off + i];
        if (c == 0) { out[i] = 0; return true; }
        out[i] = (c >= 0x20) ? c : '?';
        i++;
    }
    out[i] = 0;
    return i > 0;
}

static inline bool contains_substr_l(const std::string& low, const char* sub) {
    return low.find(sub) != std::string::npos;
}

static std::string lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) c = (char)tolower((unsigned char)c);
    return r;
}

// 是否已知系统/可信目录（System32、Windows、Program Files、ProgramData、WindowsApps）
static bool is_known_system_path(const std::string& path) {
    std::string low = lower(path);
    static const char* subs[] = {
        "\\windows\\", "\\system32", "\\syswow64", "\\program files",
        "\\programdata\\", "\\windowsapps", "\\appdata\\local\\microsoft\\windows\\inetserver",
    };
    for (auto s : subs)
        if (contains_substr_l(low, s)) return true;
    return false;
}

// 可疑加载位置（临时/下载/公共/AppData 可写区）
static bool is_suspicious_location(const std::string& path) {
    std::string low = lower(path);
    static const char* subs[] = {
        "\\temp\\", "\\tmp\\", "\\downloads\\", "\\public\\",
        "\\appdata\\local\\temp", "\\appdata\\roaming\\",
        "\\programdata\\", "\\perflogs", "\\users\\public\\",
    };
    for (auto s : subs)
        if (contains_substr_l(low, s)) return true;
    return false;
}

// 文件签名校验（LRU 缓存，上限 512，防止重复 WinVerifyTrust）
static std::map<std::string, int> g_sigCache;
static std::list<std::string> g_sigOrder;
static const size_t SIG_CACHE_MAX = 512;

static bool verify_trusted(const char* pathUtf8) {
    std::wstring wpath = utf8_to_wide(pathUtf8);
    WINTRUST_FILE_INFO fi;
    memset(&fi, 0, sizeof(fi));
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = wpath.c_str();
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd;
    memset(&wd, 0, sizeof(wd));
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
    LONG res = WinVerifyTrust(nullptr, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);
    return res == ERROR_SUCCESS;
}

static bool is_signed_file_cached(const std::string& path) {
    std::string key = lower(path);
    auto it = g_sigCache.find(key);
    if (it != g_sigCache.end()) {
        // 刷新 LRU
        g_sigOrder.remove(key);
        g_sigOrder.push_back(key);
        return it->second == 1;
    }
    bool ok = verify_trusted(path.c_str());
    g_sigCache[key] = ok ? 1 : 0;
    g_sigOrder.push_back(key);
    while (g_sigOrder.size() > SIG_CACHE_MAX) {
        std::string oldest = g_sigOrder.front();
        g_sigOrder.pop_front();
        g_sigCache.erase(oldest);
    }
    return ok;
}

// ========================================================================
// DGA / C2 域名启发式
// ========================================================================
static bool looks_like_dga(const std::string& name) {
    if (name.empty() || name.size() < 8) return false;
    std::string h = lower(name);
    // 去掉末尾点
    while (!h.empty() && h.back() == '.') h.pop_back();
    if (h.size() < 8) return false;
    // 常见合法 TLD 白名单（基础）
    static const char* goodTlds[] = {
        ".com", ".net", ".org", ".cn", ".com.cn", ".net.cn", ".edu", ".gov",
        ".io", ".co", ".cc", ".tv", ".info", ".biz", ".me", ".top", ".xyz",
        ".online", ".site", ".store", ".vip", ".cloud", ".app", ".shop",
        ".microsoft.com", ".windowsupdate.com", ".microsoftonline.com",
        ".bing.com", ".qq.com", ".weixin.qq.com", ".baidu.com", ".aliyun.com",
        ".google.com", ".gstatic.com", ".googleapis.com", ".googlevideo.com",
        ".apple.com", ".icloud.com", ".office.com", ".live.com", ".msn.com",
        ".azure.com", ".azureedge.net", ".akamai.net", ".cloudflare.com",
        ".cloudfront.net", ".amazonaws.com", ".jd.com", ".taobao.com",
        ".360.cn", ".xiaomi.com", ".huawei.com", ".bytedance.com",
        ".douyin.com", ".tiktok.com", ".feishu.cn", ".larksuite.com",
    };
    for (auto t : goodTlds) {
        size_t pos = h.rfind(t);
        if (pos != std::string::npos && pos + strlen(t) == h.size()) return false;
    }
    // 字符多样性 + 数字 + 标签数
    std::set<char> distinct;
    int digits = 0, labels = 1;
    for (char c : h) {
        if (c == '.') labels++;
        else {
            distinct.insert(c);
            if (c >= '0' && c <= '9') digits++;
        }
    }
    size_t n = h.size();
    double entropy = (double)distinct.size() / (double)n;
    bool longName = n >= 18;
    bool highEntropy = entropy > 0.45;
    bool manyDigits = digits >= 3;
    bool manyLabels = labels >= 4;
    if (longName && highEntropy && manyDigits) return true;
    if (manyLabels && highEntropy && longName) return true;
    if (longName && manyDigits && manyLabels) return true;
    return false;
}

// ========================================================================
// 子串扫描：Payload 内标记检测（用于无 manifest 依赖的启发式）
// ========================================================================
static bool scan_markers(const BYTE* data, DWORD len, const char* const* markers,
                         int n, char* context, DWORD ctxSize) {
    if (!data || !len) return false;
    for (int i = 0; i < n; i++) {
        size_t ml = strlen(markers[i]);
        if (!ml) continue;
        // 以 ASCII 方式扫描
        for (DWORD p = 0; p + ml <= len; p++) {
            if (data[p] == (BYTE)markers[i][0] &&
                memcmp(data + p, markers[i], ml) == 0) {
                if (context && ctxSize) {
                    DWORD start = p > 100 ? p - 100 : 0;
                    DWORD end = p + ml + 160;
                    if (end > len) end = len;
                    DWORD out = 0;
                    for (DWORD j = start; j < end && out + 1 < ctxSize; j++) {
                        char c = (char)data[j];
                        if (c == 0) break;
                        if (c < 0x20) c = ' ';
                        context[out++] = c;
                    }
                    context[out] = 0;
                }
                return true;
            }
        }
    }
    return false;
}

// ========================================================================
// Threat-Intelligence 分析器（保留原有逻辑 + 补充规则）
// ========================================================================
bool analyze_ti(const EVENT_RECORD* rec, EtwEvent& ev) {
    const BYTE* userData = (const BYTE*)rec->UserData;
    DWORD userLen = rec->UserDataLength;
    if (!userData || userLen < 12) return false;

    ev.sourcePid = *(DWORD*)(userData + 0);
    ev.targetPid = *(DWORD*)(userData + 8);
    if (userLen >= 24) {
        ULONG64 startAddr = 0;
        memcpy(&startAddr, userData + 16, sizeof(ULONG64));
        snprintf(ev.detail, sizeof(ev.detail), "start=0x%llX", (unsigned long long)startAddr);
    }
    if (userLen >= 32)
        read_unicode_string_at(userData, userLen, 32, ev.imageName, sizeof(ev.imageName));

    switch (ev.eventId) {
        case 3:  // DriverLoad（记录但不告警）
            return false;
        case 4:  // ProcessInjection
            SET_RULE(ev, "TI_PROCESS_INJECTION");
            ev.severity = 3;
            break;
        case 5:  // ProcessTampering
            SET_RULE(ev, "TI_PROCESS_TAMPERING");
            ev.severity = 3;
            break;
        case 9:  // RemoteThreadCreated
            if (ev.sourcePid != ev.targetPid && ev.sourcePid != 0 && ev.targetPid != 0) {
                SET_RULE(ev, "TI_REMOTE_THREAD");
                ev.severity = 3;
            } else {
                return false;
            }
            break;
        case 12: // WriteProcessMemory（跨进程写内存）
            if (ev.sourcePid != ev.targetPid && ev.sourcePid && ev.targetPid) {
                SET_RULE(ev, "TI_WRITE_PROC_MEMORY");
                ev.severity = 3;
            } else {
                return false;
            }
            break;
        case 13: // QueueUserAPC
            if (ev.sourcePid != ev.targetPid && ev.sourcePid && ev.targetPid) {
                SET_RULE(ev, "TI_QUEUE_APC");
                ev.severity = 3;
            } else {
                return false;
            }
            break;
        case 14: // MapViewOfSection (进程间映射 = 无文件注入)
            if (ev.sourcePid != ev.targetPid && ev.sourcePid && ev.targetPid) {
                SET_RULE(ev, "TI_MAP_VIEW_SECTION");
                ev.severity = 3;
            } else {
                return false;
            }
            break;
        case 10: // SetThreadContext
        case 11: // ReadProcessMemory
            if (ev.sourcePid != ev.targetPid && ev.sourcePid && ev.targetPid) {
                SET_RULE(ev, (ev.eventId == 10) ? "TI_SET_THREAD_CONTEXT" : "TI_READ_PROC_MEMORY");
                ev.severity = 2;
            } else {
                return false;
            }
            break;
        default:
            if (ev.sourcePid != ev.targetPid && ev.sourcePid && ev.targetPid) {
                SET_RULE(ev, "TI_UNKNOWN_ATTACK");
                ev.severity = 2;
            } else {
                return false;
            }
            break;
    }
    ev.suspicious = true;
    return true;
}

// ========================================================================
// Kernel-Process 分析器（进程链 / DLL 侧加载）
// ========================================================================
#ifdef _WIN64
#define KPROC_START_IMAGE_OFF 0x20
#define KPROC_START_CMD_OFF   0x30
#define KPROC_LOAD_IMAGE_OFF  0x28
#define KPROC_LOAD_PID_OFF    0x20
#else
#define KPROC_START_IMAGE_OFF 0x18
#define KPROC_START_CMD_OFF   0x20
#define KPROC_LOAD_IMAGE_OFF  0x1C
#define KPROC_LOAD_PID_OFF    0x18
#endif

bool analyze_kproc(const EVENT_RECORD* rec, EtwEvent& ev) {
    const BYTE* d = (const BYTE*)rec->UserData;
    DWORD len = rec->UserDataLength;
    if (!d || len < 16) return false;

    if (ev.eventId == 2) {  // ProcessEnd：清理进程表
        DWORD pid = *(DWORD*)(d + 0);
        proc_table_remove(pid);
        return false;
    }

    if (ev.eventId == 1) {  // ProcessStart
        DWORD pid = *(DWORD*)(d + 0);
        DWORD parent = *(DWORD*)(d + 4);
        char image[MAX_PATH_LEN] = {0}, name[128] = {0}, cmd[MAX_CMD_LINE] = {0};
        read_unicode_string_at(d, len, KPROC_START_IMAGE_OFF, image, sizeof(image));
        read_unicode_string_at(d, len, KPROC_START_CMD_OFF, cmd, sizeof(cmd));
        const char* base = strrchr(image, '\\');
        snprintf(name, sizeof(name), "%s", base ? base + 1 : image);

        ev.sourcePid = parent;
        ev.targetPid = pid;
        ev.parentPid = parent;
        snprintf(ev.image, sizeof(ev.image), "%s", image);
        snprintf(ev.imageName, sizeof(ev.imageName), "%s", name);

        // 更新进程表
        proc_table_update(pid, parent, image, name, cmd);

        std::string n = lower(name);
        std::string cl = lower(cmd);
        std::string ip = lower(image);

        // 1) Office 文档进程派生脚本解释器（钓鱼/宏）
        static const char* office[] = {"winword", "excel", "powerpnt", "outlook", "visio"};
        static const char* scriptKiddie[] = {
            "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta",
            "regsvr32", "rundll32", "bitsadmin", "certutil", "msiexec",
            "wmic", "forfiles", "scrcons", "psexec",
        };
        bool fromOffice = false;
        for (auto o : office)
            if (contains_substr_l(ip, o)) { fromOffice = true; break; }
        if (fromOffice) {
            for (auto s : scriptKiddie)
                if (contains_substr_l(n, s)) {
                    SET_RULE(ev, "OFFICE_SPAWNS_SCRIPT");
                    ev.severity = 3;
                    ev.suspicious = true;
                    proc_table_add_score(pid, 30);
                    proc_table_add_score(parent, 20);
                    return true;
                }
        }

        // 2) 脚本解释器派生脚本解释器（脚本链，如 cmd→powershell）
        static const char* scriptInterp[] = {"powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta"};
        ProcInfo pinfo;
        bool parentScript = false;
        if (proc_table_lookup(parent, pinfo)) {
            std::string pn = lower(pinfo.name);
            for (auto s : scriptInterp)
                if (contains_substr_l(pn, s)) { parentScript = true; break; }
        }
        if (parentScript) {
            for (auto s : scriptInterp)
                if (contains_substr_l(n, s)) {
                    SET_RULE(ev, "SCRIPT_CHAIN");
                    ev.severity = 2;
                    ev.suspicious = true;
                    proc_table_add_score(pid, 20);
                    return true;
                }
        }

        // 3) 编码/混淆命令行（-enc、base64、FromBase64）
        if (contains_substr_l(cl, "-enc") || contains_substr_l(cl, "encodedcommand") ||
            contains_substr_l(cl, "frombase64") || contains_substr_l(cl, " -e ") ||
            contains_substr_l(cl, "enc;")) {
            if (contains_substr_l(n, "powershell") || contains_substr_l(n, "cmd") ||
                contains_substr_l(n, "wscript") || contains_substr_l(n, "cscript")) {
                SET_RULE(ev, "ENCODED_CMDLINE");
                ev.severity = 3;
                ev.suspicious = true;
                snprintf(ev.detail, sizeof(ev.detail), "%.300s", cmd);
                proc_table_add_score(pid, 35);
                return true;
            }
        }

        // 4) 临时目录中的可执行（下载落地执行）
        if (is_suspicious_location(ip)) {
            std::string ext = get_ext(ip);
            if (ext == ".exe" || ext == ".dll" || ext == ".scr" || ext == ".bat" ||
                ext == ".vbs" || ext == ".js" || ext == ".ps1" || ext == ".lnk") {
                bool signedFile = is_signed_file_cached(ip);
                if (!signedFile || contains_substr_l(ip, "\\temp\\") ||
                    contains_substr_l(ip, "\\downloads\\")) {
                    SET_RULE(ev, "SUSPICIOUS_EXEC_LOCATION");
                    ev.severity = 2;
                    ev.suspicious = true;
                    proc_table_add_score(pid, 20);
                    return true;
                }
            }
        }

        // 5) 系统进程异常派生脚本（svchost/系统派生 powershell）
        if (parent == 4 || contains_substr_l(ip, "svchost")) {
            for (auto s : scriptKiddie)
                if (contains_substr_l(n, s)) {
                    SET_RULE(ev, "SVC_HOST_SPAWNS_SCRIPT");
                    ev.severity = 3;
                    ev.suspicious = true;
                    proc_table_add_score(pid, 40);
                    return true;
                }
        }
        return false;
    }

    if (ev.eventId == 5) {  // ImageLoad → DLL 侧加载检测
        DWORD pid = *(DWORD*)(d + KPROC_LOAD_PID_OFF);
        char image[MAX_PATH_LEN] = {0};
        read_unicode_string_at(d, len, KPROC_LOAD_IMAGE_OFF, image, sizeof(image));
        const char* base = strrchr(image, '\\');
        char name[128] = {0};
        snprintf(name, sizeof(name), "%s", base ? base + 1 : image);

        ev.targetPid = pid;
        snprintf(ev.image, sizeof(ev.image), "%s", image);
        snprintf(ev.imageName, sizeof(ev.imageName), "%s", name);

        std::string ip = lower(image);
        std::string ext = get_ext(ip);

        // 只关注 DLL 与高危可执行
        if (ext != ".dll" && ext != ".exe" && ext != ".sys") return false;

        // 系统路径且签名 → 直接放行（海量正常模块）
        bool sysPath = is_known_system_path(ip);
        bool suspiciousLoc = is_suspicious_location(ip);
        if (sysPath && !suspiciousLoc) return false;

        bool signedFile = is_signed_file_cached(ip);
        if (!signedFile || suspiciousLoc) {
            SET_RULE(ev, "DLL_SIDELOAD");
            ev.severity = 2;
            ev.suspicious = true;
            proc_table_add_score(pid, 25);
            return true;
        }
    }
    return false;
}

// ========================================================================
// DNS-Client 分析器（DGA / NXDOMAIN 信标）
// ========================================================================
static std::map<DWORD, int> g_dnsNx;       // pid → NXDOMAIN 计数
static std::map<DWORD, bool> g_dnsBeaconed; // pid → 是否已告警信标

bool analyze_dns(const EVENT_RECORD* rec, EtwEvent& ev) {
    const BYTE* d = (const BYTE*)rec->UserData;
    DWORD len = rec->UserDataLength;
    if (!d || len < 2) return false;

    ev.sourcePid = rec->EventHeader.ProcessId;
    char qname[300] = {0};
    // QueryName 通常为固定 256 字节 ASCII 数组
    if (len >= 260) {
        read_cstr_at(d, 260, 0, qname, sizeof(qname));
    } else {
        read_cstr_at(d, len, 0, qname, sizeof(qname));
    }
    if (qname[0] == 0) return false;
    // 清理引号/括号
    char clean[300] = {0};
    DWORD ci = 0;
    for (DWORD i = 0; qname[i] && ci + 1 < sizeof(clean); i++) {
        char c = qname[i];
        if (c == '"' || c == '\'' || c == '(' || c == ')') continue;
        clean[ci++] = c;
    }
    clean[ci] = 0;
    snprintf(ev.detail, sizeof(ev.detail), "%s", clean);

    bool nxdomain = (ev.eventId == 3010);
    bool query = (ev.eventId == 3006 || ev.eventId == 3008 || ev.eventId == 3020 ||
                  ev.eventId == 3021 || ev.eventId == 3010);

    if (query && looks_like_dga(clean)) {
        SET_RULE(ev, "DGA_DOMAIN");
        ev.severity = 2;
        ev.suspicious = true;
        proc_table_add_score(ev.sourcePid, 20);
        return true;
    }

    // NXDOMAIN 洪水 → C2 信标/域名生成探测
    if (nxdomain) {
        int cnt = (g_dnsNx[ev.sourcePid] += 1);
        if (cnt >= 20 && !g_dnsBeaconed[ev.sourcePid]) {
            g_dnsBeaconed[ev.sourcePid] = true;
            g_dnsNx[ev.sourcePid] = 0;
            SET_RULE(ev, "DNS_NXDOMAIN_BEACON");
            ev.severity = 2;
            ev.suspicious = true;
            snprintf(ev.detail, sizeof(ev.detail), "NXDOMAIN 连续 %d 次 (最近: %s)", cnt, clean);
            proc_table_add_score(ev.sourcePid, 25);
            return true;
        }
    }
    return false;
}

// ========================================================================
// PowerShell 分析器（混淆脚本块，需已开启脚本块日志）
// ========================================================================
bool analyze_powershell(const EVENT_RECORD* rec, EtwEvent& ev) {
    if (ev.eventId != 4104) return false;   // ScriptBlock Created
    const BYTE* d = (const BYTE*)rec->UserData;
    DWORD len = rec->UserDataLength;
    if (!d || len < 8) return false;
    ev.sourcePid = rec->EventHeader.ProcessId;

    static const char* psMarkers[] = {
        "frombase64string", "invoke-expression", "iex", "-enc ",
        "-encodedcommand", "[reflection.assembly]::load", "downloadstring",
        "net.webclient", "downloaddata", "mimikatz", "nishang",
        "start-process", "wscript.shell", "netsh advfirewall",
        "new-object system.net.sockets.tcpclient", "sendkeys",
        "reg add", "schtasks", "amsiutils", "amsi",
    };
    char ctx[400] = {0};
    if (scan_markers(d, len, psMarkers, (int)(sizeof(psMarkers) / sizeof(psMarkers[0])),
                     ctx, sizeof(ctx))) {
        SET_RULE(ev, "PS_OBFUSCATED_SCRIPT");
        ev.severity = 3;
        ev.suspicious = true;
        snprintf(ev.detail, sizeof(ev.detail), "%.360s", ctx);
        proc_table_add_score(ev.sourcePid, 40);
        return true;
    }
    return false;
}

// ========================================================================
// WMI-Activity 分析器（无文件持久化消费者）
// ========================================================================
bool analyze_wmi(const EVENT_RECORD* rec, EtwEvent& ev) {
    if (ev.eventId != 5857 && ev.eventId != 5861 && ev.eventId != 5860 &&
        ev.eventId != 5862) return false;
    const BYTE* d = (const BYTE*)rec->UserData;
    DWORD len = rec->UserDataLength;
    if (!d || len < 8) return false;
    ev.sourcePid = rec->EventHeader.ProcessId;

    static const char* wmiMarkers[] = {
        "activescripteventconsumer", "commandlineeventconsumer",
        "__eventfilter", "eventconsumer", "processstartup",
        "mof", "wmic", "root\\subscription",
    };
    char ctx[400] = {0};
    if (scan_markers(d, len, wmiMarkers, (int)(sizeof(wmiMarkers) / sizeof(wmiMarkers[0])),
                     ctx, sizeof(ctx))) {
        SET_RULE(ev, "WMI_PERSISTENCE");
        ev.severity = 3;
        ev.suspicious = true;
        snprintf(ev.detail, sizeof(ev.detail), "%.360s", ctx);
        proc_table_add_score(ev.sourcePid, 45);
        return true;
    }
    return false;
}

// ========================================================================
// DotNETRuntime 分析器（可疑托管程序集加载）
// ========================================================================
bool analyze_dotnet(const EVENT_RECORD* rec, EtwEvent& ev) {
    if (ev.eventId != 154 && ev.eventId != 152) return false; // ModuleLoad
    const BYTE* d = (const BYTE*)rec->UserData;
    DWORD len = rec->UserDataLength;
    if (!d || len < 24) return false;
    ev.sourcePid = rec->EventHeader.ProcessId;

    // ModuleLoad 布局：ModuleID(8) AssemblyID(8) ModuleFlags(4) Reserved(4) 然后 ModuleILPath(UNICODE_STRING)
    char mod[512] = {0};
    if (!read_unicode_string_at(d, len, 24, mod, sizeof(mod))) return false;
    if (mod[0] == 0) return false;
    std::string ip = lower(mod);
    if (is_known_system_path(ip)) return false;
    if (is_suspicious_location(ip)) {
        SET_RULE(ev, "DOTNET_SUSPICIOUS_ASSEMBLY");
        ev.severity = 2;
        ev.suspicious = true;
        snprintf(ev.image, sizeof(ev.image), "%s", mod);
        proc_table_add_score(ev.sourcePid, 25);
        return true;
    }
    return false;
}

// ========================================================================
// Sysmon 分析器（联动，仅当 Sysmon 存在时启用）
// 使用 payload 子串启发式，不依赖 Sysmon 版本字段布局
// ========================================================================
bool analyze_sysmon(const EVENT_RECORD* rec, EtwEvent& ev) {
    const BYTE* d = (const BYTE*)rec->UserData;
    DWORD len = rec->UserDataLength;
    if (!d || len < 8) return false;
    ev.sourcePid = rec->EventHeader.ProcessId;

    // Event 10 ProcessAccess → LSASS 凭据窃取
    if (ev.eventId == 10) {
        // 定位 lsass 相关上下文（目标进程名/路径）
        char ctx[400] = {0};
        const char* lsassMarker[] = {"lsass"};
        if (scan_markers(d, len, lsassMarker, 1, ctx, sizeof(ctx))) {
            SET_RULE(ev, "LSASS_CREDENTIAL_ACCESS");
            ev.severity = 3;
            ev.suspicious = true;
            snprintf(ev.detail, sizeof(ev.detail), "%.360s", ctx);
            proc_table_add_score(ev.sourcePid, 50);
            return true;
        }
    }
    // Event 22 DNSEvent → DGA
    if (ev.eventId == 22) {
        char qname[300] = {0};
        read_cstr_at(d, len, 0, qname, sizeof(qname));
        if (qname[0] && looks_like_dga(qname)) {
            SET_RULE(ev, "DGA_DOMAIN_SYSMON");
            ev.severity = 2;
            ev.suspicious = true;
            snprintf(ev.detail, sizeof(ev.detail), "%s", qname);
            proc_table_add_score(ev.sourcePid, 20);
            return true;
        }
    }
    // Event 17/18 Pipe → 命名管道 C2
    if (ev.eventId == 17 || ev.eventId == 18) {
        char ctx[300] = {0};
        const char* pipeMarkers[] = {"\\pipe\\"};
        if (scan_markers(d, len, pipeMarkers, 1, ctx, sizeof(ctx))) {
            // 常见 C2 管道名（Sliver/Cobalt Strike 等）
            std::string c = lower(ctx);
            static const char* c2pipes[] = {
                "msagent", "ntsvcs", "spoolss", "wkssvc", "browser",
                "lsarpc", "samr", "netlogon", "mojo", "postex_", "status_",
            };
            for (auto p : c2pipes) {
                if (contains_substr_l(c, p)) {
                    SET_RULE(ev, "NAMED_PIPE_C2");
                    ev.severity = 2;
                    ev.suspicious = true;
                    snprintf(ev.detail, sizeof(ev.detail), "%.260s", ctx);
                    proc_table_add_score(ev.sourcePid, 20);
                    return true;
                }
            }
        }
    }
    // Event 7 ImageLoad → 侧加载（复用 Kernel-Process 逻辑的简化版）
    if (ev.eventId == 7) {
        char img[512] = {0};
        read_cstr_at(d, len, 0, img, sizeof(img));
        if (img[0]) {
            std::string ip = lower(img);
            if (!is_known_system_path(ip) && is_suspicious_location(ip) &&
                get_ext(ip) == ".dll" && !is_signed_file_cached(ip)) {
                SET_RULE(ev, "DLL_SIDELOAD_SYSMON");
                ev.severity = 2;
                ev.suspicious = true;
                snprintf(ev.image, sizeof(ev.image), "%s", img);
                proc_table_add_score(ev.sourcePid, 25);
                return true;
            }
        }
    }
    return false;
}

// ========================================================================
// Kernel-File 分析器（高危文件操作：卷影复制/临时目录可执行/启动目录）
// ========================================================================
bool analyze_kfile(const EVENT_RECORD* rec, EtwEvent& ev) {
    const BYTE* d = (const BYTE*)rec->UserData;
    DWORD len = rec->UserDataLength;
    if (!d || len < 16) return false;
    ev.sourcePid = rec->EventHeader.ProcessId;

    char path[1024] = {0};
    read_cstr_at(d, len, 0, path, sizeof(path));
    std::string p = lower(path);

    // 卷影复制（ShadowCopy 提权/杀毒绕过）
    if (contains_substr_l(p, "harddiskvolumeShadowCopy")) {
        SET_RULE(ev, "SHADOWCOPY_ACCESS");
        ev.severity = 3;
        ev.suspicious = true;
        snprintf(ev.detail, sizeof(ev.detail), "%.300s", path);
        proc_table_add_score(ev.sourcePid, 40);
        return true;
    }
    // 临时/下载目录中的可执行/脚本写入
    if (contains_substr_l(p, "\\temp\\") || contains_substr_l(p, "\\downloads\\") ||
        contains_substr_l(p, "\\public\\")) {
        std::string ext = get_ext(p);
        if (ext == ".exe" || ext == ".dll" || ext == ".scr" || ext == ".bat" ||
            ext == ".vbs" || ext == ".js" || ext == ".ps1" || ext == ".lnk") {
            SET_RULE(ev, "FILE_DROP_EXEC");
            ev.severity = 2;
            ev.suspicious = true;
            snprintf(ev.detail, sizeof(ev.detail), "%.300s", path);
            proc_table_add_score(ev.sourcePid, 25);
            return true;
        }
    }
    // 启动文件夹写入（持久化）
    if (contains_substr_l(p, "\\startup\\") || contains_substr_l(p, "\\start menu\\programs\\startup")) {
        SET_RULE(ev, "STARTUP_FOLDER_WRITE");
        ev.severity = 2;
        ev.suspicious = true;
        snprintf(ev.detail, sizeof(ev.detail), "%.300s", path);
        proc_table_add_score(ev.sourcePid, 25);
        return true;
    }
    return false;
}

// ========================================================================
// Kernel-Registry 分析器（持久化键写入）
// ========================================================================
bool analyze_kreg(const EVENT_RECORD* rec, EtwEvent& ev) {
    const BYTE* d = (const BYTE*)rec->UserData;
    DWORD len = rec->UserDataLength;
    if (!d || len < 16) return false;
    ev.sourcePid = rec->EventHeader.ProcessId;

    char key[1024] = {0};
    read_cstr_at(d, len, 0, key, sizeof(key));
    std::string k = lower(key);

    static const char* persistKeys[] = {
        "currentversion\\run", "runonce", "winlogon",
        "image file execution options", "appinit_dlls",
        "policies\\explorer\\run", "print\\monitors",
        "windows\\currentversion\\policies\\explorer\\run",
        "command processor\\autorun", "services\\",
    };
    for (auto s : persistKeys) {
        if (contains_substr_l(k, s)) {
            SET_RULE(ev, "REG_PERSISTENCE_WRITE");
            ev.severity = 2;
            ev.suspicious = true;
            snprintf(ev.detail, sizeof(ev.detail), "%.300s", key);
            proc_table_add_score(ev.sourcePid, 25);
            return true;
        }
    }
    // Windows Defender 关闭
    if (contains_substr_l(k, "windows defender")) {
        SET_RULE(ev, "DEFENDER_DISABLE_TAMPER");
        ev.severity = 3;
        ev.suspicious = true;
        snprintf(ev.detail, sizeof(ev.detail), "%.300s", key);
        proc_table_add_score(ev.sourcePid, 40);
        return true;
    }
    return false;
}

// ========================================================================
// AMSI 篡改扫描（导出）
// 枚举进程，校验 amsi.dll!AmsiScanBuffer 前导字节是否被 Inline Hook
// ========================================================================
static DWORD64 find_export_remote(HANDLE hProc, DWORD64 base, const char* name) {
    IMAGE_DOS_HEADER dos;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, &dos, sizeof(dos), nullptr)) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS64 nt;
    if (!ReadProcessMemory(hProc, (LPCVOID)(base + dos.e_lfanew), &nt, sizeof(nt), nullptr)) return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;
    DWORD expRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) return 0;
    IMAGE_EXPORT_DIRECTORY exp;
    if (!ReadProcessMemory(hProc, (LPCVOID)(base + expRva), &exp, sizeof(exp), nullptr)) return 0;
    if (exp.NumberOfNames > 0xFFFF || exp.NumberOfFunctions > 0xFFFF) return 0;
    std::vector<DWORD> names(exp.NumberOfNames);
    if (exp.NumberOfNames &&
        !ReadProcessMemory(hProc, (LPCVOID)(base + exp.AddressOfNames), names.data(),
                           (SIZE_T)exp.NumberOfNames * 4, nullptr))
        return 0;
    std::vector<WORD> ords(exp.NumberOfNames);
    if (exp.NumberOfNames &&
        !ReadProcessMemory(hProc, (LPCVOID)(base + exp.AddressOfNameOrdinals), ords.data(),
                           (SIZE_T)exp.NumberOfNames * 2, nullptr))
        return 0;
    for (DWORD i = 0; i < exp.NumberOfNames; i++) {
        char nm[64] = {0};
        if (!ReadProcessMemory(hProc, (LPCVOID)(base + names[i]), nm, 63, nullptr)) continue;
        if (_stricmp(nm, name) != 0) continue;
        std::vector<DWORD> funcs(exp.NumberOfFunctions);
        if (!ReadProcessMemory(hProc, (LPCVOID)(base + exp.AddressOfFunctions), funcs.data(),
                               (SIZE_T)exp.NumberOfFunctions * 4, nullptr))
            return 0;
        if (ords[i] >= exp.NumberOfFunctions) return 0;
        return base + funcs[ords[i]];
    }
    return 0;
}

// 判定 AmsiScanBuffer 前导字节是否被 hook
// 返回 1=已hook 0=正常 -1=未知(不告警)
static int amsi_prologue_state(const BYTE* b) {
    if (!b) return -1;
    if (b[0] == 0xE9 || b[0] == 0xEB || b[0] == 0xCC || b[0] == 0xC3) return 1;
    if (b[0] == 0xFF && b[1] == 0x25) return 1;
    if (b[0] == 0x48 && b[1] == 0xB8) {           // mov rax, imm; ... jmp rax
        if (b[6] == 0xFF && b[7] == 0xE0) return 1;
    }
    // 已知正常 prologue（x64，多个 Win 版本）
    static const BYTE good1[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x57};
    static const BYTE good2[] = {0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B};
    static const BYTE good3[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58};
    if (memcmp(b, good1, sizeof(good1)) == 0) return 0;
    if (memcmp(b, good2, sizeof(good2)) == 0) return 0;
    if (memcmp(b, good3, sizeof(good3)) == 0) return 0;
    return -1;
}

extern "C" __declspec(dllexport) char* guard_scan_amsi_tamper() {
    std::string json = "{\"tampered\":false,\"scanned\":0,\"hooked\":[],\"details\":[]}";
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return alloc_str(json.c_str());

    std::vector<std::string> hooked;
    std::vector<std::string> details;
    int scanned = 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == GetCurrentProcessId()) continue;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (!hProc) continue;
            HMODULE mods[512];
            DWORD needed = 0;
            if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed,
                                      LIST_MODULES_64BIT | LIST_MODULES_32BIT)) {
                CloseHandle(hProc);
                continue;
            }
            DWORD count = needed / sizeof(HMODULE);
            if (count > 512) count = 512;
            for (DWORD i = 0; i < count; i++) {
                wchar_t mname[MAX_PATH] = {0};
                if (!GetModuleBaseNameW(hProc, mods[i], mname, MAX_PATH)) continue;
                if (_wcsicmp(mname, L"amsi.dll") != 0) continue;
                DWORD64 amsiBase = (DWORD64)mods[i];
                DWORD64 fn = find_export_remote(hProc, amsiBase, "AmsiScanBuffer");
                if (!fn) break;
                BYTE pro[16] = {0};
                if (!ReadProcessMemory(hProc, (LPCVOID)fn, pro, sizeof(pro), nullptr)) break;
                int st = amsi_prologue_state(pro);
                scanned++;
                char name[128] = {0};
                wcstombs(name, pe.szExeFile, sizeof(name) - 1);
                if (st == 1) {
                    char buf[512];
                    snprintf(buf, sizeof(buf),
                             "{\"pid\":%lu,\"process\":\"%s\",\"addr\":\"0x%llX\"}",
                             pe.th32ProcessID, json_escape(name).c_str(),
                             (unsigned long long)fn);
                    hooked.push_back(buf);
                    details.push_back(name);
                }
                break;
            }
            CloseHandle(hProc);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    bool tampered = !hooked.empty();
    char out[8192];
    std::string hookArr = "[";
    for (size_t i = 0; i < hooked.size(); i++) {
        if (i) hookArr += ",";
        hookArr += hooked[i];
    }
    hookArr += "]";
    std::string detArr = "[";
    for (size_t i = 0; i < details.size(); i++) {
        if (i) detArr += ",";
        detArr += "\"" + json_escape(details[i]) + "\"";
    }
    detArr += "]";
    snprintf(out, sizeof(out),
             "{\"tampered\":%s,\"scanned\":%d,\"hooked\":%s,\"details\":%s}",
             tampered ? "true" : "false", scanned, hookArr.c_str(), detArr.c_str());
    return alloc_str(out);
}

// ========================================================================
// ETW 自身防篡改扫描（导出）
// 检测 ntdll!EtwEventWrite 是否被 Patch + 会话存活
// ========================================================================
static int etw_prologue_state(const BYTE* b) {
    if (!b) return -1;
    if (b[0] == 0xE9 || b[0] == 0xEB || b[0] == 0xCC || b[0] == 0xC3) return 1;
    if (b[0] == 0xFF && b[1] == 0x25) return 1;
    if (b[0] == 0x48 && b[1] == 0xB8) {
        if (b[6] == 0xFF && b[7] == 0xE0) return 1;
    }
    static const BYTE good1[] = {0x4C, 0x8B, 0xDC, 0x53, 0x56};
    static const BYTE good2[] = {0x48, 0x89, 0x5C, 0x24, 0x08};
    static const BYTE good3[] = {0x40, 0x53, 0x56, 0x57};
    if (memcmp(b, good1, sizeof(good1)) == 0) return 0;
    if (memcmp(b, good2, sizeof(good2)) == 0) return 0;
    if (memcmp(b, good3, sizeof(good3)) == 0) return 0;
    return -1;
}

extern "C" __declspec(dllexport) char* guard_scan_etw_tamper() {
    bool tampered = false;
    std::string detail;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        FARPROC pfn = GetProcAddress(ntdll, "EtwEventWrite");
        if (pfn) {
            BYTE pro[16] = {0};
            memcpy(pro, (const void*)pfn, sizeof(pro));
            int st = etw_prologue_state(pro);
            if (st == 1) {
                tampered = true;
                char b[256];
                snprintf(b, sizeof(b), "ntdll!EtwEventWrite @0x%p 疑似被 Hook", pfn);
                detail = b;
            }
        }
    }

    // 会话存活检查（若 ETW 已启动但会话消失 → 被篡改/停止）
    bool sessionActive = etw_session_active();
    if (!sessionActive && g_etwEverStarted) {
        tampered = true;
        if (!detail.empty()) detail += "; ";
        detail += "ETW 会话已停止/消失";
    }

    std::string json = "{\"tampered\":" + std::string(tampered ? "true" : "false") +
                       ",\"session_active\":" + std::string(sessionActive ? "true" : "false") +
                       ",\"detail\":\"" + json_escape(detail) + "\"}";
    return alloc_str(json.c_str());
}
