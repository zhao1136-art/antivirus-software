/**
 * ETW 多 Provider 事中检测框架（升级一 + 升级三）
 *
 * 架构：
 *   - 单一实时会话 "AndunETW"，通过 EnableTraceEx2 依次启用 9 个 Provider
 *     （含 3 个现代内核 Provider：Kernel-Process / Kernel-File / Kernel-Registry）。
 *     内核事件携带各自的 Provider GUID，因此按 GUID 分发无事件 ID 冲突。
 *   - 事件回调按 Provider GUID 分派到 etw_rules.cpp 的 9 个分析器，
 *     命中规则的事件进入环形缓冲队列（内存），并持久化到内存映射文件。
 *   - 进程表（线程安全拷贝查询）维护 pid→父子/镜像/命令行/风险分。
 *   - 事件关联引擎：按进程（含祖先）汇总行为规则，匹配攻击链模板，
 *     产出关联事件（攻击链）与进程树风险分。
 *   - Provider 健康监控：记录各 Provider 启用成败/捕获/告警计数；
 *     监控线程周期性校验会话存活与事件流动。
 *
 * 说明：
 *   - 需要管理员 + SeDebugPrivilege；DNS/PowerShell 需对应 Provider 可用。
 *   - PowerShell 脚本块日志需系统策略开启才能收到 4104 事件。
 */
#include "etw_guard.h"

#pragma comment(lib, "advapi32.lib")

// MinGW 的 evntrace.h 声明了 SystemTraceControlGuid 但未提供定义，此处提供
// {9e814aad-3204-11d2-9a82-006008a86939}
EXTERN_C const GUID SystemTraceControlGuid =
    {0x9e814aad, 0x3204, 0x11d2, {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}};

#define ETW_SESSION_NAME L"AndunETW"
#define ETW_MAX_EVENTS 512          // 内存环形缓冲容量（命中队列）
#define ETW_QUEUE_HARD_CAP 10000    // 硬上限（背压触发阈值）

// ========================================================================
// Provider GUID / 名称表
// ========================================================================
static const GUID PROVIDER_GUIDS[PROV_MAX] = {
    {0xF4E1897C,0xBB5D,0x5668,{0xF1,0xD8,0x04,0x0F,0x4D,0x8D,0xD3,0x44}}, // Threat-Intelligence
    {0x22FB2CD6,0x0E7B,0x422B,{0xA0,0xC7,0x2F,0xAD,0x1F,0xD0,0xE7,0x16}}, // Kernel-Process
    {0x1C95126E,0x7EEA,0x49A9,{0xA3,0xFE,0xA3,0x78,0xB0,0x3D,0xDB,0x4D}}, // DNS-Client
    {0xA0C1853B,0x5C40,0x4B15,{0x87,0x66,0x3C,0xF1,0xC5,0x8F,0x98,0x5A}}, // PowerShell
    {0x1418EF04,0xB0B4,0x4623,{0x92,0x72,0x4A,0xB1,0xF4,0x7D,0x2A,0x23}}, // WMI-Activity
    {0xE13C0D23,0xCCBC,0x4E12,{0x93,0x1B,0xD9,0xCC,0x2E,0xEE,0x27,0xE4}}, // DotNETRuntime
    {0x5770385F,0xC22A,0x43E0,{0xBF,0x4C,0x06,0xF5,0x69,0x8F,0xFB,0xD9}}, // Sysmon
    {0xEDD08927,0x9CC4,0x4E65,{0xB9,0x70,0xC2,0x56,0x0F,0xB5,0xC2,0x89}}, // Kernel-File
    {0x70EB4F03,0xC1DE,0x4F73,{0xA0,0x5C,0x9E,0x32,0xB2,0x8D,0xE3,0xA9}}, // Kernel-Registry
};

static const char* PROVIDER_NAMES[PROV_MAX] = {
    "Threat-Intelligence", "Kernel-Process", "DNS-Client",
    "PowerShell", "WMI-Activity", "DotNETRuntime",
    "Sysmon", "Kernel-File", "Kernel-Registry",
};

// ========================================================================
// 会话 / 线程 / 状态
// ========================================================================
static TRACEHANDLE  g_sessionHandle = 0;      // 实时会话句柄
static TRACEHANDLE  g_traceHandle = 0;        // 消费句柄
static HANDLE       g_consumeThread = nullptr;
static HANDLE       g_monitorThread = nullptr;
static volatile bool g_etwRunning = false;
bool g_etwEverStarted = false;                // 供 etw_rules.cpp 篡改扫描使用

static volatile LONG g_capturedTotal = 0;     // 总捕获事件数
static volatile LONG g_suspiciousTotal = 0;   // 总告警数
static volatile LONGLONG g_lastActivityQpc = 0;

// Provider 状态
static bool g_providerEnabled[PROV_MAX] = {true,true,true,true,true,true,true,true,true};
static bool g_providerEnableOk[PROV_MAX] = {false};
static long g_providerCaptured[PROV_MAX] = {0};
static long g_providerSuspicious[PROV_MAX] = {0};

static CRITICAL_SECTION g_queueLock;
static CRITICAL_SECTION g_procLock;
static CRITICAL_SECTION g_behavLock;
static CRITICAL_SECTION g_corrLock;
static CRITICAL_SECTION g_mmapLock;
static volatile bool g_locksInit = false;

// ========================================================================
// 限流：每 Provider token bucket
// ========================================================================
struct ProviderRateLimit {
    ULONGLONG lastCheck;       // 上次检查时间 (GetTickCount64 ms)
    LONG      tokens;          // 当前令牌数
    LONG      maxTokens;       // 桶容量 = 速率上限
    LONG      refillRate;      // 补充速率（令牌/秒）
    LONG      dropped;         // 累计丢弃数
    LONG      passed;          // 累计放行数
};
static ProviderRateLimit g_rateLimits[PROV_MAX];
static LONG g_totalDropped = 0;    // 总丢弃数（含限流+背压）
static LONG g_totalBackpressure = 0;

// 高价值 EventId 集合（按 Provider 分组）
// 这些 EventId 即使未命中检测规则也会保留，因为它们是进程链/行为分析的关键输入
struct HighValueEvent {
    int  provider;
    DWORD eventIds[16];   // 最多 16 个高价值 EventId
    int  count;
};

// ========================================================================
// 内存环形缓冲（事件队列）
// ========================================================================
static EtwEvent g_events[ETW_MAX_EVENTS];
static int g_qHead = 0, g_qCount = 0;

// 持久化恢复的历史事件（mmap 加载，会话重启后不丢失）
static std::vector<EtwEvent> g_recovered;

// ========================================================================
// 进程表
// ========================================================================
static std::map<DWORD, ProcInfo> g_procTable;

// ========================================================================
// 行为跟踪 + 事件关联
// ========================================================================
struct Behavior {
    char rule[80];
    int  severity;
    ULONGLONG ts;          // GetTickCount64() ms
};
static std::map<DWORD, std::vector<Behavior>> g_behaviors;   // pid → 最近行为
static const ULONGLONG BEHAVIOR_WINDOW_MS = 600000;          // 行为窗口 10 分钟
static const int       BEHAVIOR_MAX = 128;                   // 单进程行为上限

struct CorrEvent {
    DWORD pid;
    char  name[128];
    char  chain[80];
    char  detail[512];
    int   severity;
    ULONGLONG ts;
};
static std::vector<CorrEvent> g_corrEvents;
static std::map<DWORD, std::map<std::string, ULONGLONG>> g_corrCooldown;  // pid → chain → lastTs
static const ULONGLONG CORR_COOLDOWN_MS = 300000;            // 同链冷却 5 分钟

// 攻击链模板：groups 内为"任一命中"，groups 之间为"全部满足"
struct ChainGroup  { const char* rules[8]; };
struct ChainPattern { const char* name; int severity; const char* desc;
                      ChainGroup groups[3]; int groupsN; };

static const ChainPattern CHAIN_PATTERNS[] = {
    { // 恶意软件安装链路：脚本执行 → 落地/持久化 → 释放可执行
        "MALWARE_INSTALL_CHAIN", 3, "脚本执行+持久化+文件落地，疑似恶意软件安装",
        { { {"OFFICE_SPAWNS_SCRIPT","SCRIPT_CHAIN","ENCODED_CMDLINE","PS_OBFUSCATED_SCRIPT",""} },
          { {"REG_PERSISTENCE_WRITE","STARTUP_FOLDER_WRITE","WMI_PERSISTENCE",""} },
          { {"FILE_DROP_EXEC","SUSPICIOUS_EXEC_LOCATION","DOTNET_SUSPICIOUS_ASSEMBLY",""} } },
        3
    },
    { // 凭据窃取链路：访问 LSASS → 网络/管道/DGA 外传
        "CREDENTIAL_THEFT_CHAIN", 3, "LSASS 访问+回连行为，疑似凭据窃取",
        { { {"LSASS_CREDENTIAL_ACCESS","TI_READ_PROC_MEMORY","TI_PROCESS_TAMPERING",""} },
          { {"NAMED_PIPE_C2","DNS_DGA","DGA_DOMAIN","ENCODED_CMDLINE",""} } },
        2
    },
    { // C2 信标链路：DGA/NXDOMAIN → 脚本/管道回连
        "C2_BEACON_CHAIN", 3, "DGA/信标域名+脚本回连，疑似 C2 通信",
        { { {"DNS_NXDOMAIN_BEACON","DGA_DOMAIN","DNS_DGA",""} },
          { {"ENCODED_CMDLINE","PS_OBFUSCATED_SCRIPT","NAMED_PIPE_C2","SCRIPT_CHAIN",""} } },
        2
    },
    { // 防御关闭链路：关闭 Defender + 写持久化
        "DEFENSE_DISABLE_CHAIN", 3, "关闭防护+持久化写入，疑似防御破坏",
        { { {"DEFENDER_DISABLE_TAMPER",""} },
          { {"REG_PERSISTENCE_WRITE","WMI_PERSISTENCE","STARTUP_FOLDER_WRITE",""} } },
        2
    },
    { // Office 宏脚本链路：Office → 混淆脚本
        "OFFICE_MACRO_CHAIN", 2, "Office 派生混淆脚本，疑似宏攻击",
        { { {"OFFICE_SPAWNS_SCRIPT",""} },
          { {"PS_OBFUSCATED_SCRIPT","ENCODED_CMDLINE","SCRIPT_CHAIN",""} } },
        2
    },
};

// ========================================================================
// 内存映射持久化环形缓冲
// ========================================================================
#define DISK_MAGIC 0x54454E41   // 'ANET'
#define DISK_VERSION 1
#define DISK_EVENT_CAP 2048     // 磁盘环形容量

struct EtwDiskEvent {
    int      provider;
    DWORD    eventId;
    DWORD    sourcePid;
    DWORD    targetPid;
    DWORD    parentPid;
    char     image[MAX_PATH_LEN];
    char     imageName[128];
    char     detail[512];
    char     rule[80];
    int      severity;
    ULONGLONG timestamp;
    BOOL     suspicious;
};
struct EtwDiskHeader {
    DWORD magic;
    DWORD version;
    LONG  head;            // 最旧索引
    LONG  tail;            // 下一写入索引
    LONG  count;
    ULONGLONG lastWrite;
};

static HANDLE g_mmapFile = nullptr;
static HANDLE g_mmapHandle = nullptr;
static BYTE*  g_mmapBase = nullptr;
static EtwDiskHeader* g_mmapHeader = nullptr;
static EtwDiskEvent*  g_mmapEvents = nullptr;

static bool mmap_open();
static void mmap_close();
static void mmap_push(const EtwEvent& ev);

// ========================================================================
// 工具：SeDebugPrivilege
// ========================================================================
static bool enable_debug_privilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    return ok;
}

static void stop_etw_session() {
    ULONG propsSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(ETW_SESSION_NAME) + sizeof(wchar_t) * 64;
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
    if (!props) return;
    memset(props, 0, propsSize);
    props->Wnode.BufferSize = propsSize;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceW(0, ETW_SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    free(props);
}

static void ensure_locks() {
    if (g_locksInit) return;
    InitializeCriticalSection(&g_queueLock);
    InitializeCriticalSection(&g_procLock);
    InitializeCriticalSection(&g_behavLock);
    InitializeCriticalSection(&g_corrLock);
    InitializeCriticalSection(&g_mmapLock);
    g_locksInit = true;
}

// ========================================================================
// Provider 状态接口
// ========================================================================
int etw_provider_index(const GUID* g) {
    if (!g) return -1;
    for (int i = 0; i < PROV_MAX; i++)
        if (memcmp(g, &PROVIDER_GUIDS[i], sizeof(GUID)) == 0) return i;
    return -1;
}

const char* etw_provider_name(int idx) {
    if (idx < 0 || idx >= PROV_MAX) return "Unknown";
    return PROVIDER_NAMES[idx];
}

void etw_provider_note_capture(int idx, bool susp) {
    if (idx < 0 || idx >= PROV_MAX) return;
    InterlockedIncrement(&g_providerCaptured[idx]);
    InterlockedIncrement(&g_capturedTotal);
    if (susp) {
        InterlockedIncrement(&g_providerSuspicious[idx]);
        InterlockedIncrement(&g_suspiciousTotal);
    }
}

long etw_provider_captured(int idx)   { return (idx >= 0 && idx < PROV_MAX) ? g_providerCaptured[idx] : 0; }
long etw_provider_suspicious(int idx) { return (idx >= 0 && idx < PROV_MAX) ? g_providerSuspicious[idx] : 0; }
bool etw_provider_is_enabled(int idx) { return (idx >= 0 && idx < PROV_MAX) ? g_providerEnabled[idx] : false; }
void etw_provider_set_enabled(int idx, bool en) { if (idx >= 0 && idx < PROV_MAX) g_providerEnabled[idx] = en; }

bool etw_session_active() {
    return g_etwRunning && g_sessionHandle != 0;
}

// ========================================================================
// 限流：token bucket 算法
// ========================================================================
static void init_rate_limits() {
    memset(g_rateLimits, 0, sizeof(g_rateLimits));
    ULONGLONG now = GetTickCount64();
    int rates[PROV_MAX] = {
        RATE_LIMIT_DEFAULT,   // PROV_TI
        RATE_LIMIT_KPROC,     // PROV_KPROC
        RATE_LIMIT_DNS,       // PROV_DNS
        RATE_LIMIT_DEFAULT,   // PROV_POWERSHELL
        RATE_LIMIT_DEFAULT,   // PROV_WMI
        RATE_LIMIT_DEFAULT,   // PROV_DOTNET
        RATE_LIMIT_DEFAULT,   // PROV_SYSMON
        RATE_LIMIT_KFILE,     // PROV_KFILE
        RATE_LIMIT_DEFAULT,   // PROV_KREG
    };
    for (int i = 0; i < PROV_MAX; i++) {
        g_rateLimits[i].lastCheck = now;
        g_rateLimits[i].maxTokens = rates[i];
        g_rateLimits[i].refillRate = rates[i];
        g_rateLimits[i].tokens = rates[i];  // 初始满桶
        g_rateLimits[i].dropped = 0;
        g_rateLimits[i].passed = 0;
    }
}

bool etw_rate_check(int provider) {
    if (provider < 0 || provider >= PROV_MAX) return true;  // 未知 Provider 放行
    ProviderRateLimit& rl = g_rateLimits[provider];
    ULONGLONG now = GetTickCount64();
    ULONGLONG elapsed = now - rl.lastCheck;

    // 补充令牌：按经过时间比例
    if (elapsed >= 1000) {
        LONG refill = (LONG)((elapsed * rl.refillRate) / 1000);
        rl.tokens += refill;
        if (rl.tokens > rl.maxTokens) rl.tokens = rl.maxTokens;
        rl.lastCheck = now;
    }

    if (rl.tokens > 0) {
        rl.tokens--;
        InterlockedIncrement(&rl.passed);
        return true;
    }
    InterlockedIncrement(&rl.dropped);
    InterlockedIncrement(&g_totalDropped);
    return false;
}

// ========================================================================
// 高价值 EventId 过滤（即使未命中规则也保留，用于进程链/行为分析）
// ========================================================================
static const HighValueEvent HIGH_VALUE_EVENTS[] = {
    { PROV_KPROC,  {1, 2, 3, 4, 5, 6, 7, 8, 0}, 8 },   // 进程/线程 创建/终止
    { PROV_KFILE,  {12, 30, 31, 0}, 3 },                  // 文件创建/重命名
    { PROV_KREG,   {1, 2, 5, 22, 0}, 4 },                // 注册表创建/打开/设值/删除
    { PROV_DNS,    {3006, 3008, 0}, 2 },                  // DNS 查询/响应
    { PROV_POWERSHELL, {4104, 4103, 800, 0}, 3 },         // 脚本块/执行/引擎
    { PROV_WMI,    {11, 22, 23, 0}, 3 },                  // 消费者/过滤器/绑定
    { PROV_SYSMON, {1, 3, 7, 11, 0}, 4 },                // 进程创建/网络/镜像加载/文件创建
    { PROV_TI,     {1, 12, 17, 0}, 3 },                   // 读进程内存/远程线程/APC注入
    { PROV_DOTNET, {0}, 0 },                               // .NET 事件全量保留（低频）
    { -1, {0}, 0 }                                         // 哨兵
};

bool etw_is_high_value_event(int provider, DWORD eventId) {
    for (int i = 0; HIGH_VALUE_EVENTS[i].provider >= 0; i++) {
        if (HIGH_VALUE_EVENTS[i].provider == provider) {
            for (int j = 0; j < HIGH_VALUE_EVENTS[i].count; j++) {
                if (HIGH_VALUE_EVENTS[i].eventIds[j] == eventId) return true;
            }
            return false;
        }
    }
    return false;
}

// ========================================================================
// 背压入队：满队列时按严重性替换
// ========================================================================
void etw_queue_push_filtered(EtwEvent& ev) {
    EnterCriticalSection(&g_queueLock);
    if (g_qCount < ETW_QUEUE_HARD_CAP) {
        // 正常入队
        g_events[(g_qHead + g_qCount) % ETW_MAX_EVENTS] = ev;
        g_qCount++;
    } else {
        // 背压：查找队列中最低严重性的非关键事件替换
        int minIdx = -1;
        int minSev = 999;
        for (int i = 0; i < g_qCount; i++) {
            int idx = (g_qHead + i) % ETW_MAX_EVENTS;
            if (g_events[idx].severity < minSev) {
                minSev = g_events[idx].severity;
                minIdx = idx;
            }
        }
        if (minIdx >= 0 && ev.severity > minSev) {
            // 新事件严重性更高，替换低严重性事件
            g_events[minIdx] = ev;
            InterlockedIncrement(&g_totalBackpressure);
        }
        // 否则丢弃新事件（低严重性不值得替换）
        InterlockedIncrement(&g_totalDropped);
    }
    LeaveCriticalSection(&g_queueLock);

    mmap_push(ev);
    InterlockedExchange64(&g_lastActivityQpc,
        ev.timestamp ? (LONGLONG)ev.timestamp : (LONGLONG)GetTickCount64());
}

void etw_rate_stats_json(std::string& out) {
    out += "\"rate_limits\":[";
    for (int i = 0; i < PROV_MAX; i++) {
        if (i) out += ",";
        char buf[256];
        snprintf(buf, sizeof(buf),
            "{\"provider\":\"%s\",\"rate\":%ld,\"passed\":%ld,\"dropped\":%ld,"
            "\"tokens\":%ld}",
            PROVIDER_NAMES[i], (long)g_rateLimits[i].refillRate,
            (long)g_rateLimits[i].passed, (long)g_rateLimits[i].dropped,
            (long)g_rateLimits[i].tokens);
        out += buf;
    }
    out += "],\"total_dropped\":" + std::to_string((LONG)g_totalDropped);
    out += ",\"backpressure_drops\":" + std::to_string((LONG)g_totalBackpressure);
}

// ========================================================================
// 进程表（线程安全）
// ========================================================================
void proc_table_update(DWORD pid, DWORD parent, const char* image,
                       const char* name, const char* cmdline) {
    EnterCriticalSection(&g_procLock);
    auto it = g_procTable.find(pid);
    if (it != g_procTable.end()) {
        // 刷新但保留已累计的风险分
        ProcInfo& p = it->second;
        p.parentPid = parent;
        if (image)  snprintf(p.image, sizeof(p.image), "%s", image);
        if (name)   snprintf(p.name,  sizeof(p.name),  "%s", name);
        if (cmdline) snprintf(p.cmdline, sizeof(p.cmdline), "%s", cmdline);
    } else {
        ProcInfo p;
        memset(&p, 0, sizeof(p));
        p.pid = pid;
        p.parentPid = parent;
        p.score = 0;
        p.firstSeen = GetTickCount64();
        if (image)  snprintf(p.image, sizeof(p.image), "%s", image);
        if (name)   snprintf(p.name,  sizeof(p.name),  "%s", name);
        if (cmdline) snprintf(p.cmdline, sizeof(p.cmdline), "%s", cmdline);
        g_procTable[pid] = p;
    }
    LeaveCriticalSection(&g_procLock);
}

void proc_table_remove(DWORD pid) {
    EnterCriticalSection(&g_procLock);
    g_procTable.erase(pid);
    LeaveCriticalSection(&g_procLock);
}

void proc_table_add_score(DWORD pid, int score) {
    if (pid == 0) return;
    EnterCriticalSection(&g_procLock);
    auto it = g_procTable.find(pid);
    if (it != g_procTable.end()) {
        it->second.score += score;
        if (it->second.score < 0) it->second.score = 0;
        if (it->second.score > 999) it->second.score = 999;
    } else {
        // 进程尚未被 ProcessStart 记录（可能漏事件）：占位
        ProcInfo p;
        memset(&p, 0, sizeof(p));
        p.pid = pid;
        p.score = (score < 0 ? 0 : score);
        if (score > 999) p.score = 999;
        p.firstSeen = GetTickCount64();
        g_procTable[pid] = p;
    }
    LeaveCriticalSection(&g_procLock);
}

bool proc_table_lookup(DWORD pid, ProcInfo& out) {
    if (pid == 0) return false;
    EnterCriticalSection(&g_procLock);
    auto it = g_procTable.find(pid);
    bool found = (it != g_procTable.end());
    if (found) out = it->second;
    LeaveCriticalSection(&g_procLock);
    return found;
}

// 计算子树风险分（递归，带缓存防止环）
static int proc_tree_score(DWORD pid, std::map<DWORD,int>& cache) {
    auto c = cache.find(pid);
    if (c != cache.end()) return c->second;
    EnterCriticalSection(&g_procLock);
    auto it = g_procTable.find(pid);
    int own = (it != g_procTable.end()) ? it->second.score : 0;
    LeaveCriticalSection(&g_procLock);

    int total = own;
    // 枚举所有以 pid 为父的直接子进程
    EnterCriticalSection(&g_procLock);
    std::vector<DWORD> children;
    for (auto& kv : g_procTable)
        if (kv.second.parentPid == pid && kv.first != pid) children.push_back(kv.first);
    LeaveCriticalSection(&g_procLock);
    for (DWORD cid : children) {
        int cs = proc_tree_score(cid, cache);
        if (cs < 0 || cs > 10000) continue;   // 防环/异常
        total += cs;
    }
    cache[pid] = total;
    return total;
}

// ========================================================================
// 行为跟踪 + 事件关联引擎
// ========================================================================
void behavior_record(DWORD pid, const char* rule, int severity) {
    if (pid == 0 || !rule || !rule[0]) return;
    Behavior b;
    memset(&b, 0, sizeof(b));
    snprintf(b.rule, sizeof(b.rule), "%s", rule);
    b.severity = severity;
    b.ts = GetTickCount64();
    EnterCriticalSection(&g_behavLock);
    auto& vec = g_behaviors[pid];
    vec.push_back(b);
    if ((int)vec.size() > BEHAVIOR_MAX)
        vec.erase(vec.begin(), vec.end() - BEHAVIOR_MAX);
    LeaveCriticalSection(&g_behavLock);
}

// 收集 pid 及其祖先（最多 4 层）窗口内的去重规则
static void collect_chain_rules(DWORD pid, std::set<std::string>& out) {
    ULONGLONG now = GetTickCount64();
    DWORD cur = pid;
    for (int depth = 0; depth < 4 && cur != 0; depth++) {
        EnterCriticalSection(&g_behavLock);
        auto it = g_behaviors.find(cur);
        if (it != g_behaviors.end())
            for (auto& b : it->second)
                if (now - b.ts <= BEHAVIOR_WINDOW_MS)
                    out.insert(std::string(b.rule));
        LeaveCriticalSection(&g_behavLock);
        ProcInfo pi;
        if (!proc_table_lookup(cur, pi)) break;
        cur = pi.parentPid;
    }
}

static void emit_correlation(DWORD pid, const ChainPattern& pat, const std::set<std::string>& rules) {
    CorrEvent ce;
    memset(&ce, 0, sizeof(ce));
    ce.pid = pid;
    ce.severity = pat.severity;
    ce.ts = GetTickCount64();
    snprintf(ce.chain, sizeof(ce.chain), "%s", pat.name);

    ProcInfo pi;
    if (proc_table_lookup(pid, pi))
        snprintf(ce.name, sizeof(ce.name), "%s", pi.name);
    else
        snprintf(ce.name, sizeof(ce.name), "pid_%lu", pid);

    // 组装命中的规则明细
    std::string det = pat.desc;
    det += " [";
    bool first = true;
    for (auto& r : rules) {
        if (!first) det += ",";
        first = false;
        det += r;
        if (det.size() > 400) break;
    }
    det += "]";
    snprintf(ce.detail, sizeof(ce.detail), "%s", det.c_str());

    EnterCriticalSection(&g_corrLock);
    g_corrEvents.push_back(ce);
    if (g_corrEvents.size() > 256)
        g_corrEvents.erase(g_corrEvents.begin());
    LeaveCriticalSection(&g_corrLock);

    // 关联命中 → 追加风险分（进一步抬升进程树评分）
    proc_table_add_score(pid, pat.severity * 15);
}

static void run_correlation() {
    std::vector<DWORD> pids;
    EnterCriticalSection(&g_procLock);
    for (auto& kv : g_procTable) pids.push_back(kv.first);
    LeaveCriticalSection(&g_procLock);

    ULONGLONG now = GetTickCount64();
    for (DWORD pid : pids) {
        std::set<std::string> rules;
        collect_chain_rules(pid, rules);
        if (rules.empty()) continue;

        for (const auto& pat : CHAIN_PATTERNS) {
            // 冷却检查
            EnterCriticalSection(&g_corrLock);
            auto pm = g_corrCooldown.find(pid);
            bool cooldown = false;
            if (pm != g_corrCooldown.end()) {
                auto cm = pm->second.find(pat.name);
                if (cm != pm->second.end() && now - cm->second < CORR_COOLDOWN_MS)
                    cooldown = true;
            }
            LeaveCriticalSection(&g_corrLock);
            if (cooldown) continue;

            bool all = true;
            for (int gi = 0; gi < pat.groupsN && all; gi++) {
                bool any = false;
                for (int ri = 0; pat.groups[gi].rules[ri][0]; ri++)
                    if (rules.count(pat.groups[gi].rules[ri])) { any = true; break; }
                if (!any) all = false;
            }
            if (!all) continue;

            emit_correlation(pid, pat, rules);
            EnterCriticalSection(&g_corrLock);
            g_corrCooldown[pid][pat.name] = now;
            LeaveCriticalSection(&g_corrLock);
        }
    }
}

std::string correlation_events_json(bool drain) {
    std::string json = "[";
    EnterCriticalSection(&g_corrLock);
    bool first = true;
    for (auto& ce : g_corrEvents) {
        if (!first) json += ",";
        first = false;
        char buf[1024];
        snprintf(buf, sizeof(buf),
            "{\"pid\":%lu,\"name\":\"%s\",\"chain\":\"%s\",\"severity\":%d,"
            "\"ts\":%llu,\"detail\":\"%s\"}",
            ce.pid, json_escape(ce.name).c_str(), json_escape(ce.chain).c_str(),
            ce.severity, (unsigned long long)ce.ts, json_escape(ce.detail).c_str());
        json += buf;
    }
    if (drain) g_corrEvents.clear();
    LeaveCriticalSection(&g_corrLock);
    json += "]";
    return json;
}

// ========================================================================
// 事件队列
// ========================================================================
void etw_queue_push(EtwEvent& ev) {
    EnterCriticalSection(&g_queueLock);
    if (g_qCount < ETW_MAX_EVENTS) {
        g_events[(g_qHead + g_qCount) % ETW_MAX_EVENTS] = ev;
        g_qCount++;
    } else {
        // 溢出覆盖最旧
        g_events[g_qHead] = ev;
        g_qHead = (g_qHead + 1) % ETW_MAX_EVENTS;
    }
    LeaveCriticalSection(&g_queueLock);

    mmap_push(ev);
    InterlockedExchange64(&g_lastActivityQpc,
        ev.timestamp ? (LONGLONG)ev.timestamp : (LONGLONG)GetTickCount64());
}

static std::string event_to_json(const EtwEvent& ev, bool recovered) {
    char buf[2048];
    snprintf(buf, sizeof(buf),
        "{\"provider\":\"%s\",\"provider_id\":%d,\"event_id\":%lu,"
        "\"source_pid\":%lu,\"target_pid\":%lu,\"parent_pid\":%lu,"
        "\"image\":\"%s\",\"image_name\":\"%s\",\"detail\":\"%s\","
        "\"rule\":\"%s\",\"severity\":%d,\"ts\":%llu,"
        "\"suspicious\":%s,\"recovered\":%s}",
        etw_provider_name(ev.provider), ev.provider, ev.eventId,
        ev.sourcePid, ev.targetPid, ev.parentPid,
        json_escape(ev.image).c_str(), json_escape(ev.imageName).c_str(),
        json_escape(ev.detail).c_str(), json_escape(ev.rule).c_str(),
        ev.severity, (unsigned long long)ev.timestamp,
        ev.suspicious ? "true" : "false", recovered ? "true" : "false");
    return std::string(buf);
}

// ========================================================================
// 内存映射持久化环形缓冲
// ========================================================================
static void mmap_file_path(char* out, DWORD outSize) {
    // %LOCALAPPDATA%\Andun\etw_history.bin（当前用户可写，避免 ProgramData 权限问题）
    char pd[MAX_PATH] = {0};
    DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", pd, sizeof(pd));
    if (n == 0 || n >= sizeof(pd)) {
        // 兜底到当前用户本地目录
        n = GetEnvironmentVariableA("USERPROFILE", pd, sizeof(pd));
        if (n == 0 || n >= sizeof(pd)) snprintf(pd, sizeof(pd), "C:\\");
        else snprintf(pd, sizeof(pd), "%s\\AppData\\Local", pd);
    }
    snprintf(out, outSize, "%s\\Andun\\etw_history.bin", pd);
}

static bool mmap_open() {
    if (g_mmapBase) return true;
    char path[MAX_PATH];
    mmap_file_path(path, sizeof(path));

    // 确保目录存在
    std::string dir(path);
    size_t slash = dir.rfind('\\');
    if (slash != std::string::npos) {
        std::string d = dir.substr(0, slash);
        CreateDirectoryA(d.c_str(), nullptr);
    }

    size_t fileSize = sizeof(EtwDiskHeader) + sizeof(EtwDiskEvent) * DISK_EVENT_CAP;
    g_mmapFile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_mmapFile == INVALID_HANDLE_VALUE) { g_mmapFile = nullptr; return false; }

    // 若新建则设置文件大小
    if (GetFileSize(g_mmapFile, nullptr) < (DWORD)fileSize) {
        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)fileSize;
        SetFilePointerEx(g_mmapFile, li, nullptr, FILE_BEGIN);
        SetEndOfFile(g_mmapFile);
    }

    g_mmapHandle = CreateFileMappingA(g_mmapFile, nullptr, PAGE_READWRITE, 0, 0, nullptr);
    if (!g_mmapHandle) { CloseHandle(g_mmapFile); g_mmapFile = nullptr; return false; }

    g_mmapBase = (BYTE*)MapViewOfFile(g_mmapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!g_mmapBase) {
        CloseHandle(g_mmapHandle); g_mmapHandle = nullptr;
        CloseHandle(g_mmapFile);   g_mmapFile = nullptr;
        return false;
    }
    g_mmapHeader = (EtwDiskHeader*)g_mmapBase;
    g_mmapEvents = (EtwDiskEvent*)(g_mmapBase + sizeof(EtwDiskHeader));

    // 读取历史到 g_recovered
    if (g_mmapHeader->magic == DISK_MAGIC && g_mmapHeader->version == DISK_VERSION) {
        LONG cnt = g_mmapHeader->count;
        if (cnt > DISK_EVENT_CAP) cnt = DISK_EVENT_CAP;
        if (cnt > 0 && g_mmapHeader->head >= 0 && g_mmapHeader->head < DISK_EVENT_CAP) {
            for (LONG i = 0; i < cnt && g_recovered.size() < 256; i++) {
                LONG idx = (g_mmapHeader->head + i) % DISK_EVENT_CAP;
                EtwDiskEvent& de = g_mmapEvents[idx];
                EtwEvent ev;
                memset(&ev, 0, sizeof(ev));
                ev.provider   = de.provider;
                ev.eventId    = de.eventId;
                ev.sourcePid  = de.sourcePid;
                ev.targetPid  = de.targetPid;
                ev.parentPid  = de.parentPid;
                memcpy(ev.image,     de.image,     sizeof(ev.image)     < sizeof(de.image)     ? sizeof(ev.image)     : sizeof(de.image));
                memcpy(ev.imageName, de.imageName, sizeof(ev.imageName) < sizeof(de.imageName) ? sizeof(ev.imageName) : sizeof(de.imageName));
                memcpy(ev.detail,    de.detail,    sizeof(ev.detail)    < sizeof(de.detail)    ? sizeof(ev.detail)    : sizeof(de.detail));
                memcpy(ev.rule,      de.rule,      sizeof(ev.rule)      < sizeof(de.rule)      ? sizeof(ev.rule)      : sizeof(de.rule));
                ev.severity   = de.severity;
                ev.timestamp  = de.timestamp;
                ev.suspicious = (de.suspicious != FALSE);
                g_recovered.push_back(ev);
            }
        }
    } else {
        // 初始化新头
        memset(g_mmapHeader, 0, sizeof(EtwDiskHeader));
        g_mmapHeader->magic = DISK_MAGIC;
        g_mmapHeader->version = DISK_VERSION;
        g_mmapHeader->head = 0;
        g_mmapHeader->tail = 0;
        g_mmapHeader->count = 0;
        memset(g_mmapEvents, 0, sizeof(EtwDiskEvent) * DISK_EVENT_CAP);
    }
    return true;
}

static void mmap_close() {
    if (g_mmapBase)  { UnmapViewOfFile(g_mmapBase); g_mmapBase = nullptr; }
    if (g_mmapHandle){ CloseHandle(g_mmapHandle); g_mmapHandle = nullptr; }
    if (g_mmapFile)  { CloseHandle(g_mmapFile); g_mmapFile = nullptr; }
    g_mmapHeader = nullptr;
    g_mmapEvents = nullptr;
}

static void mmap_push(const EtwEvent& ev) {
    if (!g_mmapBase || !g_mmapHeader) return;
    EnterCriticalSection(&g_mmapLock);
    EtwDiskEvent de;
    memset(&de, 0, sizeof(de));
    de.provider   = ev.provider;
    de.eventId    = ev.eventId;
    de.sourcePid  = ev.sourcePid;
    de.targetPid  = ev.targetPid;
    de.parentPid  = ev.parentPid;
    memcpy(de.image,     ev.image,     sizeof(de.image)     < sizeof(ev.image)     ? sizeof(de.image)     : sizeof(ev.image));
    memcpy(de.imageName, ev.imageName, sizeof(de.imageName) < sizeof(ev.imageName) ? sizeof(de.imageName) : sizeof(ev.imageName));
    memcpy(de.detail,    ev.detail,    sizeof(de.detail)    < sizeof(ev.detail)    ? sizeof(de.detail)    : sizeof(ev.detail));
    memcpy(de.rule,      ev.rule,      sizeof(de.rule)      < sizeof(ev.rule)      ? sizeof(de.rule)      : sizeof(ev.rule));
    de.severity   = ev.severity;
    de.timestamp  = ev.timestamp;
    de.suspicious = ev.suspicious ? TRUE : FALSE;

    LONG idx = g_mmapHeader->tail;
    g_mmapEvents[idx] = de;
    g_mmapHeader->tail = (g_mmapHeader->tail + 1) % DISK_EVENT_CAP;
    if (g_mmapHeader->count < DISK_EVENT_CAP) g_mmapHeader->count++;
    else g_mmapHeader->head = (g_mmapHeader->head + 1) % DISK_EVENT_CAP;
    g_mmapHeader->lastWrite = GetTickCount64();
    LeaveCriticalSection(&g_mmapLock);
}

// ========================================================================
// 事件分发
// ========================================================================
static void handle_user_event(int prov, const EVENT_RECORD* rec, EtwEvent& ev) {
    ev.provider = prov;
    bool hit = false;
    switch (prov) {
        case PROV_TI:         hit = analyze_ti(rec, ev); break;
        case PROV_KPROC:      hit = analyze_kproc(rec, ev); break;
        case PROV_DNS:        hit = analyze_dns(rec, ev); break;
        case PROV_POWERSHELL: hit = analyze_powershell(rec, ev); break;
        case PROV_WMI:        hit = analyze_wmi(rec, ev); break;
        case PROV_DOTNET:     hit = analyze_dotnet(rec, ev); break;
        case PROV_SYSMON:     hit = analyze_sysmon(rec, ev); break;
        case PROV_KFILE:      hit = analyze_kfile(rec, ev); break;
        case PROV_KREG:       hit = analyze_kreg(rec, ev); break;
        default: return;
    }
    etw_provider_note_capture(prov, hit);

    // 粗筛：只保留命中规则（suspicious）或高价值事件
    bool highValue = (!hit && etw_is_high_value_event(prov, ev.eventId));
    if (!hit && !highValue) return;   // 无价值事件直接丢弃

    // 限流检查
    if (!etw_rate_check(prov)) return;

    if (hit) {
        ev.suspicious = true;
        DWORD src = ev.sourcePid ? ev.sourcePid : rec->EventHeader.ProcessId;
        behavior_record(src, ev.rule, ev.severity);
    }
    etw_queue_push_filtered(ev);
}

// 旧式内核日志回退（ProviderId = SystemTraceControlGuid 时按事件 ID 路由）
static void handle_kernel_legacy(const EVENT_RECORD* rec, EtwEvent& ev) {
    DWORD id = ev.eventId;
    int prov = -1;
    bool hit = false;
    // 进程/线程/镜像 1-10
    if (id <= 10)      { prov = PROV_KPROC; hit = analyze_kproc(rec, ev); }
    // 文件 12-17 / 20-31
    else if (id >= 12 && id <= 31) { prov = PROV_KFILE; hit = analyze_kfile(rec, ev); }
    // 注册表 11 / 32+（旧式注册表事件较低频，兜底）
    else              { prov = PROV_KREG;  hit = analyze_kreg(rec, ev); }

    etw_provider_note_capture(prov, hit);

    // 粗筛：只保留命中规则或高价值事件
    bool highValue = (!hit && etw_is_high_value_event(prov, id));
    if (!hit && !highValue) return;

    // 限流检查
    if (!etw_rate_check(prov)) return;

    if (hit) {
        ev.suspicious = true;
        DWORD src = ev.sourcePid ? ev.sourcePid : rec->EventHeader.ProcessId;
        behavior_record(src, ev.rule, ev.severity);
    }
    etw_queue_push_filtered(ev);
}

static void WINAPI event_callback(EVENT_RECORD* record) {
    if (!record) return;
    EtwEvent ev;
    memset(&ev, 0, sizeof(ev));
    ev.eventId = record->EventHeader.EventDescriptor.Id;
    ev.timestamp = record->EventHeader.TimeStamp.QuadPart;

    const GUID& pid = record->EventHeader.ProviderId;
    int prov = etw_provider_index(&pid);
    if (prov >= 0) {
        handle_user_event(prov, record, ev);
        return;
    }
    // 旧式内核日志回退
    if (memcmp(&pid, &SystemTraceControlGuid, sizeof(GUID)) == 0)
        handle_kernel_legacy(record, ev);
}

// ========================================================================
// 消费线程
// ========================================================================
static DWORD WINAPI consume_loop(LPVOID) {
    EVENT_TRACE_LOGFILEW logfile;
    memset(&logfile, 0, sizeof(logfile));
    logfile.LoggerName = (LPWSTR)ETW_SESSION_NAME;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                               PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)event_callback;
    logfile.BufferCallback = nullptr;

    g_traceHandle = OpenTraceW(&logfile);
    if (g_traceHandle == (TRACEHANDLE)INVALID_PROCESSTRACE_HANDLE) {
        g_etwRunning = false;
        return 1;
    }
    ProcessTrace(&g_traceHandle, 1, nullptr, nullptr);
    CloseTrace(g_traceHandle);
    g_traceHandle = 0;
    g_etwRunning = false;
    return 0;
}

// ========================================================================
// 监控线程：Provider 健康 + 事件关联引擎
// ========================================================================
static volatile LONG g_lastCapturedSnapshot = 0;

static DWORD WINAPI monitor_loop(LPVOID) {
    while (g_etwRunning) {
        Sleep(5000);
        if (!g_etwRunning) break;

        // 事件关联引擎（周期性运行，扫描全部进程行为）
        run_correlation();

        // Provider 健康：事件是否仍在流动
        LONG cur = g_capturedTotal;
        if (cur == g_lastCapturedSnapshot && g_sessionHandle != 0) {
            // 10 秒以上无新事件 → 记录（供 health 查询）
            // （不断言故障，某些 Provider 静默期属正常）
        }
        g_lastCapturedSnapshot = cur;
    }
    return 0;
}

// ========================================================================
// 导出 API
// ========================================================================

/**
 * 启动 ETW 多 Provider 事中检测
 */
extern "C" __declspec(dllexport) char* guard_etw_start() {
    ensure_locks();

    if (g_etwRunning)
        return alloc_str("{\"success\":true,\"already_running\":true}");

    if (!enable_debug_privilege())
        return alloc_str("{\"success\":false,\"error\":\"SeDebugPrivilege 开启失败\"}");

    // 初始化限流
    init_rate_limits();

    // 加载持久化历史
    g_recovered.clear();
    mmap_open();

    // 创建实时会话
    ULONG propsSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(ETW_SESSION_NAME) + sizeof(wchar_t) * 64;
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
    if (!props) return alloc_str("{\"success\":false,\"error\":\"alloc failed\"}");
    memset(props, 0, propsSize);
    props->Wnode.BufferSize = propsSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;               // QPC 时间戳
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->MinimumBuffers = 4;
    props->MaximumBuffers = 16;

    ULONG status = StartTraceW(&g_sessionHandle, ETW_SESSION_NAME, props);
    free(props);

    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "{\"success\":false,\"error\":\"StartTrace failed 0x%lX\"}", status);
        return alloc_str(buf);
    }
    if (status == ERROR_ALREADY_EXISTS) {
        stop_etw_session();
        Sleep(300);
        props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
        memset(props, 0, propsSize);
        props->Wnode.BufferSize = propsSize;
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 1;
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        props->MinimumBuffers = 4;
        props->MaximumBuffers = 16;
        status = StartTraceW(&g_sessionHandle, ETW_SESSION_NAME, props);
        free(props);
        if (status != ERROR_SUCCESS) {
            char buf[160];
            snprintf(buf, sizeof(buf),
                "{\"success\":false,\"error\":\"StartTrace retry failed 0x%lX, 会话可能被其他程序占用\"}",
                status);
            return alloc_str(buf);
        }
    }

    // 启用各 Provider（逐个尝试，失败不影响其它）
    int enabledOk = 0, failed = 0;
    std::string failedNames;
    for (int i = 0; i < PROV_MAX; i++) {
        if (!g_providerEnabled[i]) continue;
        ULONG st = EnableTraceEx2(g_sessionHandle, &PROVIDER_GUIDS[i],
                                  EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                  TRACE_LEVEL_VERBOSE, 0xFFFFFFFF, 0, 0, nullptr);
        if (st != ERROR_SUCCESS) {
            g_providerEnableOk[i] = false;
            failed++;
            if (!failedNames.empty()) failedNames += ",";
            failedNames += PROVIDER_NAMES[i];
        } else {
            g_providerEnableOk[i] = true;
            enabledOk++;
        }
    }

    if (enabledOk == 0) {
        stop_etw_session();
        g_sessionHandle = 0;
        char buf[256];
        snprintf(buf, sizeof(buf),
            "{\"success\":false,\"error\":\"无 Provider 启用成功(0x%lX), 需要管理员/SYSTEM 权限\",\"failed\":\"%s\"}",
            status, failedNames.c_str());
        return alloc_str(buf);
    }

    g_etwRunning = true;
    g_etwEverStarted = true;
    g_lastCapturedSnapshot = 0;
    g_consumeThread = CreateThread(nullptr, 0, consume_loop, nullptr, 0, nullptr);
    g_monitorThread = CreateThread(nullptr, 0, monitor_loop, nullptr, 0, nullptr);

    std::string json = "{\"success\":true,\"status\":\"running\",\"enabled\":"
        + std::to_string(enabledOk) + ",\"failed\":" + std::to_string(failed)
        + ",\"failed_names\":\"" + json_escape(failedNames) + "\"}";
    return alloc_str(json.c_str());
}

/**
 * 停止 ETW 检测
 */
extern "C" __declspec(dllexport) char* guard_etw_stop() {
    if (g_sessionHandle) {
        stop_etw_session();
        g_sessionHandle = 0;
    }
    g_etwRunning = false;
    if (g_consumeThread) {
        WaitForSingleObject(g_consumeThread, 3000);
        g_consumeThread = nullptr;
    }
    if (g_monitorThread) {
        WaitForSingleObject(g_monitorThread, 2000);
        g_monitorThread = nullptr;
    }
    mmap_close();
    g_recovered.clear();
    return alloc_str("{\"success\":true,\"status\":\"stopped\"}");
}

/**
 * 获取状态（含各 Provider 启用/捕获/告警）
 */
extern "C" __declspec(dllexport) char* guard_etw_status() {
    std::string json = "{\"running\":";
    json += g_etwRunning ? "true" : "false";
    json += ",\"session_active\":"; json += etw_session_active() ? "true" : "false";
    json += ",\"events_captured\":"; json += std::to_string((LONG)g_capturedTotal);
    json += ",\"suspicious\":"; json += std::to_string((LONG)g_suspiciousTotal);
    json += ",\"queue_size\":"; json += std::to_string(g_qCount);
    json += ",\"queue_hard_cap\":"; json += std::to_string(ETW_QUEUE_HARD_CAP);
    json += ",\"recovered_history\":"; json += std::to_string((int)g_recovered.size());

    // 限流统计（etw_rate_stats_json 输出从 "rate_limits" 开始，需补分隔逗号）
    json += ",";
    etw_rate_stats_json(json);

    json += ",\"providers\":[";
    for (int i = 0; i < PROV_MAX; i++) {
        if (i) json += ",";
        char buf[512];
        snprintf(buf, sizeof(buf),
            "{\"id\":%d,\"name\":\"%s\",\"enabled\":%s,\"enable_ok\":%s,"
            "\"captured\":%ld,\"suspicious\":%ld}",
            i, PROVIDER_NAMES[i],
            g_providerEnabled[i] ? "true" : "false",
            g_providerEnableOk[i] ? "true" : "false",
            g_providerCaptured[i], g_providerSuspicious[i]);
        json += buf;
    }
    json += "]}";
    return alloc_str(json.c_str());
}

/**
 * 获取事件队列（含恢复的历史），获取后清空
 */
extern "C" __declspec(dllexport) char* guard_etw_get_events() {
    std::string json = "{\"events\":[";
    bool first = true;

    ensure_locks();   // 未启动 ETW 直接查询时，必须先初始化临界区，否则解锁未初始化对象触发 0xC0000005

    // 恢复的历史（会话重启后不丢失）
    EnterCriticalSection(&g_queueLock);
    for (auto& ev : g_recovered) {
        if (!first) json += ",";
        first = false;
        json += event_to_json(ev, true);
    }
    g_recovered.clear();

    // 实时队列
    for (int i = 0; i < g_qCount; i++) {
        EtwEvent& ev = g_events[(g_qHead + i) % ETW_MAX_EVENTS];
        if (!first) json += ",";
        first = false;
        json += event_to_json(ev, false);
    }
    g_qHead = 0;
    g_qCount = 0;
    LeaveCriticalSection(&g_queueLock);

    json += "]}";
    return alloc_str(json.c_str());
}

/**
 * 事件关联引擎：获取攻击链事件（可选清空）
 */
extern "C" __declspec(dllexport) char* guard_etw_get_correlations() {
    ensure_locks();   // 同上：防止 ETW 未启动时访问未初始化临界区
    std::string json = "{\"correlations\":" + correlation_events_json(true) + "}";
    return alloc_str(json.c_str());
}

/**
 * 进程树行为评分：按风险分输出 Top N 进程及子树评分
 */
extern "C" __declspec(dllexport) char* guard_etw_process_tree(int topN) {
    if (topN <= 0) topN = 20;
    if (topN > 200) topN = 200;

    ensure_locks();   // 同上：防止 ETW 未启动时访问未初始化临界区

    // 计算所有进程的子树评分（带缓存）
    std::map<DWORD, int> cache;
    std::vector<std::pair<int, DWORD>> ranked;   // (treeScore, pid)

    EnterCriticalSection(&g_procLock);
    std::vector<DWORD> pids;
    for (auto& kv : g_procTable) pids.push_back(kv.first);
    LeaveCriticalSection(&g_procLock);

    for (DWORD pid : pids) {
        int ts = proc_tree_score(pid, cache);
        ranked.push_back(std::make_pair(ts, pid));
    }
    // 按子树评分降序
    std::sort(ranked.begin(), ranked.end(),
              [](const std::pair<int,DWORD>& a, const std::pair<int,DWORD>& b) {
                  return a.first > b.first;
              });

    std::string json = "{\"processes\":[";
    int shown = 0;
    for (auto& r : ranked) {
        if (shown >= topN) break;
        DWORD pid = r.second;
        ProcInfo pi;
        if (!proc_table_lookup(pid, pi)) continue;
        if (r.first <= 0 && pi.score <= 0) continue;   // 零风险进程不输出
        if (shown) json += ",";
        shown++;
        char buf[1536];
        snprintf(buf, sizeof(buf),
            "{\"pid\":%lu,\"parent_pid\":%lu,\"name\":\"%s\","
            "\"image\":\"%s\",\"own_score\":%d,\"tree_score\":%d,"
            "\"first_seen\":%llu}",
            pid, pi.parentPid, json_escape(pi.name).c_str(),
            json_escape(pi.image).c_str(), pi.score, r.first,
            (unsigned long long)pi.firstSeen);
        json += buf;
    }
    json += "],\"total\":";
    json += std::to_string((int)ranked.size());
    json += "}";
    return alloc_str(json.c_str());
}

/**
 * Provider 健康监控：会话存活 + 事件流动 + 各 Provider 捕获情况
 */
extern "C" __declspec(dllexport) char* guard_etw_health() {
    bool active = etw_session_active();
    LONG now = g_capturedTotal;
    LONG delta = now - g_lastCapturedSnapshot;
    g_lastCapturedSnapshot = now;

    char buf[1024];
    snprintf(buf, sizeof(buf),
        "{\"running\":%s,\"session_active\":%s,\"flowing\":%s,"
        "\"events_since_last_poll\":%ld,\"total_captured\":%ld,"
        "\"total_suspicious\":%ld,\"ever_started\":%s}",
        g_etwRunning ? "true" : "false",
        active ? "true" : "false",
        (active && delta >= 0) ? "true" : "false",
        delta, (LONG)g_capturedTotal, (LONG)g_suspiciousTotal,
        g_etwEverStarted ? "true" : "false");
    return alloc_str(buf);
}
