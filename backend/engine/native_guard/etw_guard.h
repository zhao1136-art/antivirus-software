/**
 * ETW 多 Provider 事中检测 - 内部共享定义
 *
 * 由 etw_guard.cpp（会话/队列/进程表/导出）与 etw_rules.cpp（检测规则）
 * 共同包含，供两者相互调用。
 */
#pragma once
#include "native_guard.h"
#include <evntrace.h>
#include <evntcons.h>
#include <evntprov.h>

#pragma comment(lib, "advapi32.lib")

// ========================================================================
// Provider 枚举
// ========================================================================
enum EtwProviderId {
    PROV_TI = 0,        // Microsoft-Windows-Threat-Intelligence
    PROV_KPROC,         // Microsoft-Windows-Kernel-Process
    PROV_DNS,           // Microsoft-Windows-DNS-Client
    PROV_POWERSHELL,    // Microsoft-Windows-PowerShell
    PROV_WMI,           // Microsoft-Windows-WMI-Activity
    PROV_DOTNET,        // Microsoft-Windows-DotNETRuntime
    PROV_SYSMON,        // Microsoft-Windows-Sysmon
    PROV_KFILE,         // Microsoft-Windows-Kernel-File
    PROV_KREG,          // Microsoft-Windows-Kernel-Registry
    PROV_MAX
};

// ========================================================================
// 事件记录（统一抽象，供 Python 消费）
// ========================================================================
struct EtwEvent {
    int      provider;      // EtwProviderId
    DWORD    eventId;       // 原始事件 ID
    DWORD    sourcePid;     // 来源进程（注入者/父进程/查询进程）
    DWORD    targetPid;     // 目标进程（0 表示无）
    DWORD    parentPid;     // 进程链：父进程
    char     image[MAX_PATH_LEN];      // 镜像/模块完整路径
    char     imageName[128];           // 镜像文件名
    char     detail[512];              // 详情（DNS 域名/脚本片段/注册表路径/管道名）
    char     rule[80];                 // 命中检测规则名
    int      severity;                 // 0低 1中 2高 3严重
    ULONGLONG timestamp;               // QPC 时间戳
    bool     suspicious;               // 是否告警
};

// ========================================================================
// 进程树/行为评分记录
// ========================================================================
struct ProcInfo {
    DWORD      pid;
    DWORD      parentPid;
    char       image[MAX_PATH_LEN];
    char       name[128];
    char       cmdline[MAX_CMD_LINE];
    int        score;          // 行为风险分（跨 Provider 累加）
    ULONGLONG  firstSeen;
};

// ========================================================================
// 分析器（etw_rules.cpp 实现）
// 返回 true 表示该事件命中规则（ev 已被填充）
// ========================================================================
bool analyze_ti(const EVENT_RECORD* rec, EtwEvent& ev);
bool analyze_kproc(const EVENT_RECORD* rec, EtwEvent& ev);
bool analyze_dns(const EVENT_RECORD* rec, EtwEvent& ev);
bool analyze_powershell(const EVENT_RECORD* rec, EtwEvent& ev);
bool analyze_wmi(const EVENT_RECORD* rec, EtwEvent& ev);
bool analyze_dotnet(const EVENT_RECORD* rec, EtwEvent& ev);
bool analyze_sysmon(const EVENT_RECORD* rec, EtwEvent& ev);
bool analyze_kfile(const EVENT_RECORD* rec, EtwEvent& ev);
bool analyze_kreg(const EVENT_RECORD* rec, EtwEvent& ev);

// ========================================================================
// 进程表（etw_guard.cpp 实现）
// ========================================================================
void proc_table_update(DWORD pid, DWORD parent, const char* image,
                       const char* name, const char* cmdline);
void proc_table_remove(DWORD pid);
void proc_table_add_score(DWORD pid, int score);
bool proc_table_lookup(DWORD pid, ProcInfo& out);   // 线程安全：拷贝返回

// ========================================================================
// 行为跟踪 + 事件关联引擎（etw_guard.cpp 实现）
// ========================================================================
void behavior_record(DWORD pid, const char* rule, int severity);   // 记录进程行为
std::string correlation_events_json(bool drain);                   // 攻击链事件

// ========================================================================
// 事件队列（etw_guard.cpp 实现）
// ========================================================================
void etw_queue_push(EtwEvent& ev);

// ========================================================================
// Provider 状态（etw_guard.cpp 实现）
// ========================================================================
int  etw_provider_index(const GUID* g);
const char* etw_provider_name(int idx);
void etw_provider_note_capture(int idx, bool susp);
long etw_provider_captured(int idx);
long etw_provider_suspicious(int idx);
bool etw_provider_is_enabled(int idx);
void etw_provider_set_enabled(int idx, bool en);

// ETW 会话是否存活（健康监控 / 防篡改）
bool etw_session_active();

// ========================================================================
// 限流与过滤（etw_guard.cpp 实现）
// ========================================================================
// 每 Provider 速率上限（事件/秒），0 表示不限流
#define RATE_LIMIT_DEFAULT    100     // 默认：100 事件/秒
#define RATE_LIMIT_DNS        200     // DNS 查询高频，适当放宽
#define RATE_LIMIT_KPROC      150     // 进程事件次高频
#define RATE_LIMIT_KFILE      120     // 文件事件

// 总队列上限（超过后触发背压丢弃）
#define QUEUE_CAP_HARD        10000

// 高价值 EventId：即使未命中规则也保留（仅限关键事件类型）
// Kernel-Process: 1(Start), 2(Stop)
// Kernel-File:     12(Create), 30(CreateNewFile), 31(Rename)
// Kernel-Registry:  1(CreateKey), 2(OpenKey), 5(SetValue), 22(DeleteKey)
// DNS:              3006(Query), 3008(Response)
// PowerShell:       4104(ScriptBlock), 4103(Execute), 800(EngineLifecycle)
// WMI:              11(Consumer), 22(Filter), 23(Binding)
// Sysmon:           1(ProcessCreate), 3(NetworkConnect), 7(ImageLoad), 11(FileCreate)
// TI:               1(ReadProcessMemory), 12(RemoteThread), 17(QueueUserAPC)
bool etw_is_high_value_event(int provider, DWORD eventId);

// 每 Provider 速率检查（token bucket），返回 true 表示放行
bool etw_rate_check(int provider);

// 背压入队：满队列时按严重性替换
void etw_queue_push_filtered(EtwEvent& ev);

// 获取速率统计（供 Python 查询）
void etw_rate_stats_json(std::string& out);
