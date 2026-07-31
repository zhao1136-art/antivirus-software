/**
 * ETW 事中检测模块（升级一：事件驱动）
 *
 * 订阅 Microsoft-Windows-Threat-Intelligence Provider：
 *   - EventId 9  RemoteThreadCreated  → 远程线程注入（实时）
 *   - EventId 4  ProcessInjection     → 进程注入组合行为
 *   - EventId 5  ProcessTampering     → 进程篡改
 *   - EventId 3  DriverLoad           → 内核驱动加载
 *
 * 相比轮询快照（scan_threads），本模块在注入发生的瞬间收到通知，
 * 将检测从"事后发现现场"升级为"事中接到报警"。
 *
 * 权限：需要管理员 + SeDebugPrivilege
 * 局限：仅 Win10 1903+；实时会话同一时间仅一个创建者。
 */
#include "native_guard.h"
#include <evntrace.h>
#include <evntprov.h>
#include <evntcons.h>

#pragma comment(lib, "advapi32.lib")

// Microsoft-Windows-Threat-Intelligence Provider GUID
// 验证: logman query providers | grep Threat-Intelligence → {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
static const GUID TP_PROVIDER_GUID =
    {0xF4E1897C, 0xBB5D, 0x5668, {0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44}};

#define ETW_SESSION_NAME L"AndunETW"
#define ETW_MAX_EVENTS 256

// 事件记录（供 Python 查询）
struct EtwEvent {
    DWORD eventId;
    DWORD sourcePid;
    DWORD targetPid;
    ULONG64 startAddress;
    char sourceModule[128];
    char targetModule[128];
    ULONGLONG timestamp;
    bool suspicious;
};

static TRACEHANDLE g_sessionHandle = 0;   // 实时会话句柄
static TRACEHANDLE g_traceHandle = 0;     // 消费句柄
static HANDLE g_consumeThread = nullptr;
static volatile bool g_etwRunning = false;

// 事件队列（环形缓冲简化版）
static EtwEvent g_events[ETW_MAX_EVENTS];
static volatile LONG g_eventCount = 0;
static CRITICAL_SECTION g_queueLock;

// ========================================================================
// 工具：启用 SeDebugPrivilege
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

// ========================================================================
// 工具：停止 ETW 会话（ControlTraceW 需要属性缓冲区，不能传 null）
// ========================================================================
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

// ========================================================================
// 事件队列
// ========================================================================
static void queue_push(const EtwEvent& ev) {
    EnterCriticalSection(&g_queueLock);
    LONG idx = InterlockedIncrement(&g_eventCount) - 1;
    if (idx >= ETW_MAX_EVENTS) {
        // 溢出则丢弃最旧（简单环形：重置计数会导致队列短，此处直接丢弃新事件保留最近）
        InterlockedDecrement(&g_eventCount);
        LeaveCriticalSection(&g_queueLock);
        return;
    }
    g_events[idx] = ev;
    LeaveCriticalSection(&g_queueLock);
}

// 解析 UnicodeString（防御性读取：Length + Buffer 指针）
static void read_unicode_string(PCWCHAR data, DWORD maxLen, char* out, DWORD outSize) {
    out[0] = 0;
    if (!data || maxLen < 8) return;
    USHORT len = *(USHORT*)data;          // +0 Length
    // +2 MaximumLength, +4/8 Buffer 指针（64位下 8 字节对齐到 +8）
#ifdef _WIN64
    PCWCHAR buf = *(PCWCHAR*)(data + 8);
#else
    PCWCHAR buf = *(PCWCHAR*)(data + 4);
#endif
    if (!buf || len == 0 || len > maxLen) return;
    // 防止越界：len 是字节数
    DWORD chars = len / 2;
    if (chars >= outSize) chars = outSize - 1;
    for (DWORD i = 0; i < chars; i++) {
        wchar_t wc = buf[i];
        if (wc < 0x80) out[i] = (char)wc;
        else out[i] = '?';
    }
    out[chars] = 0;
}

// ========================================================================
// ETW 回调：处理事件
// ========================================================================
static ULONG WINAPI buffer_callback(EVENT_TRACE_LOGFILEW* logfile) {
    // 返回 TRUE 继续
    (void)logfile;
    return TRUE;
}

static void WINAPI event_callback(EVENT_RECORD* record) {
    if (!record) return;

    // 只处理 Threat-Intelligence provider 的事件
    if (memcmp(&record->EventHeader.ProviderId, &TP_PROVIDER_GUID, sizeof(GUID)) != 0)
        return;

    EtwEvent ev;
    memset(&ev, 0, sizeof(ev));
    ev.eventId = record->EventHeader.EventDescriptor.Id;
    ev.timestamp = record->EventHeader.TimeStamp.QuadPart;

    // 事件头 UserData 含 SourceProcessId (Win10 1809+ 增强头)
    // 从事件头提取：增强头在 HeaderSize 之后
    BYTE* userData = (BYTE*)record->UserData;
    DWORD userLen = record->UserDataLength;

    // 防御性解析 payload（按 TP provider manifest 布局）
    // 通用布局（各事件类似）:
    //   +0  SourceProcessId   UINT32
    //   +4  SourceThreadId    UINT32
    //   +8  TargetProcessId   UINT32
    //   +12 TargetThreadId    UINT32
    //   +16 (StartAddress / Handle / 其他)
    if (userData && userLen >= 12) {
        ev.sourcePid = *(DWORD*)(userData + 0);
        ev.targetPid = *(DWORD*)(userData + 8);

        // RemoteThreadCreated (9) / ProcessInjection (4): +16 附近是 StartAddress
        if (userLen >= 24) {
            memcpy(&ev.startAddress, userData + 16, sizeof(ULONG64));
        }

        // 尝试解析 StartModule/StartFunction（UnicodeString，通常在前 32-64 字节区）
        if (userLen >= 32) {
            read_unicode_string((PCWCHAR)(userData + 32), userLen - 32,
                                ev.sourceModule, sizeof(ev.sourceModule));
        }
    }

    // 获取目标进程名
    get_process_name_by_pid(ev.targetPid);

    // 可疑判定：
    //  - 事件本身（TP provider 只在可疑行为时发事件）
    //  - RemoteThreadCreated: 来源进程 != 目标进程（跨进程远程线程 = 注入）
    bool suspicious = false;
    switch (ev.eventId) {
        case 3:  // DriverLoad
            suspicious = false;  // 记录但不告警（驱动加载量大）
            break;
        case 4:  // ProcessInjection
        case 5:  // ProcessTampering
            suspicious = true;
            break;
        case 9:  // RemoteThreadCreated
            // 跨进程远程线程 = 注入特征；同进程（如线程池）不告警
            suspicious = (ev.sourcePid != ev.targetPid && ev.sourcePid != 0 && ev.targetPid != 0);
            break;
        default:
            suspicious = (ev.sourcePid != ev.targetPid && ev.sourcePid != 0 && ev.targetPid != 0);
            break;
    }
    ev.suspicious = suspicious;

    // 只有可疑事件入队（减少噪音）
    if (suspicious) {
        queue_push(ev);
    }
}

// ========================================================================
// 消费线程：ProcessTrace 阻塞
// ========================================================================
static DWORD WINAPI consume_loop(LPVOID) {
    EVENT_TRACE_LOGFILEW logfile;
    memset(&logfile, 0, sizeof(logfile));
    logfile.LoggerName = (LPWSTR)ETW_SESSION_NAME;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                               PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)event_callback;
    logfile.BufferCallback = (PEVENT_TRACE_BUFFER_CALLBACKW)buffer_callback;

    g_traceHandle = OpenTraceW(&logfile);
    if (g_traceHandle == (TRACEHANDLE)INVALID_PROCESSTRACE_HANDLE) {
        g_etwRunning = false;
        return 1;
    }

    // 阻塞直到 StopTrace / 出错
    ProcessTrace(&g_traceHandle, 1, nullptr, nullptr);
    CloseTrace(g_traceHandle);
    g_traceHandle = 0;
    g_etwRunning = false;
    return 0;
}

// ========================================================================
// 导出 API
// ========================================================================

/**
 * 启动 ETW 事中检测
 */
extern "C" __declspec(dllexport) char* guard_etw_start() {
    if (g_etwRunning) {
        return alloc_str("{\"success\":true,\"already_running\":true}");
    }

    // 需要管理员
    if (!enable_debug_privilege()) {
        return alloc_str("{\"success\":false,\"error\":\"SeDebugPrivilege 开启失败\"}");
    }

    InitializeCriticalSection(&g_queueLock);

    // 1. 创建实时会话
    EVENT_TRACE_PROPERTIES* props = nullptr;
    ULONG propsSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(ETW_SESSION_NAME) + sizeof(wchar_t) * 64;
    props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
    if (!props) return alloc_str("{\"success\":false,\"error\":\"alloc failed\"}");
    memset(props, 0, propsSize);
    props->Wnode.BufferSize = propsSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  // QPC 时间戳
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->MinimumBuffers = 2;
    props->MaximumBuffers = 8;

    ULONG status = StartTraceW(&g_sessionHandle, ETW_SESSION_NAME, props);
    free(props);

    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        char buf[128];
        snprintf(buf, sizeof(buf), "{\"success\":false,\"error\":\"StartTrace failed 0x%lX\"}", status);
        return alloc_str(buf);
    }

    if (status == ERROR_ALREADY_EXISTS) {
        // 会话残留（上次崩溃/未清理）→ 先停止（需属性缓冲区），等待释放，再重建
        stop_etw_session();
        Sleep(300);
        props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
        memset(props, 0, propsSize);
        props->Wnode.BufferSize = propsSize;
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 1;
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        props->MinimumBuffers = 2;
        props->MaximumBuffers = 8;
        status = StartTraceW(&g_sessionHandle, ETW_SESSION_NAME, props);
        free(props);
        if (status != ERROR_SUCCESS) {
            char buf[160];
            snprintf(buf, sizeof(buf), "{\"success\":false,\"error\":\"StartTrace retry failed 0x%lX, 会话可能被其他程序占用\"}", status);
            return alloc_str(buf);
        }
    }

    // 2. 启用 TP provider
    ULONG64 matchAnyKeyword = 0xFFFFFFFF;  // 全部关键字
    status = EnableTraceEx2(g_sessionHandle, &TP_PROVIDER_GUID,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE, matchAnyKeyword, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        stop_etw_session();
        char buf[256];
        snprintf(buf, sizeof(buf),
            "{\"success\":false,\"error\":\"EnableTraceEx2 failed 0x%lX, "
            "Threat-Intelligence provider 需要 SYSTEM 权限(以管理员/计划任务 SYSTEM 身份运行可解决), "
            "已自动回退轮询兜底\"}",
            status);
        return alloc_str(buf);
    }

    // 3. 启动消费线程
    g_etwRunning = true;
    g_consumeThread = CreateThread(nullptr, 0, consume_loop, nullptr, 0, nullptr);

    return alloc_str("{\"success\":true,\"status\":\"running\"}");
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
        // ProcessTrace 在会话停止后返回，线程自行结束
        WaitForSingleObject(g_consumeThread, 3000);
        g_consumeThread = nullptr;
    }
    DeleteCriticalSection(&g_queueLock);
    return alloc_str("{\"success\":true,\"status\":\"stopped\"}");
}

/**
 * 获取状态
 */
extern "C" __declspec(dllexport) char* guard_etw_status() {
    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"running\":%s,\"events_captured\":%ld}",
        g_etwRunning ? "true" : "false",
        (LONG)g_eventCount);
    return alloc_str(buf);
}

/**
 * 获取事件队列（JSON 数组），并清空
 */
extern "C" __declspec(dllexport) char* guard_etw_get_events() {
    std::string json = "{\"events\":[";
    bool first = true;
    LONG count = (LONG)g_eventCount;

    EnterCriticalSection(&g_queueLock);
    for (LONG i = 0; i < count && i < ETW_MAX_EVENTS; i++) {
        EtwEvent& ev = g_events[i];
        if (!first) json += ",";
        first = false;

        char buf[1024];
        snprintf(buf, sizeof(buf),
            "{\"event_id\":%lu,\"source_pid\":%lu,\"target_pid\":%lu,"
            "\"start_addr\":\"0x%llX\",\"source_module\":\"%s\",\"suspicious\":%s}",
            ev.eventId, ev.sourcePid, ev.targetPid,
            (unsigned long long)ev.startAddress,
            json_escape(ev.sourceModule).c_str(),
            ev.suspicious ? "true" : "false");
        json += buf;
    }
    // 清空队列
    InterlockedExchange(&g_eventCount, 0);
    LeaveCriticalSection(&g_queueLock);

    json += "]}";
    return alloc_str(json.c_str());
}
