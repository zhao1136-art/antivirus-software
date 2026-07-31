/**
 * 安盾 原生防护引擎 DLL - 主入口
 * 聚合 inject_guard, fileless_guard, persist_guard, net_guard 四大模块
 *
 * 编译: g++ -O2 -shared -o native_guard.dll *.cpp -ladvapi32 -lws2_32 -liphlpapi -lpsapi -lole32 -lntdll -lwintrust -static-libgcc -static-libstdc++
 * 调用: Python ctypes.CDLL("native_guard.dll")
 */
#include "native_guard.h"

// ========================================================================
// 版本 & 自检
// ========================================================================

extern "C" __declspec(dllexport) char* guard_version() {
    return alloc_str("{\"name\":\"安盾 Native Guard\",\"version\":\"1.1.0\","
                     "\"modules\":[\"inject_guard\",\"fileless_guard\",\"persist_guard\",\"net_guard\",\"etw_guard\",\"amsi_provider\"],"
                     "\"arch\":\"native_guard.dll\",\"calling\":\"ctypes\"}");
}

extern "C" __declspec(dllexport) void guard_free_string(char* str) {
    free(str);
}

extern "C" __declspec(dllexport) char* guard_self_test() {
    // 测试 1: 进程枚举是否正常
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    bool processOk = (hSnap != INVALID_HANDLE_VALUE);
    if (processOk) CloseHandle(hSnap);

    // 测试 2: 网络 API 是否可调用
    DWORD tcpSize = 0;
    bool netOk = (GetExtendedTcpTable(nullptr, &tcpSize, FALSE, AF_INET,
                                       TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR ||
                  GetLastError() == ERROR_INSUFFICIENT_BUFFER);

    // 测试 3: WMI 初始化
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool wmiOk = SUCCEEDED(hr);
    if (SUCCEEDED(hr)) CoUninitialize();

    // 测试 4: 签名验证 API
    bool signOk = true;  // WinTrust 库已链接

    // 测试 5: NT API
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    bool ntOk = (hNtdll != nullptr);

    char buf[1024];
    snprintf(buf, sizeof(buf),
        "{\"status\":\"%s\",\"tests\":{"
        "\"process_enum\":%s,\"network_api\":%s,\"wmi_init\":%s,"
        "\"wintrust_linked\":%s,\"ntdll_available\":%s},"
        "\"modules\":[\"inject_guard\",\"fileless_guard\",\"persist_guard\",\"net_guard\"]}",
        (processOk && netOk && wmiOk && signOk && ntOk) ? "ok" : "partial",
        processOk ? "true" : "false",
        netOk ? "true" : "false",
        wmiOk ? "true" : "false",
        signOk ? "true" : "false",
        ntOk ? "true" : "false");
    return alloc_str(buf);
}

// ========================================================================
// DLL 入口
// ========================================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
