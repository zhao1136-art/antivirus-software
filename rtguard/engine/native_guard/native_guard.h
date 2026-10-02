/**
 * 御天 原生防护引擎 - 公共定义
 * 编译: g++ -O2 -shared -o native_guard.dll *.cpp -ladvapi32 -lws2_32 -liphlpapi -lpsapi -lole32 -lwintrust -ldbghelp -lwbemuuid -static-libgcc -static-libstdc++
 * 调用: Python ctypes.CDLL 直接加载
 */
#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602   // Windows 8+：启用 EnableTraceEx2 / OpenTraceW 等 API
#endif
#ifndef WINVER
#define WINVER 0x0602
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <wintrust.h>
#include <softpub.h>
#include <dbghelp.h>
#include <wbemidl.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <vector>
#include <string>
#include <algorithm>
#include <set>
#include <map>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "wbemuuid.lib")

#define MAX_PATH_LEN 4096
#define MAX_CMD_LINE 8192

// ============== Unicode/UTF8 工具 ==============
static inline std::wstring utf8_to_wide(const char* str) {
    if (!str) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
    std::wstring result(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str, -1, &result[0], len);
    return result;
}

static inline std::wstring utf8_to_wide(const std::string& str) {
    return utf8_to_wide(str.c_str());
}

static inline std::string wide_to_utf8(const wchar_t* wstr) {
    if (!wstr) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], len, nullptr, nullptr);
    return result;
}

static inline std::string wide_to_utf8(const std::wstring& wstr) {
    return wide_to_utf8(wstr.c_str());
}

static inline std::string json_escape(const std::string& s) {
    std::string r;
    r.reserve(s.length() + 16);
    for (char c : s) {
        unsigned char uc = (unsigned char)c;
        switch (c) {
            case '"':  r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n"; break;
            case '\r': r += "\\r"; break;
            case '\t': r += "\\t"; break;
            case '\b': r += "\\b"; break;
            case '\f': r += "\\f"; break;
            default:
                // 转义所有控制字符和 DEL
                if (uc < 0x20 || uc == 0x7f) {
                    char hex[8];
                    snprintf(hex, sizeof(hex), "\\u%04x", uc);
                    r += hex;
                } else {
                    r += c;
                }
                break;
        }
    }
    return r;
}

static inline char* alloc_str(const char* s) {
    if (!s) return nullptr;
    size_t len = strlen(s) + 1;
    char* buf = (char*)malloc(len);
    if (buf) memcpy(buf, s, len);
    return buf;
}

// ============== 进程名/路径提取 ==============
static inline std::string get_process_name_by_pid(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return "unknown";
    wchar_t buf[MAX_PATH_LEN];
    DWORD len = MAX_PATH_LEN;
    std::string result = "unknown";
    if (QueryFullProcessImageNameW(hProc, 0, buf, &len)) {
        wchar_t* base = wcsrchr(buf, L'\\');
        result = wide_to_utf8(base ? base + 1 : buf);
    }
    CloseHandle(hProc);
    return result;
}

static inline std::string get_process_path_by_pid(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return "";
    wchar_t buf[MAX_PATH_LEN];
    DWORD len = MAX_PATH_LEN;
    std::string result;
    if (QueryFullProcessImageNameW(hProc, 0, buf, &len)) {
        result = wide_to_utf8(buf);
    }
    CloseHandle(hProc);
    return result;
}

static inline std::string to_lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) c = (char)tolower(c);
    return r;
}

static inline std::string get_ext(const std::string& path) {
    size_t pos = path.rfind('.');
    if (pos == std::string::npos) return "";
    return to_lower(path.substr(pos));
}

// ============== DLL 导出函数声明（供同一 DLL 内的 .cpp 互相调用） ==============
extern "C" __declspec(dllexport) void guard_free_string(char* str);
