/**
 * 御天 原生引擎 - 公共定义
 * 编译: g++ -O2 -shared -o native_engine.dll *.cpp -ladvapi32 -lws2_32 -liphlpapi -lpsapi -lole32 -static-libgcc -static-libstdc++
 */
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <winreg.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <vector>
#include <string>
#include <cmath>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

// ============== 常量和宏 ==============
#define MAX_PATH_LEN 4096
#define MAX_SECTIONS 128
#define MAX_IMPORTS 2048
#define ENTROPY_BUCKETS 256

// PE 结构直接使用 winnt.h 中已有的定义（IMAGE_DOS_HEADER, IMAGE_FILE_HEADER,
// IMAGE_OPTIONAL_HEADER32/64, IMAGE_SECTION_HEADER, IMAGE_IMPORT_DESCRIPTOR 等）

// 补充偏移量常量
#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE    0x5A4D
#endif
#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE     0x00004550
#endif
#ifndef IMAGE_SIZEOF_SHORT_NAME
#define IMAGE_SIZEOF_SHORT_NAME 8
#endif
#ifndef IMAGE_NUMBEROF_DIRECTORY_ENTRIES
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_IMPORT
#define IMAGE_DIRECTORY_ENTRY_IMPORT  1
#endif

// ============== 工具函数 ==============
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

// 简易 JSON 构建器（只用于构建返回字符串）
static inline std::string json_escape(const std::string& s) {
    std::string r;
    for (char c : s) {
        switch (c) {
            case '"':  r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n"; break;
            case '\r': r += "\\r"; break;
            case '\t': r += "\\t"; break;
            default:   r += c;
        }
    }
    return r;
}

// 内存安全分配
static inline char* alloc_str(const char* s) {
    if (!s) return nullptr;
    size_t len = strlen(s) + 1;
    char* buf = (char*)malloc(len);
    if (buf) memcpy(buf, s, len);
    return buf;
}

// 释放分配给 Python 的字符串
static inline void native_free_string_internal(char* str) {
    free(str);
}
