/**
 * 安盾 原生引擎 - 隔离区管理模块
 * 加密移动可疑文件到隔离区，支持恢复和永久删除
 * 使用 XOR 简单加密 + 元数据存储
 */
#include "native_common.h"
#include <time.h>

// ============== 隔离操作 ==============

// XOR 加密密钥
static const BYTE XOR_KEY[16] = {
    0xAD, 0x3F, 0x72, 0xE1, 0x5B, 0x9C, 0x4E, 0xD8,
    0x12, 0x67, 0x3A, 0xBF, 0x85, 0x4D, 0xFE, 0x19
};

// 加密/解密文件（XOR 流式）
static bool xor_crypt_file(const wchar_t* srcPath, const wchar_t* dstPath) {
    HANDLE hSrc = CreateFileW(srcPath, GENERIC_READ, 0, nullptr,
                               OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hSrc == INVALID_HANDLE_VALUE) return false;

    HANDLE hDst = CreateFileW(dstPath, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDst == INVALID_HANDLE_VALUE) {
        CloseHandle(hSrc);
        return false;
    }

    BYTE buffer[65536];
    DWORD bytesRead, bytesWritten;

    while (ReadFile(hSrc, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
        for (DWORD i = 0; i < bytesRead; i++)
            buffer[i] ^= XOR_KEY[i % 16];
        if (!WriteFile(hDst, buffer, bytesRead, &bytesWritten, nullptr))
            goto fail;
    }

    CloseHandle(hSrc);
    CloseHandle(hDst);
    return true;

fail:
    CloseHandle(hSrc);
    CloseHandle(hDst);
    DeleteFileW(dstPath);
    return false;
}

// ============== 导出: 隔离文件（移动到隔离区 + 加密）==============
extern "C" __declspec(dllexport) char* quarantine_move(const char* filepath_utf8, const char* quarantine_dir_utf8) {
    std::wstring srcPath = utf8_to_wide(filepath_utf8);
    std::wstring qdir = utf8_to_wide(quarantine_dir_utf8);

    // 检查源文件
    if (GetFileAttributesW(srcPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return alloc_str("{\"success\":false,\"error\":\"source file not found\"}");
    }

    // 创建隔离目录
    CreateDirectoryW(qdir.c_str(), nullptr);

    // 生成隔离文件名（时间戳 + 原文件名）
    const wchar_t* fname = wcsrchr(srcPath.c_str(), L'\\');
    if (!fname) fname = srcPath.c_str();
    else fname++;

    DWORD tick = GetTickCount();
    wchar_t qname[512];
    swprintf(qname, 512, L"%s\\%08x_%s.quar", qdir.c_str(), tick, fname);

    // 加密并移动
    if (!xor_crypt_file(srcPath.c_str(), qname)) {
        return alloc_str("{\"success\":false,\"error\":\"encrypt/move failed\"}");
    }

    // 删除原始文件
    DeleteFileW(srcPath.c_str());

    std::string qnameUtf8 = wide_to_utf8(qname);
    char buf[1024];
    snprintf(buf, sizeof(buf),
             "{\"success\":true,\"quarantine_path\":\"%s\",\"original_path\":\"%s\"}",
             json_escape(qnameUtf8).c_str(), json_escape(filepath_utf8));
    return alloc_str(buf);
}

// ============== 导出: 恢复隔离文件 ==============
extern "C" __declspec(dllexport) char* quarantine_restore(const char* quar_path_utf8, const char* restore_dir_utf8) {
    std::wstring quarPath = utf8_to_wide(quar_path_utf8);
    std::wstring restoreDir = utf8_to_wide(restore_dir_utf8);

    if (GetFileAttributesW(quarPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return alloc_str("{\"success\":false,\"error\":\"quarantine file not found\"}");
    }

    CreateDirectoryW(restoreDir.c_str(), nullptr);

    // 从隔离文件名还原原始文件名
    const wchar_t* fname = wcsrchr(quarPath.c_str(), L'\\');
    if (!fname) fname = quarPath.c_str();
    else fname++;

    std::wstring fnameStr = fname;
    // 去掉 .quar 后缀和时间戳前缀
    size_t dotPos = fnameStr.rfind(L".quar");
    if (dotPos != std::wstring::npos) fnameStr = fnameStr.substr(0, dotPos);
    size_t underPos = fnameStr.find(L'_');
    if (underPos != std::wstring::npos) fnameStr = fnameStr.substr(underPos + 1);

    wchar_t restorePath[MAX_PATH_LEN];
    swprintf(restorePath, MAX_PATH_LEN, L"%s\\%s", restoreDir.c_str(), fnameStr.c_str());

    // 解密恢复
    if (!xor_crypt_file(quarPath.c_str(), restorePath)) {
        return alloc_str("{\"success\":false,\"error\":\"decrypt failed\"}");
    }

    // 删除隔离文件
    DeleteFileW(quarPath.c_str());

    std::string restoreUtf8 = wide_to_utf8(restorePath);
    char buf[1024];
    snprintf(buf, sizeof(buf), "{\"success\":true,\"restored_path\":\"%s\"}",
             json_escape(restoreUtf8).c_str());
    return alloc_str(buf);
}

// ============== 导出: 永久删除隔离文件 ==============
extern "C" __declspec(dllexport) char* quarantine_delete(const char* quar_path_utf8) {
    std::wstring quarPath = utf8_to_wide(quar_path_utf8);

    // 先用随机数据覆写（防恢复）
    HANDLE hFile = CreateFileW(quarPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER size;
        if (GetFileSizeEx(hFile, &size)) {
            // 覆写3次
            BYTE buf[4096];
            for (int pass = 0; pass < 3; pass++) {
                for (int i = 0; i < 4096; i++) buf[i] = (BYTE)(rand() & 0xFF);
                SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
                LONGLONG remain = size.QuadPart;
                while (remain > 0) {
                    DWORD toWrite = (DWORD)((std::min)(remain, (LONGLONG)4096));
                    DWORD written;
                    WriteFile(hFile, buf, toWrite, &written, nullptr);
                    remain -= toWrite;
                }
                FlushFileBuffers(hFile);
            }
        }
        CloseHandle(hFile);
    }

    if (DeleteFileW(quarPath.c_str())) {
        return alloc_str("{\"success\":true}");
    } else {
        return alloc_str("{\"success\":false,\"error\":\"delete failed\"}");
    }
}

// ============== 导出: 列出隔离区文件 ==============
extern "C" __declspec(dllexport) char* quarantine_list(const char* quarantine_dir_utf8) {
    std::wstring qdir = utf8_to_wide(quarantine_dir_utf8);
    std::wstring search = qdir + L"\\*.quar";

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
    
    std::string json = "{\"items\":[";
    bool first = true;

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            std::string fname = wide_to_utf8(fd.cFileName);
            std::string fullPath = wide_to_utf8(qdir.c_str()) + "\\" + fname;

            // 解析文件大小和时间
            ULONGLONG fileSize = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            FILETIME localTime;
            FileTimeToLocalFileTime(&fd.ftCreationTime, &localTime);
            SYSTEMTIME st;
            FileTimeToSystemTime(&localTime, &st);

            char timeBuf[64];
            snprintf(timeBuf, sizeof(timeBuf), "%04d-%02d-%02d %02d:%02d:%02d",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

            if (!first) json += ",";
            first = false;

            char buf[1024];
            snprintf(buf, sizeof(buf),
                     "{\"file\":\"%s\",\"path\":\"%s\",\"size\":%llu,\"date\":\"%s\"}",
                     json_escape(fname).c_str(), json_escape(fullPath).c_str(),
                     fileSize, timeBuf);
            json += buf;

        } while (FindNextFileW(hFind, &fd) && !first); // first 用于防止无限循环
        FindClose(hFind);
    }

    json += "]}";
    return alloc_str(json.c_str());
}
