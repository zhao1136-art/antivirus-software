/**
 * 安盾 原生引擎 - SHA256 文件哈希模块
 * 使用 Win32 CryptoAPI 快速计算哈希，支持超大文件流式处理
 * 速度远超 Python hashlib（原生C，无GIL）
 */
#include "native_common.h"

// ============== 单文件 SHA256 ==============
static bool compute_sha256(const wchar_t* filepath, unsigned char hash_out[32], uint64_t* file_size_out) {
    HANDLE hFile = CreateFileW(filepath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    uint64_t totalSize = 0;
    DWORD hashLen = 32;
    DWORD bytesRead;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        goto fail;

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        goto fail;

    {
    BYTE buffer[65536]; // 64KB 缓冲区

    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0))
            goto fail;
        totalSize += bytesRead;
    }
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash_out, &hashLen, 0))
        goto fail;

    if (file_size_out) *file_size_out = totalSize;

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return true;

fail:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return false;
}

static std::string hash_to_hex(const unsigned char* hash) {
    const char* hex = "0123456789abcdef";
    std::string result(64, '0');
    for (int i = 0; i < 32; i++) {
        result[i * 2]     = hex[hash[i] >> 4];
        result[i * 2 + 1] = hex[hash[i] & 0x0F];
    }
    return result;
}

// ============== 导出: 计算单文件 SHA256 ==============
extern "C" __declspec(dllexport) char* sha256_file(const char* filepath_utf8) {
    std::wstring wpath = utf8_to_wide(filepath_utf8);
    unsigned char hash[32];
    uint64_t fileSize = 0;

    if (!compute_sha256(wpath.c_str(), hash, &fileSize)) {
        std::string err = "{\"error\":\"open failed\",\"path\":\"" + json_escape(filepath_utf8) + "\"}";
        return alloc_str(err.c_str());
    }

    char buf[256];
    snprintf(buf, sizeof(buf), "{\"sha256\":\"%s\",\"path\":\"%s\",\"size\":%llu}",
             hash_to_hex(hash).c_str(), json_escape(filepath_utf8).c_str(),
             (unsigned long long)fileSize);
    return alloc_str(buf);
}

// ============== 导出: 批量计算目录下所有文件 SHA256 ==============
extern "C" __declspec(dllexport) char* sha256_directory(const char* dirpath_utf8, int max_files) {
    std::wstring wdir = utf8_to_wide(dirpath_utf8);
    std::string result = "[";
    int count = 0;

    std::wstring searchPath = wdir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return alloc_str("[]");
    }

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (count >= max_files && max_files > 0) break;

        std::wstring fullPath = wdir + L"\\" + fd.cFileName;
        unsigned char hash[32];
        uint64_t fileSize = 0;

        if (compute_sha256(fullPath.c_str(), hash, &fileSize)) {
            char entry[512];
            std::string fname = wide_to_utf8(fd.cFileName);
            snprintf(entry, sizeof(entry), "%s{\"file\":\"%s\",\"sha256\":\"%s\",\"size\":%llu}",
                     count > 0 ? "," : "",
                     json_escape(fname).c_str(),
                     hash_to_hex(hash).c_str(),
                     (unsigned long long)fileSize);
            result += entry;
            count++;
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);

    result += "]";
    return alloc_str(result.c_str());
}

// ============== 导出: 与 MalwareBazaar 黑名单比对 ==============
// 黑名单以换行分隔的 SHA256 列表形式传入
extern "C" __declspec(dllexport) char* sha256_check_blacklist(const char* filepath_utf8, const char* blacklist_sha256) {
    std::wstring wpath = utf8_to_wide(filepath_utf8);
    unsigned char hash[32];

    if (!compute_sha256(wpath.c_str(), hash, nullptr)) {
        std::string err = "{\"error\":\"open failed\",\"path\":\"" + json_escape(filepath_utf8) + "\"}";
        return alloc_str(err.c_str());
    }

    std::string fileHash = hash_to_hex(hash);
    std::string bl(blacklist_sha256 ? blacklist_sha256 : "");

    // 逐行匹配
    bool matched = false;
    size_t pos = 0;
    while (pos < bl.size()) {
        size_t nl = bl.find('\n', pos);
        if (nl == std::string::npos) nl = bl.size();
        std::string line = bl.substr(pos, nl - pos);
        // 去空白
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        while (!line.empty() && (line.front() == ' ')) line.erase(0, 1);
        if (line == fileHash) {
            matched = true;
            break;
        }
        pos = nl + 1;
    }

    char buf[512];
    snprintf(buf, sizeof(buf), "{\"sha256\":\"%s\",\"path\":\"%s\",\"blacklisted\":%s}",
             fileHash.c_str(), json_escape(filepath_utf8).c_str(),
             matched ? "true" : "false");
    return alloc_str(buf);
}
