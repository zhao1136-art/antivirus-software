/**
 * 御天 原生引擎 DLL - 主入口
 */
#include "native_common.h"

// 版本信息
extern "C" __declspec(dllexport) char* native_engine_version() {
    return alloc_str("{\"name\":\"御天 Native Engine\",\"version\":\"1.0.0\",\"modules\":[\"sha256\",\"pe_parser\",\"heuristic\",\"sys_scanner\",\"quarantine\"]}");
}

// 释放字符串（Python ctypes 调用）
extern "C" __declspec(dllexport) void native_free_string(char* str) {
    free(str);
}

// 自检
extern "C" __declspec(dllexport) char* native_engine_self_test() {
    // 测试 SHA256
    BYTE testData[] = "hello world";
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE hash[32];
    
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return alloc_str("{\"status\":\"error\",\"module\":\"crypto\",\"error\":\"CryptAcquireContext failed\"}");

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return alloc_str("{\"status\":\"error\",\"module\":\"crypto\",\"error\":\"CryptCreateHash failed\"}");
    }

    CryptHashData(hHash, testData, sizeof(testData), 0);
    DWORD hashLen = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    // 验证已知哈希: "hello world\0" sha256
    const char* expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    char actual[65];
    for (int i = 0; i < 32; i++)
        sprintf(actual + i * 2, "%02x", hash[i]);

    bool sha256Ok = (strcmp(actual, expected) == 0);

    char buf[512];
    snprintf(buf, sizeof(buf),
             "{\"status\":\"%s\",\"sha256_test\":\"%s\",\"modules\":[\"crypto\",\"pe_parser\",\"heuristic\",\"sys_scanner\",\"quarantine\"]}",
             sha256Ok ? "ok" : "partial", sha256Ok ? "passed" : "failed");
    return alloc_str(buf);
}
