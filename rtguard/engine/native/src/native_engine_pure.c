/**
 * 御天 原生引擎 - 纯C实现（零STL依赖，兼容任何Python CRT）
 * 编译: gcc -O2 -shared -o native_engine.dll native_engine_pure.c 
 *        -ladvapi32 -lws2_32 -liphlpapi -lpsapi -lole32 -static
 */
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

/* ============== 工具函数 ============== */
#define MAX_BUF 65536
#define MAX_SECT 128

static char* alloc_copy(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static void str_escape(char* dst, const char* src, size_t max) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < max - 2; i++) {
        switch (src[i]) {
            case '"':  dst[j++] = '\\'; dst[j++] = '"'; break;
            case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
            case '\n': dst[j++] = '\\'; dst[j++] = 'n'; break;
            case '\r': dst[j++] = '\\'; dst[j++] = 'r'; break;
            case '\t': dst[j++] = '\\'; dst[j++] = 't'; break;
            default:   dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

static WCHAR* utf8_to_w(const char* s) {
    if (!s) return NULL;
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    WCHAR* w = (WCHAR*)malloc(n * sizeof(WCHAR));
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static char* w_to_utf8(const WCHAR* w) {
    if (!w) return NULL;
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char* s = (char*)malloc(n);
    if (s) WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    return s;
}

#define safefree(p) do { if(p) free(p); (p)=NULL; } while(0)

/* 字符串构建器 */
typedef struct {
    char* data;
    size_t len;
    size_t cap;
} StrBuf;

static void sb_init(StrBuf* sb, size_t init_cap) {
    sb->cap = init_cap > 0 ? init_cap : 4096;
    sb->data = (char*)malloc(sb->cap);
    sb->data[0] = '\0';
    sb->len = 0;
}

static void sb_append(StrBuf* sb, const char* s) {
    size_t add = strlen(s);
    if (sb->len + add + 1 > sb->cap) {
        sb->cap = (sb->len + add) * 2;
        sb->data = (char*)realloc(sb->data, sb->cap);
    }
    memcpy(sb->data + sb->len, s, add + 1);
    sb->len += add;
}

static void sb_appendn(StrBuf* sb, const char* s, size_t n) {
    if (sb->len + n + 1 > sb->cap) {
        sb->cap = (sb->len + n) * 2;
        sb->data = (char*)realloc(sb->data, sb->cap);
    }
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
}

static void sb_free(StrBuf* sb) {
    safefree(sb->data);
    sb->len = sb->cap = 0;
}

/* ============== 导出: 释放内存 ============== */
__declspec(dllexport) void native_free_string(char* str) {
    free(str);
}

/* ============== 版本/自检 ============== */
__declspec(dllexport) char* native_engine_version(void) {
    return alloc_copy("{\"name\":\"御天 Native Engine\",\"version\":\"1.0.0\",\"modules\":[\"sha256\",\"pe_parser\",\"heuristic\",\"sys_scanner\",\"quarantine\"]}");
}

__declspec(dllexport) char* native_engine_self_test(void) {
    /* 测试 SHA256 */
    BYTE td[] = "hello world";
    HCRYPTPROV hp = 0;
    HCRYPTHASH hh = 0;
    BYTE hash[32];
    char actual[65];
    int ok = 0;

    if (CryptAcquireContextW(&hp, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hp, CALG_SHA_256, 0, 0, &hh)) {
            CryptHashData(hh, td, (DWORD)(sizeof(td) - 1), 0);
            DWORD hl = 32;
            CryptGetHashParam(hh, HP_HASHVAL, hash, &hl, 0);
            CryptDestroyHash(hh);
            for (int i = 0; i < 32; i++)
                sprintf(actual + i * 2, "%02x", hash[i]);
            ok = (strcmp(actual, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9") == 0);
        }
        CryptReleaseContext(hp, 0);
    }

    char buf[256];
    snprintf(buf, sizeof(buf), "{\"status\":\"%s\",\"sha256_test\":\"%s\"}",
             ok ? "ok" : "partial", ok ? "passed" : "failed");
    return alloc_copy(buf);
}

/* ============== SHA256 哈希 ============== */
static int sha256_file_impl(const WCHAR* path, BYTE hash_out[32], ULONGLONG* size_out) {
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;

    HCRYPTPROV hp = 0;
    HCRYPTHASH hh = 0;
    ULONGLONG total = 0;

    if (!CryptAcquireContextW(&hp, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) goto fail;
    if (!CryptCreateHash(hp, CALG_SHA_256, 0, 0, &hh)) goto fail;

    BYTE buf[65536];
    DWORD br;
    while (ReadFile(hf, buf, sizeof(buf), &br, NULL) && br > 0) {
        if (!CryptHashData(hh, buf, br, 0)) goto fail;
        total += br;
    }

    DWORD hl = 32;
    CryptGetHashParam(hh, HP_HASHVAL, hash_out, &hl, 0);
    if (size_out) *size_out = total;

    CryptDestroyHash(hh);
    CryptReleaseContext(hp, 0);
    CloseHandle(hf);
    return 1;

fail:
    if (hh) CryptDestroyHash(hh);
    if (hp) CryptReleaseContext(hp, 0);
    CloseHandle(hf);
    return 0;
}

static void hash_to_hex(const BYTE* h, char out[65]) {
    const char* hex = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = hex[h[i] >> 4];
        out[i * 2 + 1] = hex[h[i] & 0x0F];
    }
    out[64] = '\0';
}

__declspec(dllexport) char* sha256_file(const char* path) {
    WCHAR* wp = utf8_to_w(path);
    BYTE hash[32];
    ULONGLONG sz = 0;
    char hex[65];
    char escaped[MAX_BUF];

    if (!sha256_file_impl(wp, hash, &sz)) {
        str_escape(escaped, path, sizeof(escaped));
        safefree(wp);
        char buf[1024];
        snprintf(buf, sizeof(buf), "{\"error\":\"open failed\",\"path\":\"%s\"}", escaped);
        return alloc_copy(buf);
    }
    safefree(wp);

    hash_to_hex(hash, hex);
    str_escape(escaped, path, sizeof(escaped));
    char buf[1024];
    snprintf(buf, sizeof(buf), "{\"sha256\":\"%s\",\"path\":\"%s\",\"size\":%llu}", hex, escaped, sz);
    return alloc_copy(buf);
}

/* ============== PE 解析 ============== */
static int is_high_risk_import(const char* name) {
    static const char* list[] = {
        "CreateRemoteThread","WriteProcessMemory","VirtualAllocEx",
        "NtCreateThreadEx","QueueUserAPC","SetWindowsHookEx",
        "CreateProcess","WinExec","ShellExecute",
        "OpenProcess","ReadProcessMemory","AdjustTokenPrivileges",
        "URLDownloadToFile","InternetOpenUrl",
        "RegSetValueEx","StartService","CreateService",
        "TerminateProcess","IsDebuggerPresent",
        "CryptEncrypt","NtUnmapViewOfSection","NtMapViewOfSection",
        NULL
    };
    for (int i = 0; list[i]; i++)
        if (_stricmp(name, list[i]) == 0) return 1;
    return 0;
}

static double calc_entropy(const BYTE* data, size_t size) {
    if (size == 0) return 0.0;
    unsigned int counts[256] = {0};
    size_t i;
    for (i = 0; i < size; i++) counts[data[i]]++;
    double e = 0.0;
    for (i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / (double)size;
            e -= p * log(p) / log(2.0);
        }
    }
    return e;
}

__declspec(dllexport) char* pe_parse_full(const char* path) {
    WCHAR* wp = utf8_to_w(path);
    HANDLE hf = CreateFileW(wp, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    safefree(wp);
    
    if (hf == INVALID_HANDLE_VALUE) {
        char escaped[MAX_BUF]; str_escape(escaped, path, sizeof(escaped));
        char buf[1024];
        snprintf(buf, sizeof(buf), "{\"error\":\"open failed\",\"path\":\"%s\",\"valid_pe\":false}", escaped);
        return alloc_copy(buf);
    }

    LARGE_INTEGER li;
    GetFileSizeEx(hf, &li);
    
    HANDLE hm = CreateFileMappingW(hf, NULL, PAGE_READONLY, 0, 0, NULL);
    BYTE* base = (BYTE*)MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hm);
    CloseHandle(hf);
    
    if (!base) return alloc_copy("{\"valid_pe\":false,\"error\":\"map failed\"}");

    size_t fs = (size_t)li.QuadPart;
    StrBuf sb;
    sb_init(&sb, 8192);
    
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "{\"path\":\"");
    sb_append(&sb, tmp);
    { char esc[MAX_BUF]; str_escape(esc, path, sizeof(esc)); sb_append(&sb, esc); }
    snprintf(tmp, sizeof(tmp), "\",\"file_size\":%zu,", fs);
    sb_append(&sb, tmp);

    /* DOS check */
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != 0x5A4D || dos->e_lfanew >= fs) {
        sb_append(&sb, "\"valid_pe\":false,\"error\":\"not PE\"}");
        char* r = alloc_copy(sb.data); sb_free(&sb); UnmapViewOfFile(base); return r;
    }
    sb_append(&sb, "\"valid_pe\":true,");

    /* NT headers */
    DWORD* ntSig = (DWORD*)(base + dos->e_lfanew);
    if (*ntSig != 0x00004550) {
        sb_append(&sb, "\"valid_pe\":false,\"error\":\"bad NT sig\"}");
        char* r = alloc_copy(sb.data); sb_free(&sb); UnmapViewOfFile(base); return r;
    }

    IMAGE_FILE_HEADER* fh = (IMAGE_FILE_HEADER*)(ntSig + 1);
    WORD optMagic = *(WORD*)(fh + 1);
    int is64 = (optMagic == 0x20b);
    DWORD entry = 0, subsystem = 0, sizeCode = 0;

    if (optMagic == 0x20b) {
        IMAGE_OPTIONAL_HEADER64* o = (IMAGE_OPTIONAL_HEADER64*)(fh + 1);
        entry = o->AddressOfEntryPoint; subsystem = o->Subsystem; sizeCode = o->SizeOfCode;
        snprintf(tmp, sizeof(tmp), "\"pe_type\":\"PE32+\",\"entry_point\":%lu,\"subsystem\":%u,\"size_of_code\":%lu,",
                 entry, subsystem, sizeCode);
        sb_append(&sb, tmp);
    } else if (optMagic == 0x10b) {
        IMAGE_OPTIONAL_HEADER32* o = (IMAGE_OPTIONAL_HEADER32*)(fh + 1);
        entry = o->AddressOfEntryPoint; subsystem = o->Subsystem; sizeCode = o->SizeOfCode;
        snprintf(tmp, sizeof(tmp), "\"pe_type\":\"PE32\",\"entry_point\":%lu,\"subsystem\":%u,\"size_of_code\":%lu,",
                 entry, subsystem, sizeCode);
        sb_append(&sb, tmp);
    }

    snprintf(tmp, sizeof(tmp), "\"machine\":%u,\"sections\":%u,\"chars\":%u,",
             fh->Machine, fh->NumberOfSections, fh->Characteristics);
    sb_append(&sb, tmp);

    /* 节表 */
    size_t optSz = (optMagic == 0x20b) ? sizeof(IMAGE_OPTIONAL_HEADER64)
                 : (optMagic == 0x10b) ? sizeof(IMAGE_OPTIONAL_HEADER32) : 0;
    IMAGE_SECTION_HEADER* secs = (IMAGE_SECTION_HEADER*)((BYTE*)(fh + 1) + fh->SizeOfOptionalHeader);

    sb_append(&sb, "\"sections\":[");
    int rwxCnt = 0, hiEntCnt = 0;
    double maxE = 0.0;
    int i;

    for (i = 0; i < fh->NumberOfSections && i < MAX_SECT; i++) {
        IMAGE_SECTION_HEADER* s = &secs[i];
        /* sec name */
        char sname[9] = {0};
        for (int j = 0; j < 8; j++)
            if (s->Name[j] >= 0x20 && s->Name[j] <= 0x7E) sname[j] = s->Name[j];

        int isRwx = (s->Characteristics & 0x20000000) && (s->Characteristics & 0x80000000);
        int isExec = (s->Characteristics & 0x20000000) != 0;
        if (isRwx) rwxCnt++;

        double ent = 0.0;
        if (s->PointerToRawData > 0 && s->SizeOfRawData > 0 && s->PointerToRawData + s->SizeOfRawData <= fs) {
            ent = calc_entropy(base + s->PointerToRawData, s->SizeOfRawData);
            if (ent > maxE) maxE = ent;
            if (ent > 7.0) hiEntCnt++;
        }

        if (i > 0) sb_append(&sb, ",");
        char nameEsc[32]; str_escape(nameEsc, sname, sizeof(nameEsc));
        snprintf(tmp, sizeof(tmp),
                 "{\"name\":\"%s\",\"vsize\":%lu,\"vaddr\":%lu,\"rsize\":%lu,\"roff\":%lu,\"rwx\":%s,\"exec\":%s,\"entropy\":%.2f}",
                 nameEsc, s->Misc.VirtualSize, s->VirtualAddress, s->SizeOfRawData, s->PointerToRawData,
                 isRwx ? "true" : "false", isExec ? "true" : "false", ent);
        sb_append(&sb, tmp);
    }
    snprintf(tmp, sizeof(tmp), "],\"rwx_sections\":%d,\"high_entropy\":%d,\"max_entropy\":%.1f,",
             rwxCnt, hiEntCnt, maxE);
    sb_append(&sb, tmp);

    /* 导入表 */
    DWORD impRva = 0, impSize = 0;
    if (optMagic == 0x20b) {
        IMAGE_OPTIONAL_HEADER64* o = (IMAGE_OPTIONAL_HEADER64*)(fh + 1);
        impRva = o->DataDirectory[1].VirtualAddress;
        impSize = o->DataDirectory[1].Size;
    } else if (optMagic == 0x10b) {
        IMAGE_OPTIONAL_HEADER32* o = (IMAGE_OPTIONAL_HEADER32*)(fh + 1);
        impRva = o->DataDirectory[1].VirtualAddress;
        impSize = o->DataDirectory[1].Size;
    }

    sb_append(&sb, "\"imports\":[");
    int hiRisk = 0, firstImp = 1;

    if (impRva > 0 && impSize > 0) {
        /* RVA to offset */
        DWORD impOff = 0;
        for (i = 0; i < fh->NumberOfSections; i++) {
            DWORD vs = (secs[i].Misc.VirtualSize > secs[i].SizeOfRawData) ? secs[i].Misc.VirtualSize : secs[i].SizeOfRawData;
            if (impRva >= secs[i].VirtualAddress && impRva < secs[i].VirtualAddress + vs) {
                impOff = impRva - secs[i].VirtualAddress + secs[i].PointerToRawData;
                break;
            }
        }

        if (impOff > 0 && impOff < fs) {
            IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + impOff);
            int idx = 0;
            while (imp->Name != 0 && idx < 256) {
                /* DLL name */
                DWORD noff = 0;
                for (i = 0; i < fh->NumberOfSections; i++) {
                    DWORD vs = (secs[i].Misc.VirtualSize > secs[i].SizeOfRawData) ? secs[i].Misc.VirtualSize : secs[i].SizeOfRawData;
                    if (imp->Name >= secs[i].VirtualAddress && imp->Name < secs[i].VirtualAddress + vs) {
                        noff = imp->Name - secs[i].VirtualAddress + secs[i].PointerToRawData;
                        break;
                    }
                }
                char dllName[128] = "unknown";
                if (noff > 0 && noff < fs)
                    strncpy(dllName, (char*)(base + noff), sizeof(dllName) - 1);

                /* Thunk */
                DWORD* pd = (DWORD*)imp;
                DWORD thunk = pd[0] ? pd[0] : imp->FirstThunk;
                DWORD toff = 0;
                for (i = 0; i < fh->NumberOfSections; i++) {
                    DWORD vs = (secs[i].Misc.VirtualSize > secs[i].SizeOfRawData) ? secs[i].Misc.VirtualSize : secs[i].SizeOfRawData;
                    if (thunk >= secs[i].VirtualAddress && thunk < secs[i].VirtualAddress + vs) {
                        toff = thunk - secs[i].VirtualAddress + secs[i].PointerToRawData;
                        break;
                    }
                }

                StrBuf funcs;
                sb_init(&funcs, 256);

                if (toff > 0 && toff < fs) {
                    int fc = 0;
                    DWORD* td;
                    while (fc < 200) {
                        td = is64 ? (DWORD*)(base + toff + fc * 8) : (DWORD*)(base + toff + fc * 4);
                        if (*td == 0) break;
                        if (*td & 0x80000000) { fc++; continue; }

                        DWORD hintRva = *td & 0x7FFFFFFF;
                        DWORD hoff = 0;
                        for (i = 0; i < fh->NumberOfSections; i++) {
                            DWORD vs = (secs[i].Misc.VirtualSize > secs[i].SizeOfRawData) ? secs[i].Misc.VirtualSize : secs[i].SizeOfRawData;
                            if (hintRva >= secs[i].VirtualAddress && hintRva < secs[i].VirtualAddress + vs) {
                                hoff = hintRva - secs[i].VirtualAddress + secs[i].PointerToRawData;
                                break;
                            }
                        }
                        if (hoff > 0 && hoff + 2 < fs) {
                            WORD* ibn = (WORD*)(base + hoff);
                            char* fn = (char*)(ibn + 1);
                            if (fc > 0) sb_append(&funcs, ",");
                            sb_append(&funcs, "\"");
                            { char fe[512]; str_escape(fe, fn, sizeof(fe)); sb_append(&funcs, fe); }
                            sb_append(&funcs, "\"");
                            if (is_high_risk_import(fn)) hiRisk++;
                        }
                        fc++;
                    }
                }

                if (funcs.len > 2) {
                    if (!firstImp) sb_append(&sb, ",");
                    firstImp = 0;
                    sb_append(&sb, "{\"dll\":\"");
                    { char de[128]; str_escape(de, dllName, sizeof(de)); sb_append(&sb, de); }
                    sb_append(&sb, "\",\"functions\":[");
                    sb_append(&sb, funcs.data);
                    sb_append(&sb, "]}");
                }
                sb_free(&funcs);
                imp++;
                idx++;
            }
        }
    }
    sb_append(&sb, "],");

    snprintf(tmp, sizeof(tmp), "\"high_risk_api_count\":%d,\"import_count\":%d,", hiRisk, hiRisk);
    sb_append(&sb, tmp);

    /* 字符串/URL */
    sb_append(&sb, "\"extracted_urls\":[],\"suspicious_urls_count\":0,");
    sb_append(&sb, "\"has_signature\":false,\"signature_count\":0}");
    
    char* r = alloc_copy(sb.data);
    sb_free(&sb);
    UnmapViewOfFile(base);
    return r;
}

/* ============== 启发式检测 ============== */
__declspec(dllexport) char* heuristic_score_fast(int rwx_secs, double max_ent, int hi_apis,
                                                   int subsystem, int has_sig, int sus_urls, int size_code) {
    double total = 0.0;
    StrBuf sb;
    sb_init(&sb, 1024);
    int first = 1;

    #define ADD_RF(fmt, ...) do { \
        if (!first) sb_append(&sb, ","); first = 0; \
        char _b[256]; snprintf(_b, sizeof(_b), fmt, ##__VA_ARGS__); sb_append(&sb, _b); \
    } while(0)

    sb_append(&sb, "{\"reasons\":[");

    if (rwx_secs > 0) {
        double s = 15.0 * rwx_secs; if (s > 30.0) s = 30.0; total += s;
        ADD_RF("\"RWX section x%d (+%.0f)\"", rwx_secs, s);
    }
    if (max_ent > 7.0) {
        double s = 10.0 * (max_ent - 6.5); if (s > 25.0) s = 25.0; total += s;
        ADD_RF("\"High entropy %.1f packed (+%.0f)\"", max_ent, s);
    }
    if (hi_apis > 0) {
        double s = 3.0 * hi_apis; if (s > 30.0) s = 30.0; total += s;
        ADD_RF("\"High-risk APIs: %d (+%.0f)\"", hi_apis, s);
    }
    if (subsystem != 2 && subsystem != 0) {
        total += 8.0;
        ADD_RF("\"Non-GUI app (sub=%d) (+8.0)\"", subsystem);
    }
    if (!has_sig) {
        total += 12.0;
        ADD_RF("\"No digital signature (+12.0)\"");
    }
    if (sus_urls > 0) {
        double s = 5.0 * sus_urls; if (s > 15.0) s = 15.0; total += s;
        ADD_RF("\"Suspicious URLs: %d (+%.0f)\"", sus_urls, s);
    }
    if (size_code > 0 && size_code < 4096) {
        total += 5.0;
        ADD_RF("\"Small code section (%d bytes) (+5.0)\"", size_code);
    }

    if (total > 100.0) total = 100.0;
    const char* level = total >= 70 ? "critical" : total >= 50 ? "high" : total >= 30 ? "medium" : total >= 15 ? "low" : "safe";

    char buf[1024];
    snprintf(buf, sizeof(buf), "],\"risk_score\":%.1f,\"risk_level\":\"%s\"}", total, level);
    sb_append(&sb, buf);
    char* r = alloc_copy(sb.data);
    sb_free(&sb);
    return r;
}

/* ============== 系统巡检: 进程 ============== */
__declspec(dllexport) char* sys_enum_processes(void) {
    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hs == INVALID_HANDLE_VALUE) return alloc_copy("{\"error\":\"snapshot failed\",\"processes\":[]}");

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    StrBuf sb;
    sb_init(&sb, 8192);
    sb_append(&sb, "{\"processes\":[");
    int first = 1;

    if (Process32FirstW(hs, &pe)) {
        do {
            if (!first) sb_append(&sb, ",");
            first = 0;

            char* name = w_to_utf8(pe.szExeFile);
            char* path = NULL;
            
            HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hp) {
                WCHAR pb[MAX_PATH];
                DWORD pl = MAX_PATH;
                if (QueryFullProcessImageNameW(hp, 0, pb, &pl))
                    path = w_to_utf8(pb);
                CloseHandle(hp);
            }

            char ne[512], pe_[1024];
            str_escape(ne, name ? name : "", sizeof(ne));
            str_escape(pe_, path ? path : "", sizeof(pe_));

            char buf[1536];
            snprintf(buf, sizeof(buf), "{\"pid\":%lu,\"name\":\"%s\",\"path\":\"%s\",\"threads\":%lu}",
                     pe.th32ProcessID, ne, pe_, pe.cntThreads);
            sb_append(&sb, buf);
            safefree(name);
            safefree(path);
        } while (Process32NextW(hs, &pe));
    }
    CloseHandle(hs);
    sb_append(&sb, "]}");
    char* r = alloc_copy(sb.data);
    sb_free(&sb);
    return r;
}

/* ============== 系统巡检: 启动项 ============== */
__declspec(dllexport) char* sys_scan_startup(void) {
    StrBuf sb;
    sb_init(&sb, 8192);
    sb_append(&sb, "{\"items\":[");
    int first = 1;
    int i;

    /* 注册表 Run 键 */
    static const WCHAR* hives[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    };
    static const HKEY roots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    static const char* hnames[] = {"HKLM","HKCU"};
    static const char* rnames[] = {"Run","RunOnce"};

    for (i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            HKEY hk;
            if (RegOpenKeyExW(roots[i], hives[j], 0, KEY_READ, &hk) != ERROR_SUCCESS) continue;

            DWORD idx = 0;
            WCHAR vn[512];
            BYTE vd[4096];
            DWORD nl, dl, tp;
            while (1) {
                nl = 512; dl = sizeof(vd);
                if (RegEnumValueW(hk, idx, vn, &nl, NULL, &tp, vd, &dl) != ERROR_SUCCESS) break;
                
                char* name = w_to_utf8(vn);
                char* val = (tp == REG_SZ || tp == REG_EXPAND_SZ) ? w_to_utf8((WCHAR*)vd) : alloc_copy("");
                
                const char* risk = "safe";
                if (val) {
                    char* vl = (char*)malloc(strlen(val)+1);
                    if (vl) {
                        for (size_t k = 0; val[k]; k++) vl[k] = tolower((unsigned char)val[k]);
                        vl[strlen(val)] = '\0';
                        if (strstr(vl, "\\temp\\") || strstr(vl, "\\appdata\\local\\temp"))
                            risk = "high";
                        else if (strstr(vl, "\\appdata\\"))
                            risk = "suspicious";
                        free(vl);
                    }
                }

                if (!first) sb_append(&sb, ",");
                first = 0;
                char ne[512], ve[2048];
                str_escape(ne, name ? name : "", sizeof(ne));
                str_escape(ve, val ? val : "", sizeof(ve));

                char buf[3072];
                snprintf(buf, sizeof(buf),
                         "{\"source\":\"registry\",\"location\":\"%s\\\\%s\",\"name\":\"%s\",\"command\":\"%s\",\"risk\":\"%s\"}",
                         hnames[i], rnames[j], ne, ve, risk);
                sb_append(&sb, buf);
                safefree(name); safefree(val);
                idx++;
            }
            RegCloseKey(hk);
        }
    }

    /* 启动文件夹 */
    WCHAR cs[MAX_PATH], us[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, 0, cs) == S_OK) {
        WCHAR sp[MAX_PATH+4];
        swprintf(sp, MAX_PATH+3, L"%s\\*", cs);
        WIN32_FIND_DATAW fd;
        HANDLE hf = FindFirstFileW(sp, &fd);
        if (hf != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                char* fn = w_to_utf8(fd.cFileName);
                if (!first) sb_append(&sb, ",");
                first = 0;
                char fe[512];
                str_escape(fe, fn, sizeof(fe));
                char buf[1024];
                snprintf(buf, sizeof(buf),
                         "{\"source\":\"startup_folder\",\"location\":\"Common\",\"name\":\"%s\",\"risk\":\"safe\"}", fe);
                sb_append(&sb, buf);
                safefree(fn);
            } while (FindNextFileW(hf, &fd));
            FindClose(hf);
        }
    }

    sb_append(&sb, "]}");
    char* r = alloc_copy(sb.data);
    sb_free(&sb);
    return r;
}

/* ============== 系统巡检: 网络连接 ============== */
__declspec(dllexport) char* sys_enum_network(void) {
    StrBuf sb;
    sb_init(&sb, 16384);
    sb_append(&sb, "{\"connections\":[");
    int first = 1;

    /* TCP */
    DWORD tsz = 0;
    GetExtendedTcpTable(NULL, &tsz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tsz > 0) {
        BYTE* tb = (BYTE*)malloc(tsz + 1024);
        if (GetExtendedTcpTable((PMIB_TCPTABLE_OWNER_PID)tb, &tsz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            PMIB_TCPTABLE_OWNER_PID ttp = (PMIB_TCPTABLE_OWNER_PID)tb;
            DWORD i;
            for (i = 0; i < ttp->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID* r = &ttp->table[i];
                IN_ADDR la, ra;
                la.S_un.S_addr = r->dwLocalAddr;
                ra.S_un.S_addr = r->dwRemoteAddr;
                
                const char* st = "UNKNOWN";
                switch (r->dwState) {
                    case MIB_TCP_STATE_ESTAB: st = "ESTABLISHED"; break;
                    case MIB_TCP_STATE_LISTEN: st = "LISTEN"; break;
                    case MIB_TCP_STATE_SYN_SENT: st = "SYN_SENT"; break;
                    case MIB_TCP_STATE_CLOSE_WAIT: st = "CLOSE_WAIT"; break;
                    case MIB_TCP_STATE_TIME_WAIT: st = "TIME_WAIT"; break;
                }

                const char* risk = "safe";
                DWORD rp = ntohs((u_short)r->dwRemotePort);
                if (r->dwState == MIB_TCP_STATE_ESTAB && rp != 80 && rp != 443) {
                    if (rp == 4444 || rp == 5555 || rp == 6666 || rp == 1337 || rp == 31337)
                        risk = "high";
                    else if (rp > 10000)
                        risk = "suspicious";
                }

                if (!first) sb_append(&sb, ",");
                first = 0;
                char buf[1024];
                snprintf(buf, sizeof(buf),
                         "{\"pid\":%lu,\"proto\":\"TCP\",\"local\":\"%s:%lu\",\"remote\":\"%s:%lu\",\"state\":\"%s\",\"risk\":\"%s\"}",
                         r->dwOwningPid, inet_ntoa(la), ntohs((u_short)r->dwLocalPort),
                         inet_ntoa(ra), rp, st, risk);
                sb_append(&sb, buf);
            }
        }
        free(tb);
    }

    sb_append(&sb, "]}");
    char* r = alloc_copy(sb.data);
    sb_free(&sb);
    return r;
}

/* ============== 系统信息 ============== */
__declspec(dllexport) char* sys_summary(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    char cn[256];
    DWORD cl = sizeof(cn);
    GetComputerNameA(cn, &cl);

    char buf[512];
    snprintf(buf, sizeof(buf),
             "{\"computer\":\"%s\",\"cpu_count\":%lu,\"ram_total_gb\":%.1f,\"ram_avail_gb\":%.1f}",
             cn, si.dwNumberOfProcessors,
             mem.ullTotalPhys / (1024.0*1024.0*1024.0),
             mem.ullAvailPhys / (1024.0*1024.0*1024.0));
    return alloc_copy(buf);
}

/* ============== 隔离区 ============== */
static const BYTE XOR_KEY[16] = {0xAD,0x3F,0x72,0xE1,0x5B,0x9C,0x4E,0xD8,0x12,0x67,0x3A,0xBF,0x85,0x4D,0xFE,0x19};

static int q_xor_file(const WCHAR* src, const WCHAR* dst) {
    HANDLE hs = CreateFileW(src, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hs == INVALID_HANDLE_VALUE) return 0;
    HANDLE hd = CreateFileW(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hd == INVALID_HANDLE_VALUE) { CloseHandle(hs); return 0; }
    
    BYTE buf[65536];
    DWORD br, bw;
    while (ReadFile(hs, buf, sizeof(buf), &br, NULL) && br > 0) {
        DWORD k;
        for (k = 0; k < br; k++) buf[k] ^= XOR_KEY[k % 16];
        if (!WriteFile(hd, buf, br, &bw, NULL)) { CloseHandle(hs); CloseHandle(hd); DeleteFileW(dst); return 0; }
    }
    CloseHandle(hs); CloseHandle(hd);
    return 1;
}

__declspec(dllexport) char* quarantine_move(const char* src, const char* qdir) {
    WCHAR* ws = utf8_to_w(src);
    WCHAR* wd = utf8_to_w(qdir);
    char* r;

    if (GetFileAttributesW(ws) == INVALID_FILE_ATTRIBUTES) {
        safefree(ws); safefree(wd);
        return alloc_copy("{\"success\":false,\"error\":\"source not found\"}");
    }

    CreateDirectoryW(wd, NULL);

    const WCHAR* fn = wcsrchr(ws, L'\\');
    fn = fn ? fn + 1 : ws;
    WCHAR qn[512];
    swprintf(qn, 512, L"%s\\%08x_%s.quar", wd, GetTickCount(), fn);

    if (!q_xor_file(ws, qn)) {
        safefree(ws); safefree(wd);
        return alloc_copy("{\"success\":false,\"error\":\"encrypt failed\"}");
    }
    DeleteFileW(ws);
    safefree(ws); safefree(wd);

    char* qs = w_to_utf8(qn);
    char qe[1024], se[1024];
    str_escape(qe, qs, sizeof(qe));
    str_escape(se, src, sizeof(se));
    safefree(qs);

    char buf[2048];
    snprintf(buf, sizeof(buf), "{\"success\":true,\"quarantine_path\":\"%s\",\"original_path\":\"%s\"}", qe, se);
    return alloc_copy(buf);
}

__declspec(dllexport) char* quarantine_list(const char* qdir) {
    WCHAR* wd = utf8_to_w(qdir);
    WCHAR sp[520];
    swprintf(sp, 520, L"%s\\*.quar", wd);

    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW(sp, &fd);
    safefree(wd);

    StrBuf sb;
    sb_init(&sb, 4096);
    sb_append(&sb, "{\"items\":[");
    int first = 1;

    if (hf != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            char* fn = w_to_utf8(fd.cFileName);
            if (!first) sb_append(&sb, ",");
            first = 0;
            char fe[512];
            str_escape(fe, fn, sizeof(fe));
            ULONGLONG sz = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            char buf[1024];
            snprintf(buf, sizeof(buf), "{\"file\":\"%s\",\"size\":%llu}", fe, sz);
            sb_append(&sb, buf);
            safefree(fn);
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }

    sb_append(&sb, "]}");
    char* r = alloc_copy(sb.data);
    sb_free(&sb);
    return r;
}

/* ============== CLI入口 ============== */
int main(int argc, char* argv[]) {
    if (argc < 2) { printf("{\"error\":\"usage: native_engine <cmd> [args]\"}\n"); return 1; }
    char* r = NULL;
    const char* c = argv[1];
    if (!strcmp(c,"version")) r=native_engine_version();
    else if (!strcmp(c,"selftest")) r=native_engine_self_test();
    else if (!strcmp(c,"sha256") && argc>=3) r=sha256_file(argv[2]);
    else if (!strcmp(c,"peparse") && argc>=3) r=pe_parse_full(argv[2]);
    else if (!strcmp(c,"heuristic") && argc>=9) r=heuristic_score_fast(atoi(argv[2]),atof(argv[3]),atoi(argv[4]),atoi(argv[5]),atoi(argv[6]),atoi(argv[7]),atoi(argv[8]));
    else if (!strcmp(c,"processes")) r=sys_enum_processes();
    else if (!strcmp(c,"startup")) r=sys_scan_startup();
    else if (!strcmp(c,"network")) r=sys_enum_network();
    else if (!strcmp(c,"sysinfo")) r=sys_summary();
    else if (!strcmp(c,"qmove") && argc>=4) r=quarantine_move(argv[2],argv[3]);
    else if (!strcmp(c,"qlist") && argc>=3) r=quarantine_list(argv[2]);
    else { printf("{\"error\":\"unknown cmd\"}\n"); return 1; }
    if (r) { printf("%s\n",r); free(r); }
    return 0;
}
