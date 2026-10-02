/**
 * 御天 AMSI Provider (升级一：无文件攻击事中拦截)
 *
 * 注册为 Windows AMSI Provider 后，PowerShell / VBS / 宏 / JScript
 * 在执行脚本内容前会调用本 DLL 的 Scan() 方法。
 * 通过检测常见恶意脚本特征（Base64 编码、远程下载、混淆执行等），
 * 在载荷执行前返回 AMSI_RESULT_DETECTED 实现拦截。
 *
 * 编译: g++ -O2 -shared -o amsi_provider.dll amsi_provider.cpp -lole32 -ladvapi32 -static-libgcc -static-libstdc++
 * 注册: regsvr32 /s amsi_provider.dll  （或直接写注册表）
 * 注册表: HKLM\SOFTWARE\Microsoft\AMSI\Providers\{GUID} = DLL 路径
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

// ========================================================================
// AMSI 接口定义（MinGW 无 amsi.h，此处手动定义）
// ========================================================================
typedef enum AMSI_RESULT {
    AMSI_RESULT_CLEAN = 0,
    AMSI_RESULT_NOT_DETECTED = 1,
    AMSI_RESULT_BLOCKED_BY_POLICY = 2,
    AMSI_RESULT_BLOCKED_BY_ADMIN = 3,
    AMSI_RESULT_DETECTED = 32768
} AMSI_RESULT;

// IAmsiStream（Scan 参数，AMSI 传 null；此处仅需类型存在）
MIDL_INTERFACE("ED7B7B8B-B6A8-4F0A-B3A6-0B8F8E9B1C2D")
IAmsiStream : public IUnknown {};

// IAmsiProvider
MIDL_INTERFACE("9002CDB8-AC2C-41A4-8913-EA85002FCE11")
IAmsiProvider : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE Scan(
        IN CONST PVOID content,
        IN ULONG length,
        IN LPCWSTR contentName,
        IN IAmsiStream* stream,
        OUT AMSI_RESULT* result) = 0;
    virtual HRESULT STDMETHODCALLTYPE DisplayName(
        OUT LPWSTR* displayName) = 0;
};

// 本 Provider 的 CLSID（固定）
// {5E2D2B3C-4F1A-4A7B-8E0D-9C3D1E2F3A4B}
static const CLSID CLSID_AndunAmsi =
    {0x5E2D2B3C, 0x4F1A, 0x4A7B, {0x8E, 0x0D, 0x9C, 0x3D, 0x1E, 0x2F, 0x3A, 0x4B}};

// IAmsiProvider IID
static const IID IID_IAmsiProvider =
    {0x9002CDB8, 0xAC2C, 0x41A4, {0x89, 0x13, 0xEA, 0x85, 0x00, 0x2F, 0xCE, 0x11}};

static long g_moduleLockCount = 0;
static volatile LONG g_scanCount = 0;

// ========================================================================
// 恶意脚本特征库（与 fileless_guard.cpp 的 LOLBin 特征一致）
// ========================================================================
struct AmsiPattern {
    const char* keyword;
    int minLength;   // 内容最短长度才检测（减少误报）
};

static const AmsiPattern PATTERNS[] = {
    {"invoke-expression", 60},
    {"iex(", 60},
    {"frombase64string", 40},
    {"downloadstring", 40},
    {"invoke-webrequest", 40},
    {"start-process -windowstyle hidden", 40},
    {"-enc ", 40},
    {"-encodedcommand", 40},
    {"-windowstyle hidden", 40},
    {"wscript.shell", 40},
    {"adodb.stream", 40},
    {"xmldom", 40},
    {"shell.application", 40},
    {"powershell.exe -w hidden", 40},
    {"reflection.assembly.load", 60},
    {"virtualalloc", 80},
    {"createremotethread", 80},
    {"writeprocessmemory", 80},
    {"process hollowing", 60},
    {"0x90", 80},   // NOP 填充（shellcode 特征，需长内容）
    {nullptr, 0}
};

// 小写转换
static void to_lower_inplace(char* s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (s[i] >= 'A' && s[i] <= 'Z') s[i] = s[i] - 'A' + 'a';
    }
}

// 在内容中搜索子串（内存安全）
static bool contains_ci(const unsigned char* content, DWORD length,
                        const char* needle, DWORD needleLen) {
    if (!content || length == 0 || needleLen == 0 || needleLen > length)
        return false;
    // 转换为小写副本（只转前 64KB 足够）
    DWORD scanLen = length > 65536 ? 65536 : length;
    // 逐窗口比较（避免大拷贝）
    DWORD limit = scanLen - needleLen;
    for (DWORD i = 0; i <= limit; i++) {
        bool match = true;
        for (DWORD j = 0; j < needleLen; j++) {
            unsigned char c = content[i + j];
            if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
            if (c != (unsigned char)needle[j]) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

// ========================================================================
// IAmsiProvider 实现
// ========================================================================
class CAndunAmsiProvider : public IAmsiProvider {
public:
    CAndunAmsiProvider() : m_ref(1) { InterlockedIncrement(&g_scanCount); }

    virtual ~CAndunAmsiProvider() {}

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IAmsiProvider) {
            *ppv = static_cast<IAmsiProvider*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override {
        return InterlockedIncrement(&m_ref);
    }

    STDMETHODIMP_(ULONG) Release() override {
        ULONG ref = InterlockedDecrement(&m_ref);
        if (ref == 0) delete this;
        return ref;
    }

    // IAmsiProvider::DisplayName
    STDMETHODIMP DisplayName(LPWSTR* displayName) override {
        if (!displayName) return E_POINTER;
        const wchar_t* name = L"Andun Antivirus AMSI Provider";
        size_t len = wcslen(name) + 1;
        *displayName = (LPWSTR)CoTaskMemAlloc(len * sizeof(wchar_t));
        if (!*displayName) return E_OUTOFMEMORY;
        wcscpy(*displayName, name);
        return S_OK;
    }

    // IAmsiProvider::Scan — 核心检测
    STDMETHODIMP Scan(PVOID content, ULONG length, LPCWSTR contentName,
                      IAmsiStream* stream, AMSI_RESULT* result) override {
        if (!result) return E_POINTER;
        *result = AMSI_RESULT_NOT_DETECTED;

        // 防御：空内容 / 过长内容直接放行
        if (!content || length == 0 || length > 8 * 1024 * 1024)
            return S_OK;

        // 只检查文本类内容（跳过明显二进制）
        // 判断前若干字节是否含空字节（二进制文件特征）
        DWORD probeLen = length > 1024 ? 1024 : length;
        DWORD nullCount = 0;
        for (DWORD i = 0; i < probeLen; i++) {
            if (((unsigned char*)content)[i] == 0) nullCount++;
        }
        // 空字节比例 > 10% 视为二进制，跳过（脚本一般无空字节）
        if (nullCount * 10 > probeLen)
            return S_OK;

        const unsigned char* buf = (const unsigned char*)content;

        // 特征匹配
        for (int i = 0; PATTERNS[i].keyword; i++) {
            size_t klen = strlen(PATTERNS[i].keyword);
            if (length >= (DWORD)PATTERNS[i].minLength &&
                contains_ci(buf, length, PATTERNS[i].keyword, (DWORD)klen)) {
                *result = AMSI_RESULT_DETECTED;
                break;
            }
        }

        return S_OK;
    }

private:
    LONG m_ref;
};

// ========================================================================
// Class Factory
// ========================================================================
class CAndunAmsiFactory : public IClassFactory {
public:
    CAndunAmsiFactory() : m_ref(1) {}

    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&m_ref); }

    STDMETHODIMP_(ULONG) Release() override {
        ULONG ref = InterlockedDecrement(&m_ref);
        if (ref == 0) delete this;
        return ref;
    }

    STDMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) override {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        CAndunAmsiProvider* provider = new CAndunAmsiProvider();
        if (!provider) return E_OUTOFMEMORY;
        HRESULT hr = provider->QueryInterface(riid, ppv);
        provider->Release();
        return hr;
    }

    STDMETHODIMP LockServer(BOOL fLock) override {
        if (fLock) InterlockedIncrement(&g_moduleLockCount);
        else InterlockedDecrement(&g_moduleLockCount);
        return S_OK;
    }

private:
    LONG m_ref;
};

// ========================================================================
// DLL 导出
// ========================================================================
extern "C" {

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (!ppv) return E_POINTER;
    if (rclsid != CLSID_AndunAmsi) return CLASS_E_CLASSNOTAVAILABLE;
    CAndunAmsiFactory* factory = new CAndunAmsiFactory();
    if (!factory) return E_OUTOFMEMORY;
    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

STDAPI DllCanUnloadNow() {
    return g_moduleLockCount == 0 ? S_OK : S_FALSE;
}

STDAPI DllRegisterServer() {
    wchar_t dllPath[MAX_PATH];
    DWORD len = GetModuleFileNameW((HMODULE)&DllGetClassObject, dllPath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return E_FAIL;

    // 注册 CLSID
    wchar_t clsidKey[128];
    StringFromGUID2(CLSID_AndunAmsi, clsidKey, 128);
    // StringFromGUID2 返回 {GUID} 格式，注册表键需要去掉 {} 或用原始格式
    // AMSI 使用带大括号格式：HKLM\SOFTWARE\Microsoft\AMSI\Providers\{GUID}

    wchar_t amsiKey[256];
    swprintf(amsiKey, 256, L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", clsidKey);

    HKEY hKey;
    LONG status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, amsiKey, 0, nullptr, 0,
                                   KEY_WRITE, nullptr, &hKey, nullptr);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);

    status = RegSetValueExW(hKey, L"", 0, REG_SZ,
                            (BYTE*)dllPath, (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    return status == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(status);
}

STDAPI DllUnregisterServer() {
    wchar_t clsidKey[128];
    StringFromGUID2(CLSID_AndunAmsi, clsidKey, 128);
    wchar_t amsiKey[256];
    swprintf(amsiKey, 256, L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", clsidKey);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, amsiKey);
    return S_OK;
}

}  // extern "C"

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    (void)hinst;
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinst);
            break;
        default:
            break;
    }
    return TRUE;
}
