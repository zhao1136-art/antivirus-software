/**
 * 御天 AMSI Provider (升级一：无文件攻击事中拦截)
 *
 * 注册为 Windows AMSI Provider 后，PowerShell / VBS / 宏 / JScript
 * 在执行脚本内容前会调用本 DLL 的 Scan() 方法。
 * 通过检测常见恶意脚本特征（Base64 编码、远程下载、混淆执行等），
 * 在载荷执行前返回 AMSI_RESULT_DETECTED 实现拦截。
 *
 * 编译: g++ -O2 -shared -o amsi_provider.dll amsi_provider.cpp -lole32 -ladvapi32 -static-libgcc -static-libstdc++
 * 注册: regsvr32 /s amsi_provider.dll  （或 python amsi_manager.py register）
 *
 * ⚠️ 注册表必须写**三处**，少一处 AMSI 就会整体失效（2026-10-04 修正）：
 *      HKLM\SOFTWARE\Classes\CLSID\{GUID}                       = Provider 名称
 *      HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32        = DLL 全路径
 *          + ThreadingModel = Both
 *      HKLM\SOFTWARE\Microsoft\AMSI\Providers\{GUID}            = Provider 名称
 *
 *   原因：amsi.dll 是**通过 COM** 加载 Provider 的（枚举 Providers 键拿到 GUID
 *   后调 CoCreateInstance）。只写 Providers 键、不注册 COM CLSID，会让每次
 *   AmsiScanBuffer 都去实例化一个不存在的 COM 类 —— 结果是 AmsiInitialize
 *   直接失败（实测 0x80070002 ERROR_FILE_NOT_FOUND），**全系统 AMSI 内容扫描
 *   静默失效**，比不注册更糟。原实现就踩了这个坑。
 *
 *   另外 Providers 键里放的是 **Provider 名称**，不是 DLL 路径。
 *   注销时只删自己那条 GUID，**绝不能删 Providers 父键**（那是所有 Provider
 *   共享的；火绒 6.0.12.1 退出时就把整个父键删掉了，导致本机 AMSI 全废）。
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

// Provider 展示名 —— 写进 CLSID 默认值和 AMSI Providers 默认值。
// 注意：Windows 约定这里放的是**名称**，不是 DLL 路径。
static const wchar_t PROVIDER_NAME[] = L"YutianAmsiProvider";

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
// 注册表小工具（供 DllRegisterServer / DllUnregisterServer 使用）
// ========================================================================
static LONG SetSz(HKEY root, const wchar_t* sub, const wchar_t* name,
                  const wchar_t* value) {
    HKEY k = nullptr;
    LONG st = RegCreateKeyExW(root, sub, 0, nullptr, 0, KEY_WRITE, nullptr, &k, nullptr);
    if (st != ERROR_SUCCESS) return st;
    st = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)value,
                        (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    return st;
}

// 递归删除一个键及其子键（RegDeleteKeyW 只能删空键）
static void DelTree(HKEY root, const wchar_t* sub) {
    HKEY k = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_ALL_ACCESS, &k) == ERROR_SUCCESS) {
        wchar_t child[256];
        DWORD n = 256;
        while (RegEnumKeyExW(k, 0, child, &n, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            wchar_t full[1024];
            swprintf(full, 1024, L"%s\\%s", sub, child);
            DelTree(root, full);
            n = 256;
        }
        RegCloseKey(k);
    }
    RegDeleteKeyW(root, sub);
}

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

    wchar_t clsidKey[128];
    StringFromGUID2(CLSID_AndunAmsi, clsidKey, 128);   // 形如 {GUID}

    wchar_t sub[512];

    // 1) COM CLSID —— 默认值 = Provider 名称
    swprintf(sub, 512, L"SOFTWARE\\Classes\\CLSID\\%s", clsidKey);
    if (SetSz(HKEY_LOCAL_MACHINE, sub, L"", PROVIDER_NAME) != ERROR_SUCCESS) return E_FAIL;

    // 2) COM CLSID —— InprocServer32 = DLL 全路径 + ThreadingModel
    //    这一处缺失正是"注册后 AMSI 反而失效"的根因
    swprintf(sub, 512, L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", clsidKey);
    if (SetSz(HKEY_LOCAL_MACHINE, sub, L"", dllPath) != ERROR_SUCCESS) return E_FAIL;
    if (SetSz(HKEY_LOCAL_MACHINE, sub, L"ThreadingModel", L"Both") != ERROR_SUCCESS) return E_FAIL;

    // 3) AMSI Providers —— 值是 Provider 名称，**不是 DLL 路径**
    swprintf(sub, 512, L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", clsidKey);
    if (SetSz(HKEY_LOCAL_MACHINE, sub, L"", PROVIDER_NAME) != ERROR_SUCCESS) return E_FAIL;

    return S_OK;
}

STDAPI DllUnregisterServer() {
    wchar_t clsidKey[128];
    StringFromGUID2(CLSID_AndunAmsi, clsidKey, 128);

    wchar_t sub[512];
    swprintf(sub, 512, L"SOFTWARE\\Classes\\CLSID\\%s", clsidKey);
    DelTree(HKEY_LOCAL_MACHINE, sub);
    swprintf(sub, 512, L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", clsidKey);
    DelTree(HKEY_LOCAL_MACHINE, sub);
    // ⚠️ 绝不删除 HKLM\SOFTWARE\Microsoft\AMSI\Providers 父键 —— 那是共享键，
    //    删掉会让所有 Provider（含 Defender/第三方）一起失效。
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
