/**
 * 安盾 原生引擎 - 启发式检测模块
 * 基于 PE 解析结果建立风险打分模型：
 *   无窗口程序 / 异常入口点 / 无数字签名 / 大量高危API组合 / 高熵值
 * 加权判定可疑文件，输出 0-100 风险分数
 */
#include "native_common.h"
#include <map>

// ============== 风险权重模型 ==============
struct RiskWeights {
    double rwx_section      = 15.0;  // 每个RWX节
    double high_entropy     = 10.0;  // 高熵节（>7.0，加壳特征）
    double high_risk_api    = 3.0;   // 每个高危API
    double no_gui           = 8.0;   // 无窗口程序
    double no_signature     = 12.0;  // 无数字签名
    double abnormal_entry   = 10.0;  // 异常入口点（不在代码段）
    double suspicious_urls  = 5.0;   // 含域名/URL字符串
    double small_size_code  = 5.0;   // 代码段过小（注入器特征）
    double anti_debug       = 8.0;   // 反调试特征
    double privilege_escal  = 10.0;  // 提权特征
};

// 风险等级判定
static const char* risk_level(double score) {
    if (score >= 70.0) return "critical";
    if (score >= 50.0) return "high";
    if (score >= 30.0) return "medium";
    if (score >= 15.0) return "low";
    return "safe";
}

// ============== 高危 API 分类统计 ==============
struct ApiCategories {
    int process_injection = 0;   // 进程注入
    int process_creation  = 0;   // 进程创建
    int privilege_escal   = 0;   // 提权
    int anti_debug        = 0;   // 反调试
    int network           = 0;   // 网络通信
    int registry          = 0;   // 注册表
    int service           = 0;   // 服务管理
    int memory_manip      = 0;   // 内存操作
    int crypto            = 0;   // 加密操作
    int credential        = 0;   // 凭证窃取
};

static ApiCategories categorize_api(const char* name) {
    ApiCategories cat;
    const char* n = name;

    // 进程注入
    if (_stricmp(n, "CreateRemoteThread") == 0 || _stricmp(n, "WriteProcessMemory") == 0 ||
        _stricmp(n, "VirtualAllocEx") == 0 || _stricmp(n, "NtCreateThreadEx") == 0 ||
        _stricmp(n, "RtlCreateUserThread") == 0 || _stricmp(n, "QueueUserAPC") == 0 ||
        _stricmp(n, "SetWindowsHookEx") == 0 || _stricmp(n, "NtQueueApcThread") == 0)
        cat.process_injection = 1;

    // 进程创建
    if (_stricmp(n, "CreateProcess") == 0 || _stricmp(n, "WinExec") == 0 ||
        _stricmp(n, "ShellExecute") == 0 || _stricmp(n, "NtCreateProcess") == 0 ||
        _stricmp(n, "NtCreateProcessEx") == 0 || _stricmp(n, "NtCreateUserProcess") == 0)
        cat.process_creation = 1;

    // 提权
    if (_stricmp(n, "AdjustTokenPrivileges") == 0 || _stricmp(n, "LookupPrivilegeValue") == 0)
        cat.privilege_escal = 1;

    // 反调试
    if (_stricmp(n, "IsDebuggerPresent") == 0 || _stricmp(n, "CheckRemoteDebuggerPresent") == 0 ||
        _stricmp(n, "NtQueryInformationProcess") == 0 || _stricmp(n, "SetThreadContext") == 0 ||
        _stricmp(n, "GetThreadContext") == 0)
        cat.anti_debug = 1;

    // 网络
    if (_stricmp(n, "URLDownloadToFile") == 0 || _stricmp(n, "InternetOpenUrl") == 0)
        cat.network = 1;

    // 注册表
    if (_stricmp(n, "RegSetValueEx") == 0 || _stricmp(n, "RegCreateKeyEx") == 0)
        cat.registry = 1;

    // 服务
    if (_stricmp(n, "StartService") == 0 || _stricmp(n, "ControlService") == 0 ||
        _stricmp(n, "CreateService") == 0)
        cat.service = 1;

    // 内存操作
    if (_stricmp(n, "NtAllocateVirtualMemory") == 0 || _stricmp(n, "NtWriteVirtualMemory") == 0 ||
        _stricmp(n, "NtProtectVirtualMemory") == 0 || _stricmp(n, "NtUnmapViewOfSection") == 0 ||
        _stricmp(n, "NtMapViewOfSection") == 0)
        cat.memory_manip = 1;

    // 加密
    if (_stricmp(n, "CryptEncrypt") == 0 || _stricmp(n, "CryptDecrypt") == 0)
        cat.crypto = 1;

    // 凭证
    if (_stricmp(n, "LsaLogonUser") == 0 || _stricmp(n, "SamConnect") == 0 ||
        _stricmp(n, "SamOpenDomain") == 0)
        cat.credential = 1;

    return cat;
}

// ============== 导出: 启发式风险打分 ==============
// 输入: PE解析结果的 JSON 字符串
// 输出: 风险评分 JSON
extern "C" __declspec(dllexport) char* heuristic_score(const char* pe_json) {
    std::string json(pe_json ? pe_json : "");
    RiskWeights w;
    double totalScore = 0.0;
    ApiCategories totalCat;

    // 简单的JSON值提取（避免引入完整的JSON解析器）
    auto get_int = [&json](const char* key) -> int {
        std::string k = std::string("\"") + key + "\":";
        size_t pos = json.find(k);
        if (pos == std::string::npos) return 0;
        pos += k.size();
        while (pos < json.size() && json[pos] == ' ') pos++;
        return atoi(json.c_str() + pos);
    };

    auto get_bool = [&json](const char* key) -> bool {
        std::string k = std::string("\"") + key + "\":";
        size_t pos = json.find(k);
        if (pos == std::string::npos) return false;
        pos += k.size();
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
        return json.substr(pos, 4) == "true";
    };

    auto get_str = [&json](const char* key) -> std::string {
        std::string k = std::string("\"") + key + "\":\"";
        size_t pos = json.find(k);
        if (pos == std::string::npos) return "";
        pos += k.size();
        size_t end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    };

    RiskWeights weights;
    std::string reasons;
    bool firstReason = true;

    auto add_reason = [&](const char* fmt, ...) {
        if (!firstReason) reasons += ",";
        firstReason = false;
        char buf[512];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        reasons += "\"" + json_escape(buf) + "\"";
    };

    // 1. RWX 节检查
    int rwxCount = get_int("rwx_sections");
    if (rwxCount > 0) {
        double score = w.rwx_section * rwxCount;
        if (score > 30.0) score = 30.0;
        totalScore += score;
        add_reason("发现 %d 个可读写执行(RWX)节，加 %.0f 分", rwxCount, score);
    }

    // 2. 高熵值（加壳特征）
    int highEntropyCount = get_int("high_entropy_sections");
    double maxEntropy = (double)get_int("max_entropy");
    if (maxEntropy > 7.0) {
        double score = w.high_entropy * (maxEntropy - 6.5);
        if (score > 25.0) score = 25.0;
        totalScore += score;
        add_reason("检测到高熵值(%.1f)，疑似加壳程序(UPX/VMProtect)，加 %.0f 分", maxEntropy, score);
    }

    // 3. 高危API
    int highRiskApiCount = get_int("high_risk_api_count");
    if (highRiskApiCount > 0) {
        double score = w.high_risk_api * highRiskApiCount;
        if (score > 30.0) score = 30.0;
        totalScore += score;
        add_reason("发现 %d 个高危API调用，加 %.0f 分", highRiskApiCount, score);
    }

    // 4. 无窗口程序
    int subsystem = get_int("subsystem");
    bool isGui = (subsystem == 2); // IMAGE_SUBSYSTEM_WINDOWS_GUI
    if (!isGui && subsystem != 0) {
        totalScore += w.no_gui;
        add_reason("非GUI子系统程序(sub=%d)，加 %.0f 分", subsystem, w.no_gui);
    }

    // 5. 无数字签名（从json中无法直接获取，保守处理）
    bool hasSig = get_bool("has_signature");
    if (!hasSig) {
        totalScore += w.no_signature;
        add_reason("无数字签名，加 %.0f 分", w.no_signature);
    }

    // 6. 可疑 URL
    int suspiciousUrls = get_int("suspicious_urls_count");
    if (suspiciousUrls > 0) {
        double score = w.suspicious_urls * suspiciousUrls;
        if (score > 15.0) score = 15.0;
        totalScore += score;
        add_reason("提取到 %d 个可疑URL/域名，加 %.0f 分", suspiciousUrls, score);
    }

    // 7. 小代码段（注入器特征）
    int sizeOfCode = get_int("size_of_code");
    if (sizeOfCode > 0 && sizeOfCode < 4096) {
        totalScore += w.small_size_code;
        add_reason("代码段过小(%d字节，注入器特征)，加 %.0f 分", sizeOfCode, w.small_size_code);
    }

    // 8. PE类型检查
    std::string peType = get_str("pe_type");
    int entryPoint = get_int("entry_point");

    // 限定总分
    if (totalScore > 100.0) totalScore = 100.0;

    // 构建输出
    char buf[2048];
    snprintf(buf, sizeof(buf),
             "{\"risk_score\":%.1f,\"risk_level\":\"%s\",\"reasons\":[%s],"
             "\"pe_type\":\"%s\",\"entry_point\":%d,\"subsystem\":%d}",
             totalScore, risk_level(totalScore), reasons.c_str(),
             json_escape(peType).c_str(), entryPoint, subsystem);
    return alloc_str(buf);
}

// ============== 导出: 快速启发式（给定数值参数直接打分）==============
extern "C" __declspec(dllexport) char* heuristic_score_fast(
        int rwx_sections, double max_entropy, int high_risk_api_count,
        int subsystem, int has_signature, int suspicious_urls, int size_of_code) {
    
    RiskWeights w;
    double totalScore = 0.0;
    std::string reasons;
    bool firstReason = true;

    auto add_reason = [&](const char* fmt, ...) {
        if (!firstReason) reasons += ",";
        firstReason = false;
        char buf[512];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        reasons += "\"" + json_escape(buf) + "\"";
    };

    if (rwx_sections > 0) {
        double s = w.rwx_section * rwx_sections;
        if (s > 30.0) s = 30.0;
        totalScore += s;
        add_reason("RWX节: %d 个，+%.0f", rwx_sections, s);
    }

    if (max_entropy > 7.0) {
        double s = w.high_entropy * (max_entropy - 6.5);
        if (s > 25.0) s = 25.0;
        totalScore += s;
        add_reason("高熵值: %.1f (加壳特征)，+%.0f", max_entropy, s);
    }

    if (high_risk_api_count > 0) {
        double s = w.high_risk_api * high_risk_api_count;
        if (s > 30.0) s = 30.0;
        totalScore += s;
        add_reason("高危API: %d 个，+%.0f", high_risk_api_count, s);
    }

    if (subsystem != 2 && subsystem != 0) {
        totalScore += w.no_gui;
        add_reason("非GUI程序，+%.0f", w.no_gui);
    }

    if (!has_signature) {
        totalScore += w.no_signature;
        add_reason("无数字签名，+%.0f", w.no_signature);
    }

    if (suspicious_urls > 0) {
        double s = w.suspicious_urls * suspicious_urls;
        if (s > 15.0) s = 15.0;
        totalScore += s;
        add_reason("可疑URL: %d 个，+%.0f", suspicious_urls, s);
    }

    if (size_of_code > 0 && size_of_code < 4096) {
        totalScore += w.small_size_code;
        add_reason("代码段过小(%d字节)，+%.0f", size_of_code, w.small_size_code);
    }

    if (totalScore > 100.0) totalScore = 100.0;

    char buf[1024];
    snprintf(buf, sizeof(buf),
             "{\"risk_score\":%.1f,\"risk_level\":\"%s\",\"reasons\":[%s]}",
             totalScore, risk_level(totalScore), reasons.c_str());
    return alloc_str(buf);
}
