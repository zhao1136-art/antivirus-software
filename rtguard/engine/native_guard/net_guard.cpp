/**
 * 网络侧补强模块
 *
 * 替代 mitmproxy 代理方案，通过 GetTcpTable2 枚举系统全部 TCP 连接，
 * 绑定 PID 信息，匹配 C2 黑名单。捕获普通 Socket 木马绕过 HTTP 代理的漏洞。
 *
 * 优势:
 * - 枚举所有 TCP 连接，不依赖代理配置
 * - C++ 原生 API，性能远优于 psutil
 * - 可检测所有进程的外联行为
 */
#include "native_guard.h"

/**
 * 枚举系统全部 TCP 连接（IPv4 + IPv6）
 * 使用 GetExtendedTcpTable（兼容 Windows XP+）
 * 
 * JSON: {"connections": [...], "total": N}
 */
extern "C" __declspec(dllexport) char* guard_net_enum_tcp() {
    std::string json = "{\"connections\":[";
    bool first = true;
    DWORD total = 0;

    // ---- IPv4 TCP ----
    DWORD tcpSize = 0;
    GetExtendedTcpTable(nullptr, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcpSize > 0) {
        std::vector<BYTE> tcpBuf(tcpSize + 1024);
        PMIB_TCPTABLE_OWNER_PID tcpTable = (PMIB_TCPTABLE_OWNER_PID)tcpBuf.data();

        if (GetExtendedTcpTable(tcpTable, &tcpSize, FALSE, AF_INET,
                                TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID& row = tcpTable->table[i];

                IN_ADDR local, remote;
                local.S_un.S_addr = row.dwLocalAddr;
                remote.S_un.S_addr = row.dwRemoteAddr;

                char localIp[16], remoteIp[16];
                strcpy(localIp, inet_ntoa(local));
                strcpy(remoteIp, inet_ntoa(remote));

                u_short localPort = ntohs((u_short)row.dwLocalPort);
                u_short remotePort = ntohs((u_short)row.dwRemotePort);

                const char* state = "UNKNOWN";
                switch (row.dwState) {
                    case MIB_TCP_STATE_ESTAB:   state = "ESTABLISHED"; break;
                    case MIB_TCP_STATE_LISTEN:   state = "LISTEN"; break;
                    case MIB_TCP_STATE_SYN_SENT: state = "SYN_SENT"; break;
                    case MIB_TCP_STATE_SYN_RCVD: state = "SYN_RCVD"; break;
                    case MIB_TCP_STATE_CLOSE_WAIT: state = "CLOSE_WAIT"; break;
                    case MIB_TCP_STATE_LAST_ACK: state = "LAST_ACK"; break;
                    case MIB_TCP_STATE_TIME_WAIT: state = "TIME_WAIT"; break;
                    case MIB_TCP_STATE_CLOSED:   state = "CLOSED"; break;
                    case MIB_TCP_STATE_FIN_WAIT1: state = "FIN_WAIT1"; break;
                    case MIB_TCP_STATE_FIN_WAIT2: state = "FIN_WAIT2"; break;
                }

                // 获取进程名
                std::string procName = get_process_name_by_pid(row.dwOwningPid);

                // 获取进程完整路径
                std::string procPath = get_process_path_by_pid(row.dwOwningPid);

                // 是否为外连连接？
                bool outbound = (row.dwState == MIB_TCP_STATE_ESTAB ||
                                 row.dwState == MIB_TCP_STATE_SYN_SENT) &&
                                 row.dwRemoteAddr != 0 &&
                                 strcmp(remoteIp, "0.0.0.0") != 0;

                if (!first) json += ",";
                first = false;
                total++;

                char buf[1024];
                snprintf(buf, sizeof(buf),
                    "{\"pid\":%lu,\"process\":\"%s\",\"path\":\"%s\",\"family\":\"IPv4\","
                    "\"local\":\"%s:%u\",\"remote\":\"%s:%u\",\"state\":\"%s\",\"outbound\":%s}",
                    row.dwOwningPid, json_escape(procName).c_str(),
                    json_escape(procPath).c_str(),
                    localIp, localPort, remoteIp, remotePort, state,
                    outbound ? "true" : "false");
                json += buf;
            }
        }
    }

    // ---- IPv6 TCP ----
    DWORD tcp6Size = 0;
    GetExtendedTcpTable(nullptr, &tcp6Size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcp6Size > 0) {
        std::vector<BYTE> tcp6Buf(tcp6Size + 1024);
        PMIB_TCP6TABLE_OWNER_PID tcp6Table = (PMIB_TCP6TABLE_OWNER_PID)tcp6Buf.data();

        if (GetExtendedTcpTable(tcp6Table, &tcp6Size, FALSE, AF_INET6,
                                TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcp6Table->dwNumEntries; i++) {
                MIB_TCP6ROW_OWNER_PID& row = tcp6Table->table[i];

                char localIp[64], remoteIp[64];
                inet_ntop(AF_INET6, &row.ucLocalAddr, localIp, sizeof(localIp));
                inet_ntop(AF_INET6, &row.ucRemoteAddr, remoteIp, sizeof(remoteIp));

                u_short localPort = ntohs((u_short)row.dwLocalPort);
                u_short remotePort = ntohs((u_short)row.dwRemotePort);

                const char* state = "UNKNOWN";
                switch (row.dwState) {
                    case MIB_TCP_STATE_ESTAB:   state = "ESTABLISHED"; break;
                    case MIB_TCP_STATE_LISTEN:   state = "LISTEN"; break;
                    case MIB_TCP_STATE_SYN_SENT: state = "SYN_SENT"; break;
                    case MIB_TCP_STATE_CLOSE_WAIT: state = "CLOSE_WAIT"; break;
                    case MIB_TCP_STATE_TIME_WAIT: state = "TIME_WAIT"; break;
                    case MIB_TCP_STATE_CLOSED:   state = "CLOSED"; break;
                }

                std::string procName = get_process_name_by_pid(row.dwOwningPid);
                std::string procPath = get_process_path_by_pid(row.dwOwningPid);

                bool outbound = (row.dwState == MIB_TCP_STATE_ESTAB) &&
                                row.ucRemoteAddr[0] != 0 &&
                                row.ucRemoteAddr[1] != 0 &&
                                remotePort > 0;

                if (!first) json += ",";
                first = false;
                total++;

                char buf[1152];
                snprintf(buf, sizeof(buf),
                    "{\"pid\":%lu,\"process\":\"%s\",\"path\":\"%s\",\"family\":\"IPv6\","
                    "\"local\":\"[%s]:%u\",\"remote\":\"[%s]:%u\",\"state\":\"%s\",\"outbound\":%s}",
                    row.dwOwningPid, json_escape(procName).c_str(),
                    json_escape(procPath).c_str(),
                    localIp, localPort, remoteIp, remotePort, state,
                    outbound ? "true" : "false");
                json += buf;
            }
        }
    }

    json += "],\"total\":" + std::to_string(total) + "}";
    return alloc_str(json.c_str());
}

/**
 * 枚举 TCP 连接并标记已知恶意端口
 * 常见 C2/木马端口列表
 */
extern "C" __declspec(dllexport) char* guard_net_enum_with_risk() {
    // 已知恶意/可疑端口 -> 标签
    static const std::pair<int, const char*> MALICIOUS_PORTS[] = {
        {4444, "Metasploit default"},
        {5555, "Android ADB / Trojan"},
        {6666, "IRC bot / Trojan"},
        {1337, "Hacktool"},
        {31337, "BackOrifice"},
        {12345, "NetBus"},
        {12346, "NetBus"},
        {27374, "SubSeven"},
        {54321, "PCAnywhere"},
        {9001, "Tor / CobaltStrike beacon"},
        {9050, "Tor SOCKS"},
        {9150, "Tor SOCKS"},
        {9051, "Tor control"},
        {8080, "HTTP proxy / C2"},
        {8443, "HTTPS alt / C2"},
        {447, "SSL VPN / CobaltStrike"},
        {2222, "C2 common"},
        {10080, "C2 common"},
        {65500, "Backdoor"},
        {2525, "SMTP alt / phishing"},
        {587, "SMTP alt / phishing"},
        {25, "SMTP / spam relay"},
        {-1, nullptr}
    };

    std::string json = "{\"connections\":[";
    bool first = true;
    DWORD total = 0;
    DWORD highRisk = 0;

    DWORD tcpSize = 0;
    GetExtendedTcpTable(nullptr, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcpSize > 0) {
        std::vector<BYTE> tcpBuf(tcpSize + 1024);
        PMIB_TCPTABLE_OWNER_PID tcpTable = (PMIB_TCPTABLE_OWNER_PID)tcpBuf.data();

        if (GetExtendedTcpTable(tcpTable, &tcpSize, FALSE, AF_INET,
                                TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID& row = tcpTable->table[i];
                
                u_short remotePort = ntohs((u_short)row.dwRemotePort);
                u_short localPort = ntohs((u_short)row.dwLocalPort);

                IN_ADDR local, remote;
                local.S_un.S_addr = row.dwLocalAddr;
                remote.S_un.S_addr = row.dwRemoteAddr;
                char localIp[16], remoteIp[16];
                strcpy(localIp, inet_ntoa(local));
                strcpy(remoteIp, inet_ntoa(remote));

                // 风险判定
                std::string risk = "safe";
                std::string riskReason;
                std::string portLabel;

                // 检查恶意端口
                for (int p = 0; MALICIOUS_PORTS[p].first > 0; p++) {
                    if (remotePort == MALICIOUS_PORTS[p].first) {
                        risk = "high";
                        riskReason = "malicious_port";
                        portLabel = MALICIOUS_PORTS[p].second;
                        break;
                    }
                }

                // 非标准端口外连
                bool outbound = (row.dwState == MIB_TCP_STATE_ESTAB) &&
                                row.dwRemoteAddr != 0 && strcmp(remoteIp, "0.0.0.0") != 0;
                if (outbound && risk == "safe" && remotePort != 80 && remotePort != 443 &&
                    remotePort != 22 && remotePort != 21) {
                    risk = "suspicious";
                    riskReason = "unusual_outbound_port";
                }

                std::string procName = get_process_name_by_pid(row.dwOwningPid);

                if (risk != "safe") {
                    if (!first) json += ",";
                    first = false;
                    total++;
                    if (risk == "high") highRisk++;

                    char buf[1024];
                    snprintf(buf, sizeof(buf),
                        "{\"pid\":%lu,\"process\":\"%s\",\"family\":\"IPv4\","
                        "\"local\":\"%s:%u\",\"remote\":\"%s:%u\",\"state\":\"%s\","
                        "\"risk\":\"%s\",\"reason\":\"%s\",\"port_label\":\"%s\"}",
                        row.dwOwningPid, json_escape(procName).c_str(),
                        localIp, localPort, remoteIp, remotePort,
                        row.dwState == MIB_TCP_STATE_ESTAB ? "ESTABLISHED" : "UNKNOWN",
                        risk, riskReason.c_str(), json_escape(portLabel).c_str());
                    json += buf;
                }
            }
        }
    }

    json += "],\"total\":" + std::to_string(total);
    json += ",\"high_risk\":" + std::to_string(highRisk) + "}";
    return alloc_str(json.c_str());
}
