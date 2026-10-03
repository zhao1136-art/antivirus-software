/* Harmless network probe PE: tries outbound TCP, records results in the sandbox dir. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

static void record(const char *line) {
    char path[MAX_PATH];
    const char *wd = getenv("YUTIAN_SANDBOX_WORKDIR");
    if (!wd) wd = getenv("TEMP");
    if (!wd) wd = ".";
    snprintf(path, sizeof(path), "%s\\net_probe_report.txt", wd);
    FILE *f = fopen(path, "a");
    if (f) { fprintf(f, "%s\n", line); fclose(f); }
    printf("%s\n", line);
    fflush(stdout);
}

static void try_connect(const char *host, int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    char msg[256];
    if (s == INVALID_SOCKET) {
        snprintf(msg, sizeof(msg), "%s:%d socket() failed %d", host, port, WSAGetLastError());
        record(msg);
        return;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    addr.sin_addr.s_addr = inet_addr(host);
    int rc = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        snprintf(msg, sizeof(msg), "%s:%d CONNECTED", host, port);
    } else {
        snprintf(msg, sizeof(msg), "%s:%d BLOCKED/FAILED wsa=%d", host, port, WSAGetLastError());
    }
    record(msg);
    closesocket(s);
}

int main(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        record("WSAStartup failed");
        return 1;
    }
    record("--- net probe start ---");
    try_connect("1.1.1.1", 80);
    try_connect("8.8.8.8", 53);
    try_connect("223.5.5.5", 53);
    try_connect("93.184.216.34", 80);
    record("--- net probe end ---");
    WSACleanup();
    Sleep(1200);
    return 0;
}
