/* 原生对照实验：同步 ReadDirectoryChangesW，复用 vs 新建 buffer/OVERLAPPED。 */
#include <windows.h>
#include <stdio.h>

static void dump(char *buf, DWORD bytes) {
    DWORD off = 0;
    if (bytes == 0) { printf("      (0 bytes)"); return; }
    for (;;) {
        FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)(buf + off);
        int n = (int)(fni->FileNameLength / sizeof(WCHAR));
        printf("      action=%lu name=%.*ls\n", fni->Action, n, fni->FileName);
        if (fni->NextEntryOffset == 0) break;
        off += fni->NextEntryOffset;
    }
}

/* mode 0: 复用同一个 OVERLAPPED/buffer（watcher 的写法）
   mode 1: 每次新建 OVERLAPPED/buffer
   mode 2: 复用 OVERLAPPED，但每次新建 buffer */
static void run_case(const char *label, int mode) {
    char dir[MAX_PATH];
    char *buf = NULL;
    OVERLAPPED ov;
    HANDLE h;
    DWORD i, got = 0, zero = 0;
    double tot_immediate_ms = 0;

    GetTempPathA(MAX_PATH, dir);
    strcat_s(dir, MAX_PATH, "rdcw-c-test");
    CreateDirectoryA(dir, NULL);

    h = CreateFileA(dir, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("  %-30s CreateFile err=%lu\n", label, GetLastError());
        return;
    }
    ZeroMemory(&ov, sizeof(ov));

    for (i = 0; i < 5; i++) {
        DWORD ret = 0;
        BOOL ok;
        LARGE_INTEGER f, t0, t1 = {{0}};
        char path[MAX_PATH];
        HANDLE fh;

        if (mode != 0) buf = (char *)HeapAlloc(GetProcessHeap(), 0, 256 * 1024);
        if (mode == 1) ZeroMemory(&ov, sizeof(ov));
        ov.hEvent = NULL;

        QueryPerformanceFrequency(&f);
        QueryPerformanceCounter(&t0);
        ok = ReadDirectoryChangesW(h, buf, 256 * 1024, TRUE, 0x15F, &ret, &ov, NULL);
        QueryPerformanceCounter(&t1);
        {
            double ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)f.QuadPart;
            if (ms < 1.0) tot_immediate_ms += 1;
        }

        sprintf_s(path, MAX_PATH, "%s\\w%lu.txt", dir, i);
        fh = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, NULL);
        if (fh != INVALID_HANDLE_VALUE) CloseHandle(fh);
        Sleep(180);

        printf("    call#%lu ok=%d ret=%lu%s\n", i, (int)ok, ret,
               (ret && ok) ? "" : "   <-- 无数据");
        if (ok) dump(buf, ret);
        if (ok && ret) got++; else zero++;

        DeleteFileA(path);
        Sleep(130);
        if (mode != 0) { HeapFree(GetProcessHeap(), 0, buf); buf = NULL; }
    }
    printf("  %-30s 有数据=%lu 无数据=%lu 立即返回=%lu\n", label, got, zero,
           (DWORD)tot_immediate_ms);
    CloseHandle(h);
    if (mode == 0 && buf) HeapFree(GetProcessHeap(), 0, buf);
    RemoveDirectoryA(dir);
}

int main(void) {
    printf("sizeof(OVERLAPPED)=%d, sizeof(FILE_NOTIFY_INFORMATION)=%d\n",
           (int)sizeof(OVERLAPPED), (int)sizeof(FILE_NOTIFY_INFORMATION));
    run_case("mode0 reuse both", 0);
    run_case("mode1 fresh both", 1);
    run_case("mode2 reuse ov, fresh buf", 2);
    return 0;
}
