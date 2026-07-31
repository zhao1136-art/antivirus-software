/**
 * 安盾 实时文件守护进程 (Native C++)
 * 使用 ReadDirectoryChangesW 监控文件变更，通过命名管道与 Python 后端通信
 * 
 * 编译: g++ -O2 -static -o file_guard.exe file_guard.cpp -lole32 -luuid -ladvapi32
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define PIPE_NAME L"\\\\.\\pipe\\AndunFileGuard"
#define BUFFER_SIZE (64 * 1024)
#define MAX_PATH_LEN 1024

typedef struct {
    OVERLAPPED ol;
    HANDLE hDir;
    BYTE buffer[BUFFER_SIZE];
    DWORD notifyFilter;
    BOOL watchSubtree;
} DirectoryWatch;

typedef struct {
    HANDLE hPipe;
    CRITICAL_SECTION cs;
    BOOL running;
} PipeServer;

static PipeServer g_pipe = {NULL, {0}, FALSE};
static DirectoryWatch g_watches[16];
static int g_watchCount = 0;
static wchar_t g_watchPaths[16][MAX_PATH_LEN];

// ============== 管道通信 ==============

static void send_to_python(const wchar_t* action, const wchar_t* filepath) {
    if (!g_pipe.hPipe || g_pipe.hPipe == INVALID_HANDLE_VALUE) return;
    
    EnterCriticalSection(&g_pipe.cs);
    wchar_t msg[2048];
    swprintf(msg, 2048, L"{\"action\":\"%s\",\"path\":\"%s\",\"timestamp\":%lld}\n",
             action, filepath, (long long)GetTickCount64());
    
    DWORD written;
    WriteFile(g_pipe.hPipe, msg, (DWORD)(wcslen(msg) * sizeof(wchar_t)), &written, NULL);
    LeaveCriticalSection(&g_pipe.cs);
}

static DWORD WINAPI pipe_thread(LPVOID param) {
    while (g_pipe.running) {
        HANDLE hPipe = CreateNamedPipeW(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 4096, 4096, 0, NULL
        );
        
        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }
        
        if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            g_pipe.hPipe = hPipe;
            
            // 读取指令
            wchar_t cmd[512];
            DWORD read;
            while (g_pipe.running) {
                if (ReadFile(hPipe, cmd, sizeof(cmd) - 2, &read, NULL) && read > 0) {
                    cmd[read / sizeof(wchar_t)] = 0;
                    
                    if (wcsstr(cmd, L"add_watch")) {
                        // 格式: add_watch:path:recursive
                        wchar_t* path = wcsstr(cmd, L":") + 1;
                        wchar_t* recursive = wcsrchr(path, L':');
                        if (recursive) { *recursive = 0; recursive++; }
                        
                        if (g_watchCount < 16) {
                            wcscpy(g_watchPaths[g_watchCount], path);
                            // watch 将在主循环中添加
                        }
                    } else if (wcsstr(cmd, L"quit")) {
                        break;
                    }
                } else {
                    break;
                }
            }
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            g_pipe.hPipe = NULL;
        } else {
            CloseHandle(hPipe);
        }
    }
    return 0;
}

// ============== 目录监控 ==============

static void CALLBACK dir_callback(DWORD err, DWORD bytesXfer, LPOVERLAPPED ol) {
    DirectoryWatch* dw = (DirectoryWatch*)((char*)ol - offsetof(DirectoryWatch, ol));
    
    if (err != ERROR_SUCCESS || bytesXfer == 0) {
        // 重新发起监控
        ReadDirectoryChangesW(dw->hDir, dw->buffer, BUFFER_SIZE, dw->watchSubtree,
                             dw->notifyFilter, NULL, &dw->ol, dir_callback);
        return;
    }
    
    BYTE* buf = dw->buffer;
    FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)buf;
    
    while (TRUE) {
        wchar_t filename[MAX_PATH_LEN];
        wcsncpy(filename, fni->FileName, fni->FileNameLength / sizeof(wchar_t));
        filename[fni->FileNameLength / sizeof(wchar_t)] = 0;
        
        const wchar_t* action = L"unknown";
        switch (fni->Action) {
            case FILE_ACTION_ADDED:            action = L"created"; break;
            case FILE_ACTION_REMOVED:          action = L"deleted"; break;
            case FILE_ACTION_MODIFIED:         action = L"modified"; break;
            case FILE_ACTION_RENAMED_OLD_NAME: action = L"renamed_old"; break;
            case FILE_ACTION_RENAMED_NEW_NAME: action = L"renamed_new"; break;
        }
        
        // 构建完整路径
        wchar_t fullPath[MAX_PATH_LEN * 2];
        int watchIdx = -1;
        for (int i = 0; i < g_watchCount; i++) {
            if (g_watches[i].hDir == dw->hDir) { watchIdx = i; break; }
        }
        if (watchIdx >= 0) {
            swprintf(fullPath, MAX_PATH_LEN * 2, L"%s\\%s", g_watchPaths[watchIdx], filename);
        } else {
            wcscpy(fullPath, filename);
        }
        
        // 只关注文件创建和修改
        if (fni->Action == FILE_ACTION_ADDED || fni->Action == FILE_ACTION_MODIFIED) {
            send_to_python(action, fullPath);
        }
        
        if (fni->NextEntryOffset == 0) break;
        fni = (FILE_NOTIFY_INFORMATION*)((BYTE*)fni + fni->NextEntryOffset);
    }
    
    // 重新发起监控
    ReadDirectoryChangesW(dw->hDir, dw->buffer, BUFFER_SIZE, dw->watchSubtree,
                         dw->notifyFilter, NULL, &dw->ol, dir_callback);
}

static void add_directory_watch(const wchar_t* path, BOOL recursive) {
    if (g_watchCount >= 16) return;
    
    HANDLE hDir = CreateFileW(
        path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );
    
    if (hDir == INVALID_HANDLE_VALUE) return;
    
    DirectoryWatch* dw = &g_watches[g_watchCount];
    ZeroMemory(dw, sizeof(DirectoryWatch));
    dw->hDir = hDir;
    dw->notifyFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE;
    dw->watchSubtree = recursive;
    dw->ol.hEvent = NULL;  // 使用回调，不需要事件
    
    wcscpy(g_watchPaths[g_watchCount], path);
    g_watchCount++;
    
    // 发起首次异步监控
    ReadDirectoryChangesW(hDir, dw->buffer, BUFFER_SIZE, recursive,
                         dw->notifyFilter, NULL, &dw->ol, dir_callback);
}

// ============== 主入口 ==============

int wmain(int argc, wchar_t* argv[]) {
    g_pipe.running = TRUE;
    InitializeCriticalSection(&g_pipe.cs);
    
    // 默认监控用户目录
    wchar_t userProfile[MAX_PATH_LEN];
    GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH_LEN);
    
    wchar_t desktop[MAX_PATH_LEN * 2];
    wchar_t downloads[MAX_PATH_LEN * 2];
    swprintf(desktop, MAX_PATH_LEN * 2, L"%s\\Desktop", userProfile);
    swprintf(downloads, MAX_PATH_LEN * 2, L"%s\\Downloads", userProfile);
    
    add_directory_watch(desktop, FALSE);
    add_directory_watch(downloads, TRUE);
    
    // 从命令行参数添加额外监控路径
    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--watch") == 0 && i + 1 < argc) {
            i++;
            add_directory_watch(argv[i], FALSE);
        }
    }
    
    // 启动管道服务线程
    HANDLE hPipeThread = CreateThread(NULL, 0, pipe_thread, NULL, 0, NULL);
    
    wprintf(L"[AndunGuard] Running, watching %d directories\n", g_watchCount);
    
    // 主消息循环（使用 alertable wait 以支持 APC 回调）
    while (g_pipe.running) {
        SleepEx(100, TRUE);  // alertable sleep，允许 APC 回调执行
    }
    
    WaitForSingleObject(hPipeThread, 3000);
    CloseHandle(hPipeThread);
    
    DeleteCriticalSection(&g_pipe.cs);
    return 0;
}
