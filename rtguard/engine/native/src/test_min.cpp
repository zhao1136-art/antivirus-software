#include <windows.h>
#include <cstdlib>

extern "C" __declspec(dllexport) char* test_hello() {
    const char* msg = "{\"status\":\"ok\"}";
    char* buf = (char*)malloc(strlen(msg) + 1);
    strcpy(buf, msg);
    return buf;
}

extern "C" __declspec(dllexport) void test_free(char* ptr) {
    free(ptr);
}
