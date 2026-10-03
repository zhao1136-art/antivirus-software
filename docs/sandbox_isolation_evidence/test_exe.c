/* Harmless sandbox test target: prints one line, sleeps ~3s, exits 0. */
#include <stdio.h>
#include <windows.h>

int main(void) {
    printf("caelire-sandbox-test-exe: hello\n");
    fflush(stdout);
    Sleep(3000);
    printf("caelire-sandbox-test-exe: bye\n");
    fflush(stdout);
    return 0;
}
