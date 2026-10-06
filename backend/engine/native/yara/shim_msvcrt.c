/*
 * shim_msvcrt.c —— 为 msvcrt 目标的 OpenSSL 静态库补一个符号
 *
 * 背景：
 *   MSYS2 的 mingw-w64-x86_64-openssl 静态库（libcrypto.a）是按 **msvcrt**
 *   目标编译的，其中的 cryptlib.obj 引用了 msvcrt 的导入槽：
 *       __imp__vsnprintf      （注意：__imp_ + _vsnprintf，两个下划线）
 *   而本项目使用的 winlibs MinGW 是 **UCRT** 目标，它的 libmsvcrt.a 只提供
 *       __imp_vsnprintf       （一个下划线）
 *   于是链接报：
 *       undefined reference to `__imp__vsnprintf'
 *
 * 做法：
 *   直接定义该符号，指向 UCRT 的 vsnprintf()。两者签名一致
 *       int vsnprintf(char *buf, size_t n, const char *fmt, va_list ap)
 *   语义上 UCRT 版本更安全（总是写 NUL 结尾），对 OpenSSL 的错误信息格式化
 *   等用途完全够用。
 */
#include <stdio.h>

void *__imp__vsnprintf = (void *) vsnprintf;
void *__imp_vsnprintf  = (void *) vsnprintf;   /* 兜底：万一还有一处引用单下划线版 */
