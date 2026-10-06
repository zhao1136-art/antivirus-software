# libyara.dll 构建说明（可复现）

项目原来的 YARA 引擎是 `engine/yara_scanner.py` —— 一个**从零手写的 YARA 子集**（904 行，不依赖 libyara）。
它把 condition 压缩成「类型 + N」的粗模型，导致大量语义偏差。本目录提供**真正的 libyara**。

## 产物

| 文件 | 说明 |
|---|---|
| `libyara.dll` | **6,584 KB**，YARA **4.5.5**，x64，**完全自包含** |
| `shim_msvcrt.c` | 链接期符号垫片（见「坑 4」） |
| `build_libyara.py` | 一键重建脚本 |
| `smoke_test.py` | ctypes 功能验证（7 个语义用例） |

**运行时依赖**：只有 Windows 自带的 `KERNEL32 / ADVAPI32 / CRYPT32 / USER32 / WS2_32`
和 UCRT 的 `api-ms-win-crt-*`。**没有** `libcrypto-3-x64.dll`、`libssl-3-x64.dll`、
`libpcre2-8-0.dll` —— PCRE2 与 OpenSSL 都是**静态链进去**的，打包时只需带这一个 DLL。

**导出**：93 个 `yr_*` 函数，含 `yr_initialize` / `yr_compiler_*` / `yr_scanner_scan_mem` /
`yr_scanner_scan_file` / `yr_scanner_scan_proc` / `yr_rules_save` / `yr_rules_load` 等全套 API。

## 为什么必须自己编

预编译的 `libyara` **四条路全部走死**：

| 来源 | 结果 |
|---|---|
| `yara-python` (pip) | ❌ 无 cp314 wheel（只到 cp313，无 abi3）；sdist 需 MSVC |
| YARA 官方 Windows release | ❌ 只有 `yara64.exe`/`yarac64.exe`，**静态链接，不含 DLL** |
| MSYS2 (`mingw64`/`ucrt64`/`clang64`) | ❌ 无 yara 包 |
| conda-forge | ❌ 无 yara 包 |

## 构建配方

### 依赖获取

| 依赖 | 来源 | 用途 |
|---|---|---|
| YARA 4.5.5 源码 | `https://api.github.com/repos/VirusTotal/yara/tarball/v4.5.5` | 源码树（已含生成的 lexer/parser，**不需要 flex/bison**） |
| PCRE2 10.47 (MinGW) | MSYS2 `mingw-w64-x86_64-pcre2-10.47-1-any.pkg.tar.zst` | 正则引擎（静态库 `libpcre2-8.a`） |
| OpenSSL 3.5.0 (MinGW) | MSYS2 `mingw-w64-x86_64-openssl-3.5.0-1-any.pkg.tar.zst` | hash 模块 + pe 的 authenticode（静态库 `libcrypto.a`/`libssl.a`） |
| 编译器 | `F:\winlibs_mingw-16.1.0posix-14.0.0-ucrt-r3\mingw64` | GCC 16.1.0 |

MSYS2 包是 `.pkg.tar.zst`，Windows 自带 `tar` **要外部 `zstd` 程序、会失败**；
用带 `zstandard` 模块的 Python 解（`zstandard` + `tarfile`）。

### 编译宏（取自 `windows/vs2019/libyara/libyara.vcxproj`）

```
YR_BUILDING_DLL      <- 决定 YR_API 为 __attribute__((dllexport))
USE_WINDOWS_PROC     <- 支持扫描进程内存（御天的 memory_scanner 要用）
HASH_MODULE
DOTNET_MODULE        <- 你的规则里有 26 处 dotnet.*
HAVE_LIBCRYPTO
HAVE_STDBOOL_H=1
HAVE__MKGMTIME=1
BUCKETS_128 / CHECKSUM_1B   <- TLSH 参数
_CRT_SECURE_NO_WARNINGS
```

**故意不定义**：`CUCKOO_MODULE`（需 jansson）、`MAGIC_MODULE`（需 libmagic）、
`HAVE_WINCRYPT_H`（既然用了 OpenSSL）、`HAVE_STRLCPY/STRLCAT/MEMMEM/TIMEGM/CLOCK_GETTIME`
—— `libyara/strutils.c` 在未定义时会启用自带回退实现。

`libyara/modules/module_list` **不要改**：`MODULE(cuckoo)` 本来就被 `#ifdef CUCKOO_MODULE`
包着，不定义宏即可；手改会把 `#if/#endif` 弄不平衡。只需**不编译** `modules/cuckoo/cuckoo.c`。

### 源文件

按 vcxproj 的清单取 **55 个 `.c`**（56 减去 cuckoo）。**只编 `proc/windows.c`**，
不要 `proc/freebsd.c`/`linux.c`/`mach.c`；不要 `modules/demo`、`modules/magic`、`modules/pb_tests`。

### 链接

静态库按**全路径**传入（顺序 `libssl.a` → `libcrypto.a` → `libpcre2-8.a`），
再补系统导入库 `-lws2_32 -lcrypt32 -lbcrypt -ladvapi32 -luser32 -lgdi32 -lole32 -lshell32 -lshlwapi -lpsapi -lz -lmsvcrt`，
加 `-static-libgcc -static-libstdc++ -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic`。

## 踩过的四个坑

**坑 1 —— g++ 必须在其 `bin` 在 `PATH` 时才能编译。**
否则 `cc1plus`/`as`/`ld` 起不来，表现是 **exit 1 且零输出**，完全看不出原因。

**坑 2 —— 官方 release 里没有 DLL。** 见上表。只能走源码构建。

**坑 3 —— `github.com` 不可达，但 `api.github.com` 可达。**
所以下载 release 附件要用 API 的 asset 端点：
```
curl -L -H "Accept: application/octet-stream" \
  https://api.github.com/repos/VirusTotal/yara/releases/assets/<asset_id>
```
（普通 `https://github.com/.../releases/download/...` 会静默下到 0 字节。）

**坑 4 —— `undefined reference to __imp__vsnprintf`。**
MSYS2 的 OpenSSL 静态库是按 **msvcrt** 目标编译的，引用了 `__imp__vsnprintf`；
而 winlibs 的 MinGW 是 **UCRT** 目标，其 `libmsvcrt.a` 只提供 `__imp_vsnprintf`（少一个下划线）。
解法：`shim_msvcrt.c` 直接定义该符号指向 UCRT 的 `vsnprintf()`。

## 验证

`python smoke_test.py` —— 用 ctypes 加载本 DLL，跑 7 个语义用例：

| 用例 | 结果 |
|---|---|
| `"EvilMarker" nocase` 对全小写输入 | ✅ 命中 |
| `"cat" fullword` 对 `concatenate` | ✅ 不命中 |
| `#a > 3` 但只出现 1 次 | ✅ 不命中 |
| `"SecretKey" xor`（XOR 0x41 后） | ✅ 命中 |
| `{ DE AD [4-6] BE EF }` | ✅ 命中 |
| `/ab+c/` 对 `abbbc` | ✅ 命中 |
| 纯 `filesize > 100` 对 200 字节 | ✅ 命中 |

**7/7 全部符合真 YARA 语义。** 对照：旧的 `yara_scanner.py` 在这 7 项里有 **5 项错**。

## 重新构建

```powershell
F:\Python314\python.exe build_libyara.py
```
脚本带**目标文件缓存**（首次约 155 s，之后只重链接约 8 s）。
路径常量在脚本顶部，换机器时改那几个即可。
