import os, sys, shutil, subprocess, time
sys.stdout.reconfigure(encoding='ascii', errors='replace')
def p(*a): print(*a, flush=True)

WORK = r'H:\Caelire\backend\_tmp\build'
Y = os.path.join(WORK, 'yara')
L  = os.path.join(Y, 'libyara')
OBJ = os.path.join(WORK, 'obj')
PCRE    = r'H:\Caelire\backend\_tmp\pcre2\x\mingw64'
OPENSSL = r'H:\Caelire\backend\_tmp\openssl\x\mingw64'
MINGW   = r'F:\winlibs_mingw-16.1.0posix-14.0.0-ucrt-r3\mingw64'
GCC     = os.path.join(MINGW, 'bin', 'gcc.exe')

REL = [
 'ahocorasick.c','arena.c','atoms.c','base64.c','bitmask.c','compiler.c','exec.c',
 'exefiles.c','filemap.c','grammar.c','hash.c','hex_grammar.c','hex_lexer.c','lexer.c',
 'libyara.c','mem.c','modules.c',
 r'modules\console\console.c', r'modules\dex\dex.c', r'modules\dotnet\dotnet.c',
 r'modules\elf\elf.c', r'modules\hash\hash.c', r'modules\math\math.c',
 r'modules\macho\macho.c', r'modules\pe\pe.c',
 r'modules\pe\authenticode-parser\authenticode.c',
 r'modules\pe\authenticode-parser\helper.c',
 r'modules\pe\authenticode-parser\countersignature.c',
 r'modules\pe\authenticode-parser\structs.c',
 r'modules\pe\authenticode-parser\certificate.c',
 r'modules\pe\pe_utils.c', r'modules\string\string.c', r'modules\tests\tests.c',
 r'modules\time\time.c','notebook.c','object.c','parser.c','proc.c', r'proc\windows.c',
 're.c','re_grammar.c','re_lexer.c','rules.c','scan.c','scanner.c','sizedstr.c','stack.c',
 'stopwatch.c','stream.c','strutils.c','threading.c','simple_str.c',
 r'tlshc\tlsh_util.c', r'tlshc\tlsh_impl.c', r'tlshc\tlsh.c',
]
DEFINES = ['YR_BUILDING_DLL','USE_WINDOWS_PROC','HASH_MODULE','DOTNET_MODULE',
           'HAVE_LIBCRYPTO','HAVE_STDBOOL_H=1','HAVE__MKGMTIME=1',
           'BUCKETS_128','CHECKSUM_1B','_CRT_SECURE_NO_WARNINGS']
INCLUDES = [os.path.join(L,'include'), L, Y,
            os.path.join(PCRE,'include'), os.path.join(OPENSSL,'include')]

env = dict(os.environ)
env['PATH'] = os.path.join(MINGW, 'bin') + os.pathsep + env.get('PATH', '')
CFLAGS = [f'-D{d}' for d in DEFINES] + [f'-I{i}' for i in INCLUDES] + ['-O2']

os.makedirs(OBJ, exist_ok=True)

# ---------- 0) msvcrt 符号垫片 ----------
SHIM_SRC = r'H:\Caelire\backend\_tmp\shim_msvcrt.c'
SHIM_OBJ = os.path.join(OBJ, 'shim_msvcrt.o')
r = subprocess.run([GCC, '-c', '-O2', '-o', SHIM_OBJ, SHIM_SRC],
                   capture_output=True, text=True, errors='replace', env=env)
if r.returncode != 0:
    p('垫片编译失败:')
    for l in r.stderr.splitlines()[:20]:
        p('   ' + l)
    sys.exit(1)
p('msvcrt 符号垫片已编译')

# ---------- 1) 编译（带缓存）----------
objs = []
newly = 0
t0 = time.time()
for rel in REL:
    src = os.path.join(L, rel)
    obj = os.path.join(OBJ, rel.replace('\\', '_').replace('/', '_') + '.o')
    objs.append(obj)
    up_to_date = (os.path.exists(obj) and os.path.getmtime(obj) >= os.path.getmtime(src))
    if up_to_date:
        continue
    r = subprocess.run([GCC, '-c'] + CFLAGS + ['-o', obj, src],
                       capture_output=True, text=True, errors='replace', env=env)
    if r.returncode != 0:
        p(f'编译失败: {rel}')
        for l in r.stderr.splitlines()[:20]:
            p('   ' + l)
        sys.exit(1)
    newly += 1
p(f'编译阶段: {newly} 个新目标文件（其余 {len(REL)-newly} 个命中缓存），{time.time()-t0:.1f}s')

# ---------- 2) 链接 ----------
STATIC_LIBS = [os.path.join(OPENSSL,'lib','libssl.a'),
               os.path.join(OPENSSL,'lib','libcrypto.a'),
               os.path.join(PCRE,'lib','libpcre2-8.a')]
SYSLIBS = ['-lws2_32','-lcrypt32','-lbcrypt','-ladvapi32','-luser32','-lgdi32',
           '-lole32','-lshell32','-lshlwapi','-lpsapi','-lz',
           '-lmsvcrt']                        # <- 关键：补 msvcrt 的 __imp__vsnprintf
OUT = os.path.join(WORK, 'libyara.dll')
cmd = [GCC, '-shared', '-o', OUT] + objs + [SHIM_OBJ] + STATIC_LIBS + SYSLIBS + \
      ['-static-libgcc', '-static-libstdc++', '-Wl,-Bstatic', '-lwinpthread', '-Wl,-Bdynamic']

p()
p('链接中...')
t0 = time.time()
r = subprocess.run(cmd, capture_output=True, text=True, errors='replace', env=env)
p(f'退出码 {r.returncode}  {time.time()-t0:.1f}s')
if r.returncode != 0:
    err = (r.stderr or '')
    lines = err.splitlines()
    p(f'--- 完整 stderr（{len(lines)} 行）---')
    for l in lines[:60]:
        p('   ' + l)
    if len(lines) > 60:
        p(f'   ...（还有 {len(lines)-60} 行）')
else:
    p(f'*** 生成 {OUT}  {os.path.getsize(OUT):,} 字节 ***')
