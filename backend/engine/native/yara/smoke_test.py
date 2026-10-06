import ctypes, sys, os, io
sys.stdout.reconfigure(encoding='ascii', errors='replace')
def p(*a): print(*a, flush=True)

DLL = r'H:\Caelire\backend\_tmp\build\libyara.dll'
lib = ctypes.CDLL(DLL)

c_void_p, c_int, c_char_p, c_size_t, c_uint8_p = (
    ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8))

lib.yr_initialize.restype = c_int
lib.yr_compiler_create.argtypes = [ctypes.POINTER(c_void_p)]
lib.yr_compiler_create.restype = c_int
lib.yr_compiler_add_string.argtypes = [c_void_p, c_char_p, c_char_p]
lib.yr_compiler_add_string.restype = c_int
lib.yr_compiler_get_rules.argtypes = [c_void_p, ctypes.POINTER(c_void_p)]
lib.yr_compiler_get_rules.restype = c_int
lib.yr_rules_scan_mem.argtypes = [c_void_p, c_uint8_p, c_size_t, c_int,
                                  c_void_p, c_void_p, c_int]
lib.yr_rules_scan_mem.restype = c_int
lib.yr_rules_destroy.argtypes = [c_void_p]
lib.yr_compiler_destroy.argtypes = [c_void_p]
lib.yr_finalize.restype = c_int

CALLBACK = ctypes.CFUNCTYPE(c_int, c_void_p, c_int, c_void_p, c_void_p)
YR_RULE_IDENTIFIER_OFFSET = 16          # flags, num_atoms, required_strings, unused

err = lib.yr_initialize()
p(f'yr_initialize -> {err}')
if err != 0:
    sys.exit(1)

RULES = b'''
rule demo_nocase
{
    strings:
        $a = "EvilMarker" nocase
    condition:
        $a
}

rule demo_fullword
{
    strings:
        $a = "cat" fullword
    condition:
        $a
}

rule demo_count
{
    strings:
        $a = "HIT"
    condition:
        #a > 3
}

rule demo_xor
{
    strings:
        $a = "SecretKey" xor
    condition:
        $a
}

rule demo_hexjump
{
    strings:
        $a = { DE AD [4-6] BE EF }
    condition:
        $a
}

rule demo_regex
{
    strings:
        $a = /ab+c/
    condition:
        $a
}

rule demo_fsonly
{
    condition:
        filesize > 100
}
'''

lib.yr_compiler_get_error_message.argtypes = [c_void_p, c_char_p, c_int]
lib.yr_compiler_get_error_message.restype = c_int

compiler = c_void_p()
p(f'yr_compiler_create -> {lib.yr_compiler_create(ctypes.byref(compiler))}')
nerr = lib.yr_compiler_add_string(compiler, RULES, b'default')
p(f'yr_compiler_add_string -> 错误数 {nerr}')
if nerr:
    buf = ctypes.create_string_buffer(4096)
    lib.yr_compiler_get_error_message(compiler, buf, 4096)
    p('编译器错误信息:')
    for l in buf.value.decode('utf-8', 'replace').splitlines():
        p('   ' + l)
    sys.exit(1)
rules = c_void_p()
p(f'yr_compiler_get_rules -> {lib.yr_compiler_get_rules(compiler, ctypes.byref(rules))}')

def scan(data: bytes):
    hits = []
    def _cb(ctx, message, mdata, user):
        if message == 1 and mdata:      # CALLBACK_MSG_RULE_MATCHING
            name = ctypes.cast(mdata + YR_RULE_IDENTIFIER_OFFSET,
                               ctypes.POINTER(c_char_p)).contents.value
            if name:
                hits.append(name.decode())
        return 0
    cb = CALLBACK(_cb)
    buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    lib.yr_rules_scan_mem(rules, buf, len(data), 0, cb, None, 0)
    return hits

CASES = [
    ('nocase  输入全小写 evilmarker', b'...evilmarker...', ['demo_nocase']),
    ('fullword 输入 concatenate',     b'this is concatenate text', []),
    ('count   只 1 次 HIT (#a>3)',    b'only one HIT here', []),
    ('xor     仅 XOR(0x41) 后出现',   b'pad' + bytes(b ^ 0x41 for b in b'SecretKey') + b'pad', ['demo_xor']),
    ('hexjump DE AD +4B+ BE EF',      b'\xde\xad\x01\x02\x03\x04\xbe\xef', ['demo_hexjump']),
    ('regex   /ab+c/ 输入 abbbc',     b'xxabbbcxx', ['demo_regex']),
    ('fsonly  filesize>100 200字节',  b'z' * 200, ['demo_fsonly']),
]

p()
p('==================== 用真 libyara 重跑之前的用例 ====================')
allok = True
for label, data, expect in CASES:
    got = scan(data)
    ok = (got == expect)
    allok &= ok
    p(f'{"PASS" if ok else "FAIL"}  {label}')
    p(f'        期望={expect or "(无)"}   实际={got or "(无)"}')

p()
p('==================== 结论 ====================')
p(f'  全部 {len(CASES)} 个用例: {"全部符合真 YARA 语义 ✅" if allok else "有不符合 ❌"}')

lib.yr_rules_destroy(rules)
lib.yr_compiler_destroy(compiler)
lib.yr_finalize()
