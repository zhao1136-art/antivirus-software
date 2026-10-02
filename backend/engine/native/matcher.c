/*
 * matcher.c —— Aho-Corasick 多模式匹配器（御天实时防护）
 *
 * 为什么需要它
 * ------------
 * 老实现（御天精简版 engine/yara_scanner.py）是纯 Python 的 YARA 复刻：
 * 每个文件要把缓冲区遍历「模式数」次（实测 166 条规则 / 2172 个模式，
 * 每扫 1 MB 相当于遍历 883 MB 数据），吞吐只有约 1 MB/s，
 * scan.log 里一个 22.5 MB 文件耗时 141.8 秒。
 *
 * 本模块用 Aho-Corasick 自动机把「全部模式一次遍历」做完：
 * 扫描开销只与数据长度有关，与模式数量无关，实测 GB/s 级。
 *
 * 编译（MinGW-w64 gcc，无需 make/configure）：
 *     gcc -O2 -shared -o matcher.dll matcher.c
 *
 * 调用约定：C 默认 __cdecl，Python 侧用 ctypes.CDLL 加载。
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define AC_ALPHABET 256
#define AC_NO_EDGE  (-1)

/* 前置声明：ac_build 内部失败路径需要释放 */
void ac_free(void *handle);

typedef struct {
    int32_t *trans;      /* node_cap * 256，完整 DFA 转移表，-1 表示无 */
    int32_t *fail;       /* 失配指针 */
    int32_t *out_head;   /* 每个节点的输出链表头（模式 id，-1 结束） */
    int32_t *out_next;   /* 输出链表 next */
    int32_t *out_pat;    /* 输出链表 pattern id */

    int32_t node_count;
    int32_t node_cap;

    int32_t out_count;
    int32_t out_cap;

    int32_t pattern_count;
    int32_t total_bytes;

    uint8_t *matched;    /* 扫描用去重位图，长度 pattern_count */
} ac_t;

static int ac_reserve_nodes(ac_t *ac, int32_t need) {
    int32_t cap = ac->node_cap ? ac->node_cap : 1024;
    while (cap < need) cap *= 2;
    if (cap == ac->node_cap) return 1;

    int32_t *nt = (int32_t *)realloc(ac->trans, (size_t)cap * AC_ALPHABET * sizeof(int32_t));
    if (!nt) return 0;
    ac->trans = nt;

    int32_t *nf = (int32_t *)realloc(ac->fail, (size_t)cap * sizeof(int32_t));
    if (!nf) return 0;
    ac->fail = nf;

    int32_t *nh = (int32_t *)realloc(ac->out_head, (size_t)cap * sizeof(int32_t));
    if (!nh) return 0;
    ac->out_head = nh;

    /* trans 新增部分填 AC_NO_EDGE，旧部分保持；fail/out_head 逐节点初始化 */
    for (int32_t n = ac->node_cap; n < cap; n++) {
        int32_t *row = ac->trans + (size_t)n * AC_ALPHABET;
        for (int i = 0; i < AC_ALPHABET; i++) row[i] = AC_NO_EDGE;
        ac->fail[n] = 0;
        ac->out_head[n] = AC_NO_EDGE;
    }
    ac->node_cap = cap;
    return 1;
}

static int ac_add_output(ac_t *ac, int32_t node, int32_t pattern_id) {
    if (ac->out_count >= ac->out_cap) {
        int32_t cap = ac->out_cap ? ac->out_cap * 2 : 4096;
        int32_t *np = (int32_t *)realloc(ac->out_pat, (size_t)cap * sizeof(int32_t));
        if (!np) return 0;
        ac->out_pat = np;
        int32_t *nn = (int32_t *)realloc(ac->out_next, (size_t)cap * sizeof(int32_t));
        if (!nn) return 0;
        ac->out_next = nn;
        ac->out_cap = cap;
    }
    int32_t idx = ac->out_count++;
    ac->out_pat[idx] = pattern_id;
    ac->out_next[idx] = ac->out_head[node];
    ac->out_head[node] = idx;
    return 1;
}

/*
 * 构建自动机。
 *   blob      全部模式字节首尾相接
 *   offsets   每个模式在 blob 中的起始偏移
 *   lengths   每个模式长度（必须 > 0）
 *   count     模式数量
 * 成功返回句柄，失败返回 NULL（内存不足 / 参数非法 / 节点数超上限）。
 */
void *ac_build(const unsigned char *blob, const int32_t *offsets,
               const int32_t *lengths, int32_t count) {
    if (!offsets || !lengths || count <= 0 || count > 1000000) return NULL;

    ac_t *ac = (ac_t *)calloc(1, sizeof(ac_t));
    if (!ac) return NULL;
    ac->pattern_count = count;

    if (!ac_reserve_nodes(ac, 1)) { ac_free(ac); return NULL; }
    ac->node_count = 1; /* 根节点 = 0 */

    int64_t total = 0;
    for (int32_t p = 0; p < count; p++) {
        int32_t len = lengths[p];
        if (len <= 0 || len > (1 << 20)) { ac_free(ac); return NULL; }
        /* 节点数上界保护：每模式最多新增 len 个节点。超过 40 万节点就放弃，
           交给调用方的纯 Python 回退路径，避免把内存吃光。 */
        if ((int64_t)ac->node_count + len > 400000) { ac_free(ac); return NULL; }
        if (!ac_reserve_nodes(ac, ac->node_count + len + 1)) { ac_free(ac); return NULL; }

        int32_t node = 0;
        const unsigned char *pat = blob + offsets[p];
        for (int32_t i = 0; i < len; i++) {
            int32_t c = pat[i];
            int32_t nxt = ac->trans[(size_t)node * AC_ALPHABET + c];
            if (nxt == AC_NO_EDGE) {
                nxt = ac->node_count++;
                ac->trans[(size_t)node * AC_ALPHABET + c] = nxt;
            }
            node = nxt;
        }
        if (!ac_add_output(ac, node, p)) { ac_free(ac); return NULL; }
        total += len;
    }
    ac->total_bytes = (int32_t)(total > INT32_MAX ? INT32_MAX : total);

    /* ── BFS 求 fail，并把转移表补全成完整 DFA ── */
    int32_t *queue = (int32_t *)malloc((size_t)ac->node_count * sizeof(int32_t));
    if (!queue) { ac_free(ac); return NULL; }
    int32_t head = 0, tail = 0;

    int32_t *root = ac->trans; /* 根节点行 */
    for (int c = 0; c < AC_ALPHABET; c++) {
        int32_t nxt = root[c];
        if (nxt == AC_NO_EDGE) {
            root[c] = 0; /* 根的缺失转移指回根 */
        } else {
            ac->fail[nxt] = 0;
            queue[tail++] = nxt;
        }
    }

    while (head < tail) {
        int32_t node = queue[head++];
        int32_t *row = ac->trans + (size_t)node * AC_ALPHABET;
        int32_t f = ac->fail[node];

        /* 输出合并：命中本节点即等于同时命中 fail 链上的全部输出 */
        for (int32_t e = ac->out_head[f]; e != AC_NO_EDGE; e = ac->out_next[e]) {
            if (!ac_add_output(ac, node, ac->out_pat[e])) {
                free(queue); ac_free(ac); return NULL;
            }
        }

        for (int c = 0; c < AC_ALPHABET; c++) {
            int32_t nxt = row[c];
            if (nxt == AC_NO_EDGE) {
                row[c] = ac->trans[(size_t)f * AC_ALPHABET + c]; /* 补全 DFA */
            } else {
                ac->fail[nxt] = ac->trans[(size_t)f * AC_ALPHABET + c];
                queue[tail++] = nxt;
            }
        }
    }
    free(queue);

    ac->matched = (uint8_t *)calloc((size_t)count, 1);
    if (!ac->matched) { ac_free(ac); return NULL; }
    return ac;
}

/*
 * 扫描。命中的模式 id 写入 out_ids（每个 id 只写一次），返回写入数量。
 * 找齐全部模式即提前返回。out_ids 容量不足时只写前 max_ids 个。
 */
int32_t ac_scan(void *handle, const unsigned char *data, size_t len,
                int32_t *out_ids, int32_t max_ids) {
    ac_t *ac = (ac_t *)handle;
    if (!ac || !data || !out_ids || max_ids <= 0) return 0;
    if (len == 0) return 0;

    memset(ac->matched, 0, (size_t)ac->pattern_count);

    int32_t found = 0;
    int32_t node = 0;
    int32_t *trans = ac->trans;

    for (size_t i = 0; i < len; i++) {
        node = trans[(size_t)node * AC_ALPHABET + data[i]];
        int32_t e = ac->out_head[node];
        if (e == AC_NO_EDGE) continue;
        for (; e != AC_NO_EDGE; e = ac->out_next[e]) {
            int32_t pid = ac->out_pat[e];
            if (ac->matched[pid]) continue;
            ac->matched[pid] = 1;
            if (found < max_ids) out_ids[found] = pid;
            found++;
            if (found >= ac->pattern_count) return found < max_ids ? found : max_ids;
        }
    }
    return found < max_ids ? found : max_ids;
}

void ac_free(void *handle) {
    ac_t *ac = (ac_t *)handle;
    if (!ac) return;
    free(ac->trans);
    free(ac->fail);
    free(ac->out_head);
    free(ac->out_next);
    free(ac->out_pat);
    free(ac->matched);
    free(ac);
}

int32_t ac_pattern_count(void *handle) {
    ac_t *ac = (ac_t *)handle;
    return ac ? ac->pattern_count : 0;
}

int32_t ac_node_count(void *handle) {
    ac_t *ac = (ac_t *)handle;
    return ac ? ac->node_count : 0;
}

int32_t ac_total_bytes(void *handle) {
    ac_t *ac = (ac_t *)handle;
    return ac ? ac->total_bytes : 0;
}

const char *ac_version(void) {
    return "rtguard-matcher/1.0 (aho-corasick, complete DFA)";
}
