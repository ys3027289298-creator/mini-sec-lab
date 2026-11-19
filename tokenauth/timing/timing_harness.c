/*
 * timing_harness.c - 针对 src/tokenauth.c 中 ct_equal() 的时序测量驱动。
 *
 * 直接 #include 生产源码本体（与 tokenauth/Makefile 编译的是同一个文件），
 * 通过宏把生产代码里的 main() 改名，避免与本驱动的 main() 冲突。
 *
 * 测量方法：
 *   - rdtsc/rdtscp + cpuid 序列化，取 invariant TSC 周期数
 *   - ct_equal 通过 volatile 函数指针调用，保证生成独立 call、不被内联
 *   - 65 个组：正确前缀长度 k = 0..64，每组 ROUNDS 次（默认 1000）
 *   - 每轮用固定种子的 Fisher-Yates 洗牌决定各组顺序，交错采样抵消漂移
 *   - 另测 noop 基线（同样经 volatile 指针调用）与端到端 verify() 路径
 *
 * 输出：CSV 到 stdout（mode,round,order,k,cycles），环境信息到 stderr。
 */
#define _GNU_SOURCE

#define main tokenauth_production_main_unused
#include "../src/tokenauth.c"
#undef main

#include <stdint.h>
#include <sched.h>
#include <errno.h>
#include <string.h>

#define SIG_LEN 64
#define N_GROUPS (SIG_LEN + 1) /* k = 0..64 */
#define DEFAULT_ROUNDS 1000
#define WARMUP_CALLS 10000

typedef int (*ct_equal_fn_t)(const unsigned char *, const unsigned char *, size_t);

/* volatile 指针：每次调用都从内存重新加载，编译器无法内联 */
static volatile ct_equal_fn_t g_ct_equal = ct_equal;

/*
 * 正对照：故意写成逐字节提前返回的脆弱实现。
 * 用于验证测量/分析管线确实能检出长度泄露（预期 k 与耗时强正相关）。
 * 编译器同样无法经 volatile 指针内联它，提前返回分支得以保留。
 */
static int vuln_equal(const unsigned char *a, const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}
static volatile ct_equal_fn_t g_vuln = vuln_equal;

static int noop_equal(const unsigned char *a, const unsigned char *b, size_t n) {
    (void)a; (void)b; (void)n;
    return 0;
}
static volatile ct_equal_fn_t g_noop = noop_equal;

static volatile int g_sink;

/* ---- 序列化 TSC 计时 ---- */

static inline uint64_t tsc_begin(void) {
    unsigned lo, hi;
    __asm__ volatile ("cpuid" : : : "%rax", "%rbx", "%rcx", "%rdx");
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t tsc_end(void) {
    unsigned lo, hi;
    __asm__ volatile ("rdtscp" : "=a"(lo), "=d"(hi) : : "%rcx");
    __asm__ volatile ("cpuid" : : : "%rax", "%rbx", "%rcx", "%rdx");
    return ((uint64_t)hi << 32) | lo;
}

/* ---- 固定种子 xorshift64 + Fisher-Yates，保证顺序可复现 ---- */

static uint64_t rng_state;

static uint64_t xorshift64(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static void shuffle(int *idx, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = (int)(xorshift64() % (uint64_t)(i + 1));
        int t = idx[i];
        idx[i] = idx[j];
        idx[j] = t;
    }
}

static void pin_cpu(void) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) == 0) {
        fprintf(stderr, "affinity=pinned-to-cpu0\n");
    } else {
        fprintf(stderr, "affinity=FAILED(%s)\n", strerror(errno));
    }
}

/* 直接测某个比较函数：所有组固定 n=64，仅前 k 字节相同 */
static void run_compare(const char *mode, ct_equal_fn_t fn, int rounds) {
    static unsigned char want[SIG_LEN];
    static unsigned char got[SIG_LEN];
    memset(want, 'a', sizeof(want));

    int order[N_GROUPS];
    for (int i = 0; i < N_GROUPS; i++) order[i] = i;

    /* 预热：覆盖全部组，摊冷启动/缓存影响 */
    for (int w = 0; w < WARMUP_CALLS; w++) {
        int k = w % N_GROUPS;
        for (int i = 0; i < SIG_LEN; i++)
            got[i] = (i < k) ? 'a' : 'x';
        g_sink += fn(want, got, SIG_LEN);
    }

    for (int r = 0; r < rounds; r++) {
        shuffle(order, N_GROUPS);
        for (int pos = 0; pos < N_GROUPS; pos++) {
            int k = order[pos];
            for (int i = 0; i < SIG_LEN; i++)
                got[i] = (i < k) ? 'a' : 'x';

            uint64_t t0 = tsc_begin();
            int res = fn(want, got, SIG_LEN);
            uint64_t t1 = tsc_end();

            g_sink += res;
            printf("%s,%d,%d,%d,%llu\n", mode, r, pos, k,
                   (unsigned long long)(t1 - t0));
        }
    }
}

static void run_ct_equal(int rounds) {
    run_compare("ct_equal", (ct_equal_fn_t)g_ct_equal, rounds);
}

/* 正对照：脆弱的提前返回实现，预期随 k 单调变慢 */
static void run_vuln(int rounds) {
    run_compare("vuln", (ct_equal_fn_t)g_vuln, rounds);
}

/* 测量方法学基线：同样经 volatile 指针调用的空函数 */
static void run_noop(int rounds) {
    static unsigned char want[SIG_LEN], got[SIG_LEN];
    memset(want, 'a', sizeof(want));
    memset(got, 'x', sizeof(got));

    for (int w = 0; w < WARMUP_CALLS; w++)
        g_sink += ((ct_equal_fn_t)g_noop)(want, got, SIG_LEN);

    for (int r = 0; r < rounds; r++) {
        uint64_t t0 = tsc_begin();
        int res = ((ct_equal_fn_t)g_noop)(want, got, SIG_LEN);
        uint64_t t1 = tsc_end();
        g_sink += res;
        printf("noop,%d,0,-1,%llu\n", r, (unsigned long long)(t1 - t0));
    }
}

/*
 * 端到端测 verify()：构造真实 HMAC token，仅改签名段前 k 字节之后的字符。
 * k < 64 全部走 BAD_SIG（同一条代码路径，不触碰 replay 逻辑）；
 * k = 64 为完整合法 token，每轮换新 nonce 防止 replay 分支污染。
 */
static void run_verify(int rounds) {
    Auth a;
    const unsigned char key[] = "0123456789abcdef0123456789abcdef";
    auth_init(&a, key, 32, 300, 5);
    const long now = 1000;

    int order[N_GROUPS];
    for (int i = 0; i < N_GROUPS; i++) order[i] = i;

    for (int r = 0; r < rounds; r++) {
        shuffle(order, N_GROUPS);
        for (int pos = 0; pos < N_GROUPS; pos++) {
            int k = order[pos];
            char tok[TOKEN_MAX];
            /* k=64 时每轮需要唯一 nonce；其余组在签名校验处即被拒绝 */
            build_token(&a, "u", now, (unsigned long long)r + 1, tok);

            char *sig = strrchr(tok, '.') + 1;
            for (int i = k; i < SIG_LEN; i++)
                sig[i] = (sig[i] == 'a') ? 'b' : 'a';

            uint64_t t0 = tsc_begin();
            AuthErr err = verify(&a, tok, now, NULL);
            uint64_t t1 = tsc_end();

            g_sink += (int)err;
            printf("verify,%d,%d,%d,%llu\n", r, pos, k,
                   (unsigned long long)(t1 - t0));
        }
    }
}

int main(int argc, char **argv) {
    int rounds = DEFAULT_ROUNDS;
    if (argc >= 2)
        rounds = atoi(argv[1]);
    if (rounds <= 0)
        rounds = DEFAULT_ROUNDS;

    rng_state = 0x123456789abcdef0ULL;

    fprintf(stderr, "rounds=%d groups=%d (k=0..%d) seed=0x%llx\n",
            rounds, N_GROUPS, SIG_LEN,
            (unsigned long long)0x123456789abcdef0ULL);
    pin_cpu();
    fprintf(stderr, "sink_init=%d\n", (int)g_sink);

    printf("mode,round,order,k,cycles\n");
    run_noop(rounds);
    run_ct_equal(rounds);
    run_vuln(rounds);
    run_verify(rounds);

    fprintf(stderr, "sink_final=%d\n", (int)g_sink);
    return 0;
}
