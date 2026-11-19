#define _POSIX_C_SOURCE 199309L

/* tokenauth: HMAC-SHA256 bearer tokens with constant-time compare,
   expiry with clock skew, a fixed-capacity nonce replay cache and key
   rotation.

   The replay cache never scans all entries: a fixed-size slot array holds
   the nonces, live slots are threaded in insertion order (oldest first) and
   a fix-sized open-addressed hash table maps nonce -> slot.  Capacity is an
   upper bound, a full cache evicts the oldest nonce, and every operation is
   O(1) with no allocation after init. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define TOKEN_MAX 256
#define KEY_MAX 32
#define NONCE_CACHE_CAP 10000

typedef struct {
    unsigned long long nonce;
    int next; /* live: next-newer slot; free: next free slot; -1 ends list */
} NonceSlot;

typedef struct {
    NonceSlot* slots;   /* NONCE_CACHE_CAP entries, allocated once */
    int* table;         /* open-addressed set of slot indices */
    size_t cap;         /* slot capacity */
    size_t table_cap;   /* power of two, > 2 * cap */
    size_t table_count;
    int head;           /* oldest live slot, -1 when empty */
    int tail;           /* newest live slot, -1 when empty */
    int free_head;      /* first free slot, -1 when full */
    size_t count;
    size_t probe_max;   /* longest probe seen (test observability) */
    unsigned long long salt; /* hashes distinct nonce sequences per process */
} NonceCache;

typedef struct {
    unsigned char keys[2][KEY_MAX];
    size_t key_len[2];
    int key_count;
    long ttl;
    long skew;
    NonceCache cache;
} Auth;

typedef enum {
    AUTH_OK = 0,
    AUTH_MALFORMED,
    AUTH_BAD_SIG,
    AUTH_EXPIRED,
    AUTH_NOT_YET,
    AUTH_REPLAY
} AuthErr;

static const char* auth_name(AuthErr e) {
    switch (e) {
    case AUTH_OK: return "ok";
    case AUTH_MALFORMED: return "malformed";
    case AUTH_BAD_SIG: return "bad_sig";
    case AUTH_EXPIRED: return "expired";
    case AUTH_NOT_YET: return "not_yet";
    case AUTH_REPLAY: return "replay";
    }
    return "?";
}

/* splitmix64 finalizer: nonces are attacker-controlled, so the cache hash
   must not let an attacker pack one probe chain. */
static unsigned long long mix64(unsigned long long x) {
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

/* Per-process salt from the kernel's CSPRNG, mixed with the high-resolution
   clock and mixed with the address of the process state as a last resort.
   The salt keeps nonces that are adjacent (or crafted) from sharing a probe
   chain; fall back loudly only when /dev/urandom is unavailable. */
static unsigned long long salt_from_urandom(void) {
    unsigned long long v = 0;
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(&v, sizeof(v), 1, f) != 1) v = 0;
        fclose(f);
    }
    return v;
}

static unsigned long long cache_make_salt(void) {
    unsigned long long salt = salt_from_urandom();
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        salt ^= (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
        salt = mix64(salt);
    }
    if (salt == 0) {
        static unsigned char anchor;
        fprintf(stderr, "tokenauth: entropy unavailable, replay cache hash unsalted\n");
        salt = mix64((unsigned long long)(uintptr_t)&anchor) | 1;
    }
    return salt;
}

static size_t cache_home(const NonceCache* c, unsigned long long nonce) {
    return (size_t)(mix64(nonce ^ c->salt) & (unsigned long long)(c->table_cap - 1));
}

static void cache_note_probe(NonceCache* c, size_t probes) {
    if (probes > c->probe_max) c->probe_max = probes;
}

/* Find a live nonce, returning its slot index or -1.  Linear probing stops
   at the first empty bucket; the table is never more than half full. */
static int cache_find(NonceCache* c, unsigned long long nonce, size_t* probes) {
    size_t mask = c->table_cap - 1;
    size_t i = cache_home(c, nonce);
    size_t n = 0;
    for (;;) {
        int s = c->table[i];
        n++;
        if (s < 0) {
            cache_note_probe(c, n);
            if (probes) *probes = n;
            return -1;
        }
        if (c->slots[s].nonce == nonce) {
            cache_note_probe(c, n);
            if (probes) *probes = n;
            return s;
        }
        i = (i + 1) & mask;
    }
}

static void table_insert(NonceCache* c, int slot) {
    size_t mask = c->table_cap - 1;
    size_t i = cache_home(c, c->slots[slot].nonce);
    size_t n = 0;
    while (c->table[i] >= 0) {
        i = (i + 1) & mask;
        n++;
    }
    cache_note_probe(c, n + 1);
    c->table[i] = slot;
    c->table_count++;
}

/* Backward-shift deletion keeps probe chains intact without tombstones. */
static void table_remove(NonceCache* c, int slot) {
    size_t mask = c->table_cap - 1;
    size_t i = cache_home(c, c->slots[slot].nonce);
    size_t n = 0;
    while (c->table[i] != slot) {
        i = (i + 1) & mask;
        n++;
    }
    cache_note_probe(c, n + 1);

    size_t j = i;
    for (;;) {
        j = (j + 1) & mask;
        if (c->table[j] < 0) break;
        size_t home = cache_home(c, c->slots[c->table[j]].nonce);
        int movable = (j > i) ? !(home > i && home <= j)
                              : !(home > i || home <= j);
        if (movable) {
            c->table[i] = c->table[j];
            i = j;
        }
    }
    c->table[i] = -1;
    c->table_count--;
}

static int cache_init(NonceCache* c, size_t cap) {
    memset(c, 0, sizeof(*c));
    if (cap == 0) cap = 1;

    size_t table_cap = 1;
    while (table_cap < cap * 2) table_cap <<= 1;

    c->slots = malloc(cap * sizeof(*c->slots));
    c->table = malloc(table_cap * sizeof(*c->table));
    if (!c->slots || !c->table) {
        free(c->slots);
        free(c->table);
        memset(c, 0, sizeof(*c));
        return 0;
    }

    c->cap = cap;
    c->table_cap = table_cap;
    c->salt = cache_make_salt();
    for (size_t i = 0; i < table_cap; i++) c->table[i] = -1;
    for (size_t i = 0; i + 1 < cap; i++) c->slots[i].next = (int)(i + 1);
    c->slots[cap - 1].next = -1;
    c->free_head = 0;
    c->head = -1;
    c->tail = -1;
    return 1;
}

static void cache_free(NonceCache* c) {
    free(c->slots);
    free(c->table);
    memset(c, 0, sizeof(*c));
    c->head = -1;
    c->tail = -1;
    c->free_head = -1;
}

static void cache_evict_oldest(NonceCache* c) {
    int s = c->head;
    table_remove(c, s);
    int newer = c->slots[s].next;
    c->slots[s].next = c->free_head;
    c->free_head = s;
    c->head = newer;
    if (newer < 0) c->tail = -1;
    c->count--;
}

static void cache_insert(NonceCache* c, unsigned long long nonce) {
    if (c->count == c->cap) cache_evict_oldest(c);

    int s = c->free_head;
    c->free_head = c->slots[s].next;
    c->slots[s].nonce = nonce;
    c->slots[s].next = -1;

    if (c->tail >= 0) c->slots[c->tail].next = s;
    else c->head = s;
    c->tail = s;

    table_insert(c, s);
    c->count++;
}

/* Test-and-set: returns 1 if the nonce was already seen (a replay, and the
   FIFO order is left untouched), 0 after recording it. */
static int cache_put(NonceCache* c, unsigned long long nonce) {
    if (cache_find(c, nonce, NULL) >= 0) return 1;
    cache_insert(c, nonce);
    return 0;
}

static int auth_init(Auth* a, const unsigned char* key, size_t klen, long ttl, long skew) {
    memset(a, 0, sizeof(*a));
    if (klen == 0 || klen > KEY_MAX) return 0;
    memcpy(a->keys[0], key, klen);
    a->key_len[0] = klen;
    a->key_count = 1;
    a->ttl = ttl;
    a->skew = skew;
    return cache_init(&a->cache, NONCE_CACHE_CAP);
}

static void auth_free(Auth* a) {
    cache_free(&a->cache);
}

static void auth_rotate(Auth* a, const unsigned char* key, size_t klen) {
    if (klen == 0 || klen > KEY_MAX) return;
    memcpy(a->keys[1], a->keys[0], a->key_len[0]);
    a->key_len[1] = a->key_len[0];
    memcpy(a->keys[0], key, klen);
    a->key_len[0] = klen;
    a->key_count = 2;
}

static int ct_equal(const unsigned char* a, const unsigned char* b, size_t n) {
    unsigned char diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

static void hmac_hex(const unsigned char* key, size_t klen, const char* msg, char* out) {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen = 0;
    HMAC(EVP_sha256(), key, (int)klen, (const unsigned char*)msg, strlen(msg), mac, &maclen);
    for (unsigned int i = 0; i < maclen; i++) sprintf(out + i * 2, "%02x", mac[i]);
    out[maclen * 2] = 0;
}

static int build_token(const Auth* a, const char* uid, long now, unsigned long long nonce, char* out) {
    char body[TOKEN_MAX];
    snprintf(body, sizeof(body), "%s.%ld.%llu", uid, now + a->ttl, nonce);
    char sig[EVP_MAX_MD_SIZE * 2 + 1];
    hmac_hex(a->keys[0], a->key_len[0], body, sig);
    int n = snprintf(out, TOKEN_MAX, "%s.%s", body, sig);
    return n > 0 && n < TOKEN_MAX;
}

static AuthErr verify(Auth* a, const char* token, long now, unsigned long long* nonce_out) {
    char buf[TOKEN_MAX];
    if (strlen(token) >= sizeof(buf)) return AUTH_MALFORMED;
    strcpy(buf, token);

    char* dot = strrchr(buf, '.');
    if (!dot) return AUTH_MALFORMED;
    *dot = 0;
    const char* sig = dot + 1;
    if (strlen(sig) != 64) return AUTH_MALFORMED;

    char exp_s[32], nonce_s[32];
    char* last = strrchr(buf, '.');
    if (!last) return AUTH_MALFORMED;
    *last = 0;
    char* mid = strrchr(buf, '.');
    if (!mid) return AUTH_MALFORMED;
    *mid = 0;
    const char* uid = buf;
    const char* nonce_raw = last + 1;
    const char* exp_raw = mid + 1;
    size_t exp_len = strlen(exp_raw), nonce_len = strlen(nonce_raw);
    /* Refuse over-long fields instead of truncating: the signature covers
       this exact spelling, so silently shortening it would verify a body
       the sender never signed. */
    if (exp_len >= sizeof(exp_s) || nonce_len >= sizeof(nonce_s))
        return AUTH_MALFORMED;
    memcpy(exp_s, exp_raw, exp_len + 1);
    memcpy(nonce_s, nonce_raw, nonce_len + 1);

    char body[TOKEN_MAX];
    int body_len = snprintf(body, sizeof(body), "%s.%s.%s", uid, exp_s, nonce_s);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) return AUTH_MALFORMED;

    char want[EVP_MAX_MD_SIZE * 2 + 1];
    int ok = 0;
    for (int k = 0; k < a->key_count; k++) {
        hmac_hex(a->keys[k], a->key_len[k], body, want);
        if (ct_equal((const unsigned char*)want, (const unsigned char*)sig, 64)) { ok = 1; break; }
    }
    if (!ok) return AUTH_BAD_SIG;

    long exp = strtol(exp_s, NULL, 10);
    unsigned long long nonce = strtoull(nonce_s, NULL, 10);
    if (now > exp + a->skew) return AUTH_EXPIRED;
    if (exp - a->ttl > now + a->skew) return AUTH_NOT_YET;

    if (cache_put(&a->cache, nonce)) return AUTH_REPLAY;

    if (nonce_out) *nonce_out = nonce;
    return AUTH_OK;
}

/* ------------------------------------------------------------------ tests */

static int failures = 0;
static void check(const char* name, int ok) {
    printf("%s=%d\n", name, ok ? 1 : 0);
    if (!ok) failures++;
}

static unsigned long long cpu_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

/* Per-call thresholds are meaningless when the build is instrumented. */
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define TIMING_ASSERTS 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define TIMING_ASSERTS 0
#else
#define TIMING_ASSERTS 1
#endif
#else
#define TIMING_ASSERTS 1
#endif

static int cmp_ull(const void* a, const void* b) {
    unsigned long long x = *(const unsigned long long*)a;
    unsigned long long y = *(const unsigned long long*)b;
    return (x > y) - (x < y);
}

/* Invariants that make the O(1) claim observable: every live slot is in the
   hash table exactly once, every table entry resolves back to its slot, and
   the FIFO chain visits each live slot exactly once. */
static int cache_consistent(NonceCache* c) {
    size_t entries = 0;
    for (size_t i = 0; i < c->table_cap; i++) {
        int s = c->table[i];
        if (s < 0) continue;
        entries++;
        if ((size_t)s >= c->cap) return 0;
        if (cache_find(c, c->slots[s].nonce, NULL) != s) return 0;
    }
    if (entries != c->table_count || entries != c->count) return 0;

    size_t walked = 0;
    for (int s = c->head; s >= 0; s = c->slots[s].next) {
        if ((size_t)s >= c->cap || ++walked > c->cap) return 0;
    }
    return walked == c->count;
}

/* hash-table reference model: separate chaining plus a FIFO list, so it
   shares no code path with the production cache. */
typedef struct RefNode {
    unsigned long long nonce;
    struct RefNode* hnext;
    struct RefNode* older;
    struct RefNode* newer;
} RefNode;

typedef struct {
    RefNode** buckets;
    size_t nbuckets;
    RefNode* oldest;
    RefNode* newest;
    size_t count;
    size_t cap;
} RefCache;

static size_t ref_home(const RefCache* r, unsigned long long nonce) {
    unsigned long long h = (nonce ^ (nonce >> 33)) * 0xc2b2ae3d27d4eb4fULL;
    return (size_t)(h % r->nbuckets);
}

static int ref_init(RefCache* r, size_t cap) {
    memset(r, 0, sizeof(*r));
    r->nbuckets = cap * 2 + 1;
    r->buckets = calloc(r->nbuckets, sizeof(*r->buckets));
    if (!r->buckets) return 0;
    r->cap = cap;
    return 1;
}

static int ref_put(RefCache* r, unsigned long long nonce) {
    size_t b = ref_home(r, nonce);
    for (RefNode* n = r->buckets[b]; n; n = n->hnext)
        if (n->nonce == nonce) return 1;

    if (r->count == r->cap) {
        RefNode* old = r->oldest;
        RefNode** pp = &r->buckets[ref_home(r, old->nonce)];
        while (*pp != old) pp = &(*pp)->hnext;
        *pp = old->hnext;
        r->oldest = old->newer;
        if (r->oldest) r->oldest->older = NULL;
        else r->newest = NULL;
        free(old);
        r->count--;
    }

    RefNode* n = malloc(sizeof(*n));
    if (!n) return 2;
    n->nonce = nonce;
    n->older = r->newest;
    n->newer = NULL;
    n->hnext = r->buckets[b];
    r->buckets[b] = n;
    if (r->newest) r->newest->newer = n;
    else r->oldest = n;
    r->newest = n;
    r->count++;
    return 0;
}

static void ref_free(RefCache* r) {
    for (size_t b = 0; b < r->nbuckets; b++) {
        RefNode* n = r->buckets[b];
        while (n) {
            RefNode* next = n->hnext;
            free(n);
            n = next;
        }
    }
    free(r->buckets);
    memset(r, 0, sizeof(*r));
}

static int cache_matches_ref(NonceCache* c, const RefCache* r) {
    if (c->count != r->count || c->table_count != c->count) return 0;
    int s = c->head;
    const RefNode* n = r->oldest;
    size_t steps = 0;
    while (s >= 0 && n) {
        if (c->slots[s].nonce != n->nonce) return 0;
        s = c->slots[s].next;
        n = n->newer;
        steps++;
    }
    if (s >= 0 || n != NULL || steps != c->count) return 0;
    for (n = r->oldest; n; n = n->newer)
        if (cache_find(c, n->nonce, NULL) < 0) return 0;
    return 1;
}

static void test_eviction_order(void) {
    NonceCache c;
    check("cache_init", cache_init(&c, NONCE_CACHE_CAP));
    if (c.slots == NULL) return;

    for (unsigned long long n = 1; n <= NONCE_CACHE_CAP; n++) cache_put(&c, n);
    check("cache_fills_to_cap", c.count == NONCE_CACHE_CAP);
    check("cache_keeps_first_insert", cache_find(&c, 1, NULL) >= 0);

    for (unsigned long long n = NONCE_CACHE_CAP + 1; n <= NONCE_CACHE_CAP + 4; n++)
        cache_put(&c, n);
    check("cache_evicts_oldest",
          cache_find(&c, 1, NULL) < 0 && cache_find(&c, 2, NULL) < 0 &&
          cache_find(&c, 3, NULL) < 0 && cache_find(&c, 4, NULL) < 0);
    check("cache_keeps_newer",
          cache_find(&c, 5, NULL) >= 0 &&
          cache_find(&c, NONCE_CACHE_CAP + 4, NULL) >= 0);
    check("cache_count_capped",
          c.count == NONCE_CACHE_CAP && c.table_count == c.count);

    int head = c.head, tail = c.tail;
    check("cache_order_oldest_first",
          head >= 0 && tail >= 0 &&
          c.slots[head].nonce == 5 &&
          c.slots[tail].nonce == NONCE_CACHE_CAP + 4);

    /* a replay hit is rejected without refreshing its age */
    check("cache_replay_hit", cache_put(&c, 5) == 1 && c.head == head);
    cache_put(&c, NONCE_CACHE_CAP + 5);
    check("cache_hit_does_not_refresh",
          cache_find(&c, 5, NULL) < 0 && c.slots[c.head].nonce == 6);

    check("cache_struct_consistent", cache_consistent(&c));
    check("cache_probes_bounded", c.probe_max < 64);
    cache_free(&c);
}

static void test_reference_equivalence(void) {
    NonceCache c;
    RefCache r;
    check("diff_init",
          cache_init(&c, NONCE_CACHE_CAP) && ref_init(&r, NONCE_CACHE_CAP));
    if (!c.slots || !r.buckets) return;

    unsigned long long x = 0x0123456789abcdefULL;
    const size_t pool = NONCE_CACHE_CAP + NONCE_CACHE_CAP / 4;
    int mismatch = 0;
    for (size_t i = 0; i < 30000; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        unsigned long long nonce = x % pool;
        int got = cache_put(&c, nonce);
        int want = ref_put(&r, nonce);
        if (got != want || c.count != r.count) {
            mismatch++;
            break;
        }
        if (i % 251 == 0 && !cache_matches_ref(&c, &r)) {
            mismatch++;
            break;
        }
    }
    check("cache_matches_reference",
          mismatch == 0 && cache_matches_ref(&c, &r) && cache_consistent(&c));
    check("cache_probes_bounded_ref", c.probe_max < 64);
    cache_free(&c);
    ref_free(&r);
}

static void test_memory_bounded(void) {
    NonceCache c;
    check("mem_init", cache_init(&c, NONCE_CACHE_CAP));
    if (!c.slots) return;

    NonceSlot* slots = c.slots;
    int* table = c.table;
    size_t cap = c.cap, table_cap = c.table_cap;
    int over = 0;
    for (unsigned long long n = 0; n < 1000000ULL; n++) {
        cache_put(&c, n);
        if (c.count > cap) {
            over = 1;
            break;
        }
    }
    check("cache_memory_fixed",
          !over && c.count == cap && c.slots == slots && c.table == table &&
          c.cap == cap && c.table_cap == table_cap &&
          c.table_count == c.count);
    check("cache_after_flood",
          cache_find(&c, 999999, NULL) >= 0 &&
          cache_find(&c, 999999 - NONCE_CACHE_CAP, NULL) < 0);
    check("cache_flood_consistent", cache_consistent(&c));
    check("cache_probes_bounded_flood", c.probe_max < 64);
    cache_free(&c);
}

/* Small-capacity trace: the eviction order is printed and compared against
   the exact insertion order, so FIFO semantics are auditable by eye as well
   as by assertion. */
static void test_eviction_trace(void) {
    enum { TINY = 8 };
    NonceCache c;
    check("trace_init", cache_init(&c, TINY));
    if (!c.slots) return;

    for (unsigned long long n = 10; n < 10 + TINY; n++) cache_put(&c, n);
    for (unsigned long long n = 100; n < 104; n++) cache_put(&c, n);

    printf("trace_evicted=");
    int trace_ok = 1;
    for (unsigned long long expect = 10; expect < 14; expect++) {
        if (cache_find(&c, expect, NULL) >= 0) trace_ok = 0;
        printf("%llu%c", expect, expect == 13 ? '\n' : ',');
    }

    static const unsigned long long live[TINY] = {14, 15, 16, 17, 100, 101, 102, 103};
    printf("trace_order=");
    int s = c.head;
    for (int i = 0; i < TINY; i++) {
        if (s < 0 || c.slots[s].nonce != live[i]) trace_ok = 0;
        printf("%llu%c", live[i], i == TINY - 1 ? '\n' : ',');
        if (s >= 0) s = c.slots[s].next;
    }
    check("trace_fifo_order", trace_ok && s < 0 && c.count == TINY);
    cache_free(&c);
}

/* Adjacent and crafted nonces are what an attacker actually sends.  After
   the salt is applied the probe chains must stay short: without it, nonces
   in arithmetic order tend to cluster in the same buckets. */
static void test_adversarial_nonces(void) {
    NonceCache c;
    check("adv_init", cache_init(&c, NONCE_CACHE_CAP));
    if (!c.slots) return;

    for (unsigned long long n = 0; n < NONCE_CACHE_CAP; n++) cache_put(&c, n * 2);
    check("adv_adjacent_probes", c.probe_max < 64);

    for (unsigned long long n = NONCE_CACHE_CAP * 2; n < NONCE_CACHE_CAP * 3; n++)
        cache_put(&c, n + 1);
    check("adv_adjacent_flood", c.count == NONCE_CACHE_CAP && c.probe_max < 64);
    check("adv_consistent", cache_consistent(&c));
    cache_free(&c);

    /* distinct caches get distinct salts, so one precomputed collision set
       does not transfer between processes */
    NonceCache a, b;
    int both = cache_init(&a, 64) && cache_init(&b, 64);
    check("adv_init_pair", both);
    if (both) {
        check("adv_salt_distinct", a.salt != b.salt);
        cache_free(&a);
        cache_free(&b);
    }
}

#define PERF_TOKENS 20000
#define PERF_WARMUP 1000

static void test_latency(void) {
    const unsigned char key[] = "0123456789abcdef0123456789abcdef";
    Auth a;
    check("perf_init", auth_init(&a, key, 32, 300, 5));
    if (!a.cache.slots) return;

    /* fill the replay cache before measuring */
    for (unsigned long long n = 1; n <= NONCE_CACHE_CAP; n++)
        cache_put(&a.cache, n);

    char (*tokens)[TOKEN_MAX] = malloc(sizeof(*tokens) * PERF_TOKENS);
    unsigned long long* samples = malloc(sizeof(*samples) * (PERF_TOKENS - PERF_WARMUP));
    check("perf_alloc", tokens != NULL && samples != NULL);
    if (!tokens || !samples) {
        free(tokens);
        free(samples);
        auth_free(&a);
        return;
    }

    int built = 1;
    for (size_t i = 0; i < PERF_TOKENS; i++)
        if (!build_token(&a, "perf", 2000, NONCE_CACHE_CAP + 1 + i, tokens[i]))
            built = 0;
    check("perf_build", built);

    for (size_t i = 0; i < PERF_WARMUP; i++) verify(&a, tokens[i], 2000, NULL);

    int bad = 0;
    size_t timed = PERF_TOKENS - PERF_WARMUP;
    for (size_t i = 0; i < timed; i++) {
        unsigned long long t0 = cpu_ns();
        AuthErr e = verify(&a, tokens[PERF_WARMUP + i], 2000, NULL);
        unsigned long long t1 = cpu_ns();
        samples[i] = t1 - t0;
        if (e != AUTH_OK) {
            printf("perf_verify_%zu=%s\n", i, auth_name(e));
            bad++;
        }
    }
    check("perf_all_ok", bad == 0 && a.cache.count == NONCE_CACHE_CAP);

    unsigned long long sum = 0, max = 0;
    for (size_t i = 0; i < timed; i++) {
        sum += samples[i];
        if (samples[i] > max) max = samples[i];
    }
    qsort(samples, timed, sizeof(*samples), cmp_ull);
    unsigned long long avg = sum / timed;
    unsigned long long median = samples[timed / 2];
    unsigned long long p99 = samples[timed * 99 / 100];
    unsigned long long p999 = samples[timed * 999 / 1000];

    /* A shared/virtualised host (WSL2, CI) preempts for hundreds of
       microseconds and even CPU-time accounting absorbs the boundary, so
       the tail cannot be asserted on.  Judge the cost where the scheduler
       is not in the measurement: the median and the mean with the slowest
       1% dropped. */
    size_t kept = timed - timed / 100;
    unsigned long long kept_sum = 0;
    for (size_t i = 0; i < kept; i++) kept_sum += samples[i];
    unsigned long long trimmed = kept_sum / kept;

    printf("verify_ns_avg=%llu\n", avg);
    printf("verify_ns_median=%llu\n", median);
    printf("verify_ns_trimmed=%llu\n", trimmed);
    printf("verify_ns_p99=%llu\n", p99);
    printf("verify_ns_p999=%llu\n", p999);
    printf("verify_ns_max=%llu\n", max);
    check("verify_under_5us",
          !TIMING_ASSERTS || (median < 5000 && trimmed < 5000));

    free(tokens);
    free(samples);
    auth_free(&a);
}

static unsigned long long cache_op_ns(size_t cap, int hits) {
    NonceCache c;
    if (!cache_init(&c, cap)) return 0;
    for (unsigned long long n = 0; n < cap; n++) cache_put(&c, n);

    const size_t rounds = 20000;
    unsigned long long sum = 0;
    for (size_t i = 0; i < rounds; i++) {
        unsigned long long nonce = hits ? (unsigned long long)(i % cap)
                                        : 5000000ULL + i;
        unsigned long long t0 = cpu_ns();
        cache_put(&c, nonce);
        sum += cpu_ns() - t0;
    }
    cache_free(&c);
    return sum / rounds;
}

static void test_cache_latency(void) {
    NonceCache c;
    check("cache_latency_init", cache_init(&c, NONCE_CACHE_CAP));
    if (!c.slots) return;
    cache_free(&c);

    unsigned long long hit_avg = cache_op_ns(NONCE_CACHE_CAP, 1);
    unsigned long long miss_avg = cache_op_ns(NONCE_CACHE_CAP, 0);
    printf("cache_hit_ns_avg=%llu\n", hit_avg);
    printf("cache_insert_ns_avg=%llu\n", miss_avg);

    /* same operation at 1/10 the capacity: O(1) means the cost must not
       scale with capacity */
    unsigned long long small_hit = cache_op_ns(NONCE_CACHE_CAP / 10, 1);
    unsigned long long small_miss = cache_op_ns(NONCE_CACHE_CAP / 10, 0);
    printf("cache_hit_ns_1k=%llu\n", small_hit);
    printf("cache_insert_ns_1k=%llu\n", small_miss);

    check("cache_ops_constant_time",
          !TIMING_ASSERTS || (hit_avg < 2000 && miss_avg < 2000));
    check("cache_ops_do_not_scale",
          !TIMING_ASSERTS || (hit_avg < small_hit * 3 + 1000 &&
                              miss_avg < small_miss * 3 + 1000));
}

int main(void) {
    Auth a;
    const unsigned char key[] = "0123456789abcdef0123456789abcdef";
    check("init", auth_init(&a, key, 32, 300, 5));
    if (!a.cache.slots) {
        printf("all_ok=0\n");
        return 1;
    }

    char tok[TOKEN_MAX];
    long now = 1000;
    check("build_ok", build_token(&a, "u1", now, 42, tok));
    check("verify_ok", verify(&a, tok, now, NULL) == AUTH_OK);
    check("replay_rejected", verify(&a, tok, now, NULL) == AUTH_REPLAY);

    char tok2[TOKEN_MAX];
    build_token(&a, "u1", now, 43, tok2);
    check("distinct_nonce_ok", verify(&a, tok2, now, NULL) == AUTH_OK);

    char bad[TOKEN_MAX];
    strcpy(bad, tok2);
    bad[0] = bad[0] == 'a' ? 'b' : 'a';
    check("tampered_sig", verify(&a, bad, now, NULL) == AUTH_BAD_SIG);

    check("expired", verify(&a, tok2, now + 400, NULL) == AUTH_EXPIRED);

    char tok_old[TOKEN_MAX];
    build_token(&a, "u3", now, 45, tok_old);

    const unsigned char key2[] = "ffffffffffffffffffffffffffffffff";
    auth_rotate(&a, key2, 32);
    char tok3[TOKEN_MAX];
    build_token(&a, "u2", now, 44, tok3);
    check("rotated_new_key_ok", verify(&a, tok3, now, NULL) == AUTH_OK);
    check("old_token_still_ok", verify(&a, tok_old, now, NULL) == AUTH_OK);

    check("malformed", verify(&a, "garbage", now, NULL) == AUTH_MALFORMED);

    auth_free(&a);

    test_eviction_order();
    test_eviction_trace();
    test_reference_equivalence();
    test_memory_bounded();
    test_adversarial_nonces();
    test_cache_latency();
    test_latency();

    printf("all_ok=%d\n", failures == 0);
    return failures == 0 ? 0 : 1;
}
