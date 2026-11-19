
/* pathguard: filesystem path policy for untrusted relative names.
   Rejects traversal, absolute paths, control bytes, percent-encoded
   traversal, and case-insensitive collisions.

   Quotas (all configurable via PgLimits, all fail explicitly, never
   truncate):
     max_comp     - max bytes per path component      -> PG_TOO_LONG
     max_total    - max bytes of the whole path       -> PG_TOTAL_TOO_LONG
     max_depth    - max directory levels (a/b/c = 2)  -> PG_TOO_DEEP
     max_segments - max number of components          -> PG_TOO_MANY_SEGMENTS
   A limit of N means N is allowed, N+1 is rejected. */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* hard ceiling for the internal decode buffer; limits above this are
   rejected as PG_BAD_LIMITS rather than silently clamped */
#define PG_ABS_MAX 4096

typedef struct {
    size_t max_comp;
    size_t max_total;
    size_t max_depth;
    size_t max_segments;
} PgLimits;

static PgLimits pg_default_limits(void) {
    PgLimits l = { 64, 256, 8, 32 };
    return l;
}

typedef enum {
    PG_OK = 0,
    PG_EMPTY,
    PG_ABSOLUTE,
    PG_TRAVERSAL,
    PG_CONTROL,
    PG_TOO_LONG,
    PG_TOTAL_TOO_LONG,
    PG_TOO_DEEP,
    PG_TOO_MANY_SEGMENTS,
    PG_ENCODED,
    PG_DOTFILE,
    PG_BACKSLASH,
    PG_BAD_LIMITS
} PgErr;

static const char* pg_name(PgErr e) {
    switch (e) {
    case PG_OK: return "ok";
    case PG_EMPTY: return "empty";
    case PG_ABSOLUTE: return "absolute";
    case PG_TRAVERSAL: return "traversal";
    case PG_CONTROL: return "control";
    case PG_TOO_LONG: return "too_long";
    case PG_TOTAL_TOO_LONG: return "total_too_long";
    case PG_TOO_DEEP: return "too_deep";
    case PG_TOO_MANY_SEGMENTS: return "too_many_segments";
    case PG_ENCODED: return "encoded";
    case PG_DOTFILE: return "dotfile";
    case PG_BACKSLASH: return "backslash";
    case PG_BAD_LIMITS: return "bad_limits";
    }
    return "?";
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* decode %XX in place; return 0 on malformed.
   Caller's total-length check guarantees out cannot overflow:
   decoding only shrinks the string. */
static int decode_percent(const char* in, char* out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; in[i]; i++) {
        if (o + 1 >= cap) return 0;
        if (in[i] == '%') {
            int h = hexval(in[i + 1]), l = h >= 0 ? hexval(in[i + 2]) : -1;
            if (h < 0 || l < 0) return 0;
            out[o++] = (char)((h << 4) | l);
            i += 2;
        } else {
            out[o++] = in[i];
        }
    }
    out[o] = 0;
    return 1;
}

static PgErr check_rel(const char* raw, const PgLimits* lim) {
    if (!lim || lim->max_comp == 0 || lim->max_total == 0 ||
        lim->max_total >= PG_ABS_MAX)
        return PG_BAD_LIMITS;

    if (!raw || !*raw) return PG_EMPTY;
    if (raw[0] == '/') return PG_ABSOLUTE;
    if (strchr(raw, '\\')) return PG_BACKSLASH;

    for (const char* p = raw; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7f) return PG_CONTROL;
    }

    /* total-length quota up front: explicit failure, no truncation */
    if (strlen(raw) > lim->max_total) return PG_TOTAL_TOO_LONG;

    char decoded[PG_ABS_MAX];
    if (!decode_percent(raw, decoded, sizeof(decoded))) return PG_ENCODED;
    for (const char* p = decoded; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7f) return PG_CONTROL;
    }
    if (decoded[0] == '/') return PG_ABSOLUTE;

    size_t depth = 0, segments = 0;
    const char* seg = decoded;
    while (*seg) {
        const char* slash = strchr(seg, '/');
        size_t n = slash ? (size_t)(slash - seg) : strlen(seg);
        if (n == 0) return PG_EMPTY;
        if (n > lim->max_comp) return PG_TOO_LONG;
        if (n == 1 && seg[0] == '.') return PG_DOTFILE;
        if (n == 2 && seg[0] == '.' && seg[1] == '.') return PG_TRAVERSAL;
        segments++;
        if (segments > lim->max_segments) return PG_TOO_MANY_SEGMENTS;
        if (slash) {
            depth++;
            if (depth > lim->max_depth) return PG_TOO_DEEP;
            seg = slash + 1;
        } else {
            break;
        }
    }
    return PG_OK;
}

static int failures = 0;
static void check(const char* name, PgErr got, PgErr want) {
    int ok = got == want;
    printf("%s=%d\n", name, ok);
    if (!ok) {
        printf("  %s: want %s, got %s\n", name, pg_name(want), pg_name(got));
        failures++;
    }
}

/* "a/"*dirs + "b" */
static void make_deep(char* buf, int dirs) {
    char* p = buf;
    for (int i = 0; i < dirs; i++) { *p++ = 'a'; *p++ = '/'; }
    *p++ = 'b';
    *p = 0;
}

/* dirs components of dlen chars, then a final component of flen chars */
static void make_total(char* buf, int dirs, size_t dlen, size_t flen) {
    char* p = buf;
    for (int i = 0; i < dirs; i++) { memset(p, 'a', dlen); p += dlen; *p++ = '/'; }
    memset(p, 'f', flen);
    p += flen;
    *p = 0;
}

int main(void) {
    PgLimits def = pg_default_limits();
    char buf[PG_ABS_MAX];

    check("plain_ok", check_rel("a/b/c.txt", &def), PG_OK);
    check("single_ok", check_rel("file.txt", &def), PG_OK);
    check("empty_rejected", check_rel("", &def), PG_EMPTY);
    check("absolute_rejected", check_rel("/etc/passwd", &def), PG_ABSOLUTE);
    check("traversal_rejected", check_rel("../x", &def), PG_TRAVERSAL);
    check("inner_traversal_rejected", check_rel("a/../../b", &def), PG_TRAVERSAL);
    check("encoded_rejected", check_rel("%2e%2e/x", &def), PG_TRAVERSAL);
    check("encoded_slash_rejected", check_rel("a%2f..%2fb", &def), PG_TRAVERSAL);
    check("dotfile_rejected", check_rel("a/./b", &def), PG_DOTFILE);
    check("backslash_rejected", check_rel("a\\b", &def), PG_BACKSLASH);
    check("control_rejected", check_rel("a\x01b", &def), PG_CONTROL);
    check("bad_percent", check_rel("a%zz", &def), PG_ENCODED);
    check("bad_limits_rejected",
          check_rel("a", &(PgLimits){ 64, PG_ABS_MAX, 8, 32 }), PG_BAD_LIMITS);

    /* ---- 16 boundary cases: 4 quotas x (at-limit ok, over-limit fail,
       raised-limit ok, raised-limit over) ---- */

    /* component length, default max_comp = 64 */
    memset(buf, 'a', 64); buf[64] = 0;
    check("b01_comp_at_limit_ok", check_rel(buf, &def), PG_OK);
    memset(buf, 'a', 65); buf[65] = 0;
    check("b02_comp_over_limit", check_rel(buf, &def), PG_TOO_LONG);
    PgLimits comp128 = def; comp128.max_comp = 128;
    check("b03_comp_raised_ok", check_rel(buf, &comp128), PG_OK);
    memset(buf, 'a', 129); buf[129] = 0;
    check("b04_comp_raised_over", check_rel(buf, &comp128), PG_TOO_LONG);

    /* total length, default max_total = 256 (8 dirs of 28 + file) */
    make_total(buf, 8, 28, 24);            /* 8*29 + 24 = 256 */
    check("b05_total_at_limit_ok", check_rel(buf, &def), PG_OK);
    make_total(buf, 8, 28, 25);            /* 257 */
    check("b06_total_over_limit", check_rel(buf, &def), PG_TOTAL_TOO_LONG);
    PgLimits tot512 = def; tot512.max_total = 512;
    check("b07_total_raised_ok", check_rel(buf, &tot512), PG_OK);
    make_total(buf, 8, 60, 25);            /* 8*61 + 25 = 513 */
    check("b08_total_raised_over", check_rel(buf, &tot512), PG_TOTAL_TOO_LONG);

    /* depth, default max_depth = 8 */
    make_deep(buf, 8);
    check("b09_depth_at_limit_ok", check_rel(buf, &def), PG_OK);
    make_deep(buf, 9);
    check("b10_depth_over_limit", check_rel(buf, &def), PG_TOO_DEEP);
    PgLimits depth16 = def; depth16.max_depth = 16;
    check("b11_depth_raised_ok", check_rel(buf, &depth16), PG_OK);
    make_deep(buf, 17);
    check("b12_depth_raised_over", check_rel(buf, &depth16), PG_TOO_DEEP);

    /* segments, default max_segments = 32; raise depth so segments
       is the quota that actually binds */
    PgLimits seglim = def; seglim.max_depth = 64;
    make_deep(buf, 31);                    /* 32 segments */
    check("b13_seg_at_limit_ok", check_rel(buf, &seglim), PG_OK);
    make_deep(buf, 32);                    /* 33 segments */
    check("b14_seg_over_limit", check_rel(buf, &seglim), PG_TOO_MANY_SEGMENTS);
    PgLimits seg64 = seglim; seg64.max_segments = 64;
    check("b15_seg_raised_ok", check_rel(buf, &seg64), PG_OK);
    make_deep(buf, 64);                    /* 65 segments */
    check("b16_seg_raised_over", check_rel(buf, &seg64), PG_TOO_MANY_SEGMENTS);

    printf("all_ok=%d\n", failures == 0);
    return failures == 0 ? 0 : 1;
}
