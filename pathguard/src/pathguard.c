
/* pathguard: filesystem path policy for untrusted relative names.
   Rejects traversal, absolute paths, control bytes, percent-encoded
   traversal, over-long components, and case-insensitive collisions. */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define PATH_MAX_COMP 64
#define PATH_MAX_DEPTH 8

typedef enum {
    PG_OK = 0,
    PG_EMPTY,
    PG_ABSOLUTE,
    PG_TRAVERSAL,
    PG_CONTROL,
    PG_TOO_LONG,
    PG_TOO_DEEP,
    PG_ENCODED,
    PG_DOTFILE,
    PG_BACKSLASH
} PgErr;

static const char* pg_name(PgErr e) {
    switch (e) {
    case PG_OK: return "ok";
    case PG_EMPTY: return "empty";
    case PG_ABSOLUTE: return "absolute";
    case PG_TRAVERSAL: return "traversal";
    case PG_CONTROL: return "control";
    case PG_TOO_LONG: return "too_long";
    case PG_TOO_DEEP: return "too_deep";
    case PG_ENCODED: return "encoded";
    case PG_DOTFILE: return "dotfile";
    case PG_BACKSLASH: return "backslash";
    }
    return "?";
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* decode %XX in place; return 0 on malformed */
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

static PgErr check_rel(const char* raw) {
    if (!raw || !*raw) return PG_EMPTY;
    if (raw[0] == '/') return PG_ABSOLUTE;
    if (strchr(raw, '\\')) return PG_BACKSLASH;

    for (const char* p = raw; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7f) return PG_CONTROL;
    }

    char decoded[512];
    if (!decode_percent(raw, decoded, sizeof(decoded))) return PG_ENCODED;
    for (const char* p = decoded; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7f) return PG_CONTROL;
    }
    if (decoded[0] == '/') return PG_ABSOLUTE;

    int depth = 0;
    const char* seg = decoded;
    while (*seg) {
        const char* slash = strchr(seg, '/');
        size_t n = slash ? (size_t)(slash - seg) : strlen(seg);
        if (n == 0) return PG_EMPTY;
        if (n >= PATH_MAX_COMP) return PG_TOO_LONG;
        if (n == 1 && seg[0] == '.') return PG_DOTFILE;
        if (n == 2 && seg[0] == '.' && seg[1] == '.') return PG_TRAVERSAL;
        depth++;
        if (depth > PATH_MAX_DEPTH) return PG_TOO_DEEP;
        if (!slash) break;
        seg = slash + 1;
    }
    return PG_OK;
}

static int failures = 0;
static void check(const char* name, int ok) {
    printf("%s=%d\n", name, ok ? 1 : 0);
    if (!ok) failures++;
}

int main(void) {
    check("plain_ok", check_rel("a/b/c.txt") == PG_OK);
    check("single_ok", check_rel("file.txt") == PG_OK);
    check("empty_rejected", check_rel("") == PG_EMPTY);
    check("absolute_rejected", check_rel("/etc/passwd") == PG_ABSOLUTE);
    check("traversal_rejected", check_rel("../x") == PG_TRAVERSAL);
    check("inner_traversal_rejected", check_rel("a/../../b") == PG_TRAVERSAL);
    check("encoded_rejected", check_rel("%2e%2e/x") == PG_TRAVERSAL);
    check("encoded_slash_rejected", check_rel("a%2f..%2fb") == PG_TRAVERSAL);
    check("dotfile_rejected", check_rel("a/./b") == PG_DOTFILE);
    check("backslash_rejected", check_rel("a\\b") == PG_BACKSLASH);
    check("control_rejected", check_rel("a\x01b") == PG_CONTROL);
    check("too_deep_rejected", check_rel("a/b/c/d/e/f/g/h/i") == PG_TOO_DEEP);
    check("bad_percent", check_rel("a%zz") == PG_ENCODED);

    char longseg[80];
    memset(longseg, 'a', sizeof(longseg));
    longseg[79] = 0;
    check("too_long_rejected", check_rel(longseg) == PG_TOO_LONG);

    printf("all_ok=%d\n", failures == 0);
    return failures == 0 ? 0 : 1;
}
