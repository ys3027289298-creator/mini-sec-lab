/* pg_policy: rejects traversal, absolute paths, control bytes,
   percent-encoded traversal, over-long components, dot segments and
   backslashes.  Validation operates on the decoded byte string, and the
   opener receives that same string, so encoding tricks cannot make the
   checker inspect different bytes than openat2(2) resolves. */
#include "pg_policy.h"

#include <string.h>

const char* pg_err_name(PgErr e) {
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
    case PG_OVERFLOW: return "overflow";
    }
    return "?";
}

static int hexval(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

typedef enum { DEC_OK = 0, DEC_BAD, DEC_NUL, DEC_OVERFLOW } DecRes;

/* Decode %XX in place into out.  A decoded NUL is rejected: it would end
   the C string early while the validator and the kernel still agree, but
   it hides attacker-chosen bytes from every later string consumer. */
static DecRes decode_percent(const char* in, char* out, size_t cap,
                             size_t* out_len) {
    size_t o = 0;
    for (size_t i = 0; in[i]; i++) {
        if (o + 1 >= cap) return DEC_OVERFLOW;
        if (in[i] == '%') {
            int h = hexval((unsigned char)in[i + 1]);
            int l = h >= 0 ? hexval((unsigned char)in[i + 2]) : -1;
            if (h < 0 || l < 0) return DEC_BAD;
            unsigned char c = (unsigned char)((h << 4) | l);
            if (c == 0) return DEC_NUL;
            out[o++] = (char)c;
            i += 2;
        } else {
            out[o++] = in[i];
        }
    }
    out[o] = 0;
    *out_len = o;
    return DEC_OK;
}

PgErr pg_check_name(const char* raw, char* decoded, size_t cap,
                    size_t* decoded_len) {
    if (!raw || !*raw) return PG_EMPTY;
    if (raw[0] == '/') return PG_ABSOLUTE;
    if (strchr(raw, '\\')) return PG_BACKSLASH;

    for (const char* p = raw; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7f) return PG_CONTROL;
    }

    size_t len = 0;
    switch (decode_percent(raw, decoded, cap, &len)) {
    case DEC_OK: break;
    case DEC_BAD: return PG_ENCODED;
    case DEC_NUL: return PG_CONTROL;
    case DEC_OVERFLOW: return PG_OVERFLOW;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)decoded[i];
        if (c < 0x20 || c == 0x7f) return PG_CONTROL;
        if (c == '\\') return PG_BACKSLASH;
    }
    if (decoded[0] == '/') return PG_ABSOLUTE;

    /* A trailing slash yields an empty final component, and an empty
       final component is an empty name: reject it rather than letting
       the kernel interpret it as the directory itself. */
    if (len > 0 && decoded[len - 1] == '/') return PG_EMPTY;

    int depth = 0;
    size_t seg_start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i != len && decoded[i] != '/') continue;
        size_t n = i - seg_start;
        if (n == 0) return PG_EMPTY;
        if (n >= PG_MAX_COMP) return PG_TOO_LONG;
        if (n == 1 && decoded[seg_start] == '.') return PG_DOTFILE;
        if (n == 2 && decoded[seg_start] == '.' &&
            decoded[seg_start + 1] == '.')
            return PG_TRAVERSAL;
        depth++;
        if (depth > PG_MAX_DEPTH) return PG_TOO_DEEP;
        seg_start = i + 1;
    }

    *decoded_len = len;
    return PG_OK;
}
