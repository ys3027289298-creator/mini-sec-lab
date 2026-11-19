#define _POSIX_C_SOURCE 199309L

/* reqguard: HTTP request parsing hardened against request smuggling.

   HTTP/1.1: rejects CL+TE, duplicate Content-Length, obs-fold, control
   chars, over-long header lines and oversized buffers.

   HTTP/2: a complete field section (HEADERS plus CONTINUATION payload)
   is HPACK-decoded in connection order, then validated as a request:
   lowercase field names, no connection-specific fields, pseudo-headers
   only in the leading block and not repeated, :method/:scheme/:path
   present unless CONNECT, and the same framing checks as HTTP/1.1.

   Both protocols go through parse_request(); the connection object
   carries the HPACK context so dynamic-table state persists across the
   streams of one connection. */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <strings.h>

#include "hpack.h"

#define MAX_HEADERS 32
#define MAX_LINE 256
#define MAX_BUF 4096
#define MAX_TARGET 128
#define MAX_NAME 128
#define MAX_VALUE 1024
/* `make test` gates on the 10,000-stream run; a floor this low only
   catches pathological regressions, not machine speed. */
#define BENCH_MIN_STREAMS_PER_S 100000

typedef enum {
    REQ_OK = 0,
    /* HTTP/1.1 framing */
    REQ_ERR_METHOD,
    REQ_ERR_TARGET,
    REQ_ERR_VERSION,
    REQ_ERR_HEADER_SYNTAX,
    REQ_ERR_OBS_FOLD,
    REQ_ERR_CONTROL,
    REQ_ERR_DUP_CL,
    REQ_ERR_CL_TE,
    REQ_ERR_BAD_CL,
    REQ_ERR_LINE_TOO_LONG,
    REQ_ERR_TOO_LARGE,
    REQ_ERR_TOO_MANY_HEADERS,
    /* HTTP/2 field validation (RFC 9113 section 8.2/8.3) */
    REQ_ERR_H2_FIELD_NAME,
    REQ_ERR_H2_FIELD_VALUE,
    REQ_ERR_H2_CONNECTION,
    REQ_ERR_H2_TE,
    REQ_ERR_H2_PSEUDO_ORDER,
    REQ_ERR_H2_PSEUDO_UNKNOWN,
    REQ_ERR_H2_PSEUDO_DUP,
    REQ_ERR_H2_PSEUDO_MISSING,
    REQ_ERR_H2_PSEUDO_VALUE,
    /* HPACK decoding (RFC 7541) */
    REQ_ERR_HPACK_TRUNCATED,
    REQ_ERR_HPACK_INTEGER,
    REQ_ERR_HPACK_INDEX_ZERO,
    REQ_ERR_HPACK_INDEX_RANGE,
    REQ_ERR_HPACK_HUFFMAN,
    REQ_ERR_HPACK_FIELD_TOO_LARGE,
    REQ_ERR_HPACK_LIST_TOO_LARGE,
    REQ_ERR_HPACK_TABLE_UPDATE,
    REQ_ERR_HPACK_UPDATE_POSITION,
    REQ_ERR_HPACK_UPDATE_MISSING,
    REQ_ERR_HPACK_TABLE_LIMIT
} ReqErr;

typedef enum { REQ_PROTO_HTTP1 = 1, REQ_PROTO_HTTP2 = 2 } ReqProto;

typedef struct { char name[MAX_NAME]; char value[MAX_VALUE]; } Header;

typedef struct {
    ReqProto proto;
    char method[16];
    char target[MAX_TARGET];
    char scheme[16];
    char authority[128];
    char version[16];
    Header headers[MAX_HEADERS];
    int header_count;
    long content_length;   /* -1 when absent */
    int has_te;            /* HTTP/1.1 chunked framing */
} Request;

typedef struct {
    ReqProto proto;
    HpackDecoder hpack;    /* HTTP/2 compression context, per connection */
} ReqConn;

/* Parity hook: sees every decoded field in order. */
typedef void (*ReqFieldFn)(void* user, const char* name, size_t name_len,
                           const char* value, size_t value_len);

static const char* err_name(ReqErr e) {
    switch (e) {
    case REQ_OK: return "ok";
    case REQ_ERR_METHOD: return "bad_method";
    case REQ_ERR_TARGET: return "bad_target";
    case REQ_ERR_VERSION: return "bad_version";
    case REQ_ERR_HEADER_SYNTAX: return "bad_header";
    case REQ_ERR_OBS_FOLD: return "obs_fold";
    case REQ_ERR_CONTROL: return "control_char";
    case REQ_ERR_DUP_CL: return "dup_content_length";
    case REQ_ERR_CL_TE: return "cl_te_conflict";
    case REQ_ERR_BAD_CL: return "bad_content_length";
    case REQ_ERR_LINE_TOO_LONG: return "line_too_long";
    case REQ_ERR_TOO_LARGE: return "too_large";
    case REQ_ERR_TOO_MANY_HEADERS: return "too_many_headers";
    case REQ_ERR_H2_FIELD_NAME: return "h2_field_name";
    case REQ_ERR_H2_FIELD_VALUE: return "h2_field_value";
    case REQ_ERR_H2_CONNECTION: return "h2_connection_header";
    case REQ_ERR_H2_TE: return "h2_te_value";
    case REQ_ERR_H2_PSEUDO_ORDER: return "h2_pseudo_order";
    case REQ_ERR_H2_PSEUDO_UNKNOWN: return "h2_pseudo_unknown";
    case REQ_ERR_H2_PSEUDO_DUP: return "h2_pseudo_dup";
    case REQ_ERR_H2_PSEUDO_MISSING: return "h2_pseudo_missing";
    case REQ_ERR_H2_PSEUDO_VALUE: return "h2_pseudo_value";
    case REQ_ERR_HPACK_TRUNCATED: return "hpack_truncated";
    case REQ_ERR_HPACK_INTEGER: return "hpack_integer_overflow";
    case REQ_ERR_HPACK_INDEX_ZERO: return "hpack_index_zero";
    case REQ_ERR_HPACK_INDEX_RANGE: return "hpack_index_range";
    case REQ_ERR_HPACK_HUFFMAN: return "hpack_huffman";
    case REQ_ERR_HPACK_FIELD_TOO_LARGE: return "hpack_field_too_large";
    case REQ_ERR_HPACK_LIST_TOO_LARGE: return "hpack_header_list_too_large";
    case REQ_ERR_HPACK_TABLE_UPDATE: return "hpack_table_size_update_exceeds_max";
    case REQ_ERR_HPACK_UPDATE_POSITION: return "hpack_size_update_after_field";
    case REQ_ERR_HPACK_UPDATE_MISSING: return "hpack_size_update_missing";
    case REQ_ERR_HPACK_TABLE_LIMIT: return "hpack_table_size_limit";
    }
    return "?";
}

static ReqErr hpack_req_err(int err) {
    switch (err) {
    case HPACK_OK: return REQ_OK;
    case HPACK_ERR_TRUNCATED: return REQ_ERR_HPACK_TRUNCATED;
    case HPACK_ERR_INTEGER_OVERFLOW: return REQ_ERR_HPACK_INTEGER;
    case HPACK_ERR_INDEX_ZERO: return REQ_ERR_HPACK_INDEX_ZERO;
    case HPACK_ERR_INDEX_RANGE: return REQ_ERR_HPACK_INDEX_RANGE;
    case HPACK_ERR_HUFFMAN: return REQ_ERR_HPACK_HUFFMAN;
    case HPACK_ERR_FIELD_TOO_LARGE: return REQ_ERR_HPACK_FIELD_TOO_LARGE;
    case HPACK_ERR_HEADER_LIST_TOO_LARGE: return REQ_ERR_HPACK_LIST_TOO_LARGE;
    case HPACK_ERR_TABLE_SIZE_UPDATE: return REQ_ERR_HPACK_TABLE_UPDATE;
    case HPACK_ERR_SIZE_UPDATE_POSITION: return REQ_ERR_HPACK_UPDATE_POSITION;
    case HPACK_ERR_SIZE_UPDATE_MISSING: return REQ_ERR_HPACK_UPDATE_MISSING;
    case HPACK_ERR_TABLE_SIZE_LIMIT: return REQ_ERR_HPACK_TABLE_LIMIT;
    case HPACK_ERR_CALLBACK: return REQ_ERR_H2_FIELD_NAME; /* never surfaced */
    }
    return REQ_ERR_HPACK_TRUNCATED;
}

void req_conn_init(ReqConn* c, ReqProto proto) {
    memset(c, 0, sizeof(*c));
    c->proto = proto;
    hpack_decoder_init(&c->hpack);
}

/* Small case-sensitive helpers; HTTP/2 field names are lowercase by the
   time they reach the validator, so no folding is needed here. */
static int is_token_char(unsigned char c) {
    if (isalnum(c)) return 1;
    return strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static int ci_equal(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

/* returns length of the line without CRLF, or -1 */
static int next_line(const char* buf, size_t len, size_t* pos, char* out, int cap) {
    size_t start = *pos;
    while (*pos + 1 < len) {
        if (buf[*pos] == '\r' && buf[*pos + 1] == '\n') {
            size_t n = *pos - start;
            if ((int)n >= cap) return -1;
            memcpy(out, buf + start, n);
            out[n] = 0;
            *pos += 2;
            return (int)n;
        }
        (*pos)++;
    }
    return -1;
}

/* ---------------------------------------------------------------- HTTP/1.1 */

static ReqErr parse_http1(const char* buf, size_t len, Request* req) {
    if (len > MAX_BUF) return REQ_ERR_TOO_LARGE;
    memset(req, 0, sizeof(*req));
    req->proto = REQ_PROTO_HTTP1;
    req->content_length = -1;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == 0 || (c < 0x20 && c != '\r' && c != '\n' && c != '\t')) return REQ_ERR_CONTROL;
    }

    size_t pos = 0;
    char line[MAX_LINE + 1];

    if (next_line(buf, len, &pos, line, MAX_LINE + 1) < 0) return REQ_ERR_LINE_TOO_LONG;

    /* request line: METHOD SP TARGET SP VERSION */
    char* sp1 = strchr(line, ' ');
    if (!sp1) return REQ_ERR_METHOD;
    *sp1 = 0;
    char* sp2 = strchr(sp1 + 1, ' ');
    if (!sp2) return REQ_ERR_TARGET;
    *sp2 = 0;
    const char* target = sp1 + 1;
    const char* version = sp2 + 1;

    if (strlen(line) == 0 || strlen(line) >= sizeof(req->method)) return REQ_ERR_METHOD;
    for (const char* p = line; *p; p++) if (!is_token_char((unsigned char)*p)) return REQ_ERR_METHOD;
    strcpy(req->method, line);

    if (target[0] != '/' || strlen(target) >= sizeof(req->target)) return REQ_ERR_TARGET;
    for (const char* p = target; *p; p++) if ((unsigned char)*p <= 0x20 || *p == 0x7f) return REQ_ERR_TARGET;
    strcpy(req->target, target);

    if (strncmp(version, "HTTP/1.", 7) != 0) return REQ_ERR_VERSION;
    if (version[7] != '0' && version[7] != '1') return REQ_ERR_VERSION;
    if (version[8] != 0) return REQ_ERR_VERSION;
    strcpy(req->version, version);

    int seen_cl = 0;
    for (;;) {
        int n = next_line(buf, len, &pos, line, MAX_LINE + 1);
        if (n < 0) return REQ_ERR_LINE_TOO_LONG;
        if (n == 0) break;

        if (line[0] == ' ' || line[0] == '\t') return REQ_ERR_OBS_FOLD;

        char* colon = strchr(line, ':');
        if (!colon || colon == line) return REQ_ERR_HEADER_SYNTAX;
        *colon = 0;
        for (char* p = line; *p; p++) if (!is_token_char((unsigned char)*p)) return REQ_ERR_HEADER_SYNTAX;

        char* value = colon + 1;
        while (*value == ' ' || *value == '\t') value++;
        char* end = value + strlen(value);
        while (end > value && (end[-1] == ' ' || end[-1] == '\t')) *--end = 0;
        for (char* p = value; *p; p++) if ((unsigned char)*p == 0x7f) return REQ_ERR_CONTROL;

        if (req->header_count >= MAX_HEADERS) return REQ_ERR_TOO_MANY_HEADERS;

        if (ci_equal(line, "Content-Length")) {
            if (seen_cl) return REQ_ERR_DUP_CL;
            seen_cl = 1;
            char* ep = NULL;
            long v = strtol(value, &ep, 10);
            if (ep == value || (ep && *ep != 0) || v < 0) return REQ_ERR_BAD_CL;
            req->content_length = v;
        } else if (ci_equal(line, "Transfer-Encoding")) {
            req->has_te = 1;
        }

        /* Header names/values go through the same bounds as HTTP/2. */
        if (strlen(line) >= sizeof(req->headers[0].name) ||
            strlen(value) >= sizeof(req->headers[0].value)) return REQ_ERR_TOO_LARGE;
        strcpy(req->headers[req->header_count].name, line);
        strcpy(req->headers[req->header_count].value, value);
        req->header_count++;
    }

    if (req->has_te && seen_cl) return REQ_ERR_CL_TE;
    return REQ_OK;
}

/* ----------------------------------------------------------------- HTTP/2 */

/* A regular field's name/value must fit the Request representation. The
   HPACK layer allows 64 KiB per field; this parser keeps them bounded
   and says so instead of truncating. */
static int h2_name_ok(const char* name, size_t len, int pseudo) {
    if (len == 0) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c <= 0x20 || (c >= 0x41 && c <= 0x5a) || c >= 0x7f) return 0;
        if (c == ':' && !(pseudo && i == 0)) return 0;
    }
    return 1;
}

static int h2_value_ok(const char* value, size_t len) {
    if (len == 0) return 1;
    if (value[0] == ' ' || value[0] == '\t') return 0;
    if (value[len - 1] == ' ' || value[len - 1] == '\t') return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];
        if (c == 0 || c == '\r' || c == '\n') return 0;
    }
    return 1;
}

static int h2_connection_field(const char* name, size_t len) {
    static const char* const denied[] = {
        "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade"
    };
    for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); i++) {
        if (strlen(denied[i]) == len && memcmp(name, denied[i], len) == 0) return 1;
    }
    return 0;
}

typedef struct {
    int seen_regular;
    int n_pseudo;
    int has_method, has_scheme, has_path, has_authority;
    int seen_cl;
} H2State;

/* Validation runs inside the HPACK callback but never aborts decoding:
   HPACK's dynamic table must stay in sync with the peer for the rest of
   the connection even when this field block is rejected, so the first
   violation is remembered and the block is decoded to its end before
   the error is reported. */
typedef struct {
    Request* req;
    H2State* st;
    ReqFieldFn sink;
    void* sink_user;
    ReqErr err;            /* first field violation, REQ_OK if none */
} H2Ctx;

static int h2_field(void* user, const char* name, size_t name_len,
                    const char* value, size_t value_len) {
    H2Ctx* ctx = user;
    Request* req = ctx->req;
    H2State* st = ctx->st;
    int rc = REQ_OK;

    /* Report every decoded field to the parity sink before validation,
       so its trace includes the field that fails. */
    if (ctx->sink) ctx->sink(ctx->sink_user, name, name_len, value, value_len);

    if (ctx->err != REQ_OK) return 0;

    int pseudo = name_len > 0 && name[0] == ':';

    if (!h2_name_ok(name, name_len, pseudo)) rc = REQ_ERR_H2_FIELD_NAME;
    else if (!h2_value_ok(value, value_len)) rc = REQ_ERR_H2_FIELD_VALUE;
    else if (pseudo && st->seen_regular) rc = REQ_ERR_H2_PSEUDO_ORDER;

    if (rc != REQ_OK) { ctx->err = rc; return 0; }
    if (pseudo) {
        int known = 0, dup = 0;
        if (name_len == 7 && memcmp(name, ":method", 7) == 0) {
            known = 1; dup = st->has_method; st->has_method = 1;
            if (value_len == 0 || value_len >= sizeof(req->method)) rc = REQ_ERR_H2_PSEUDO_VALUE;
            else {
                for (size_t i = 0; i < value_len; i++)
                    if (!is_token_char((unsigned char)value[i])) rc = REQ_ERR_H2_PSEUDO_VALUE;
                memcpy(req->method, value, value_len);
                req->method[value_len] = 0;
            }
        } else if (name_len == 7 && memcmp(name, ":scheme", 7) == 0) {
            known = 1; dup = st->has_scheme; st->has_scheme = 1;
            if (value_len == 0 || value_len >= sizeof(req->scheme)) rc = REQ_ERR_H2_PSEUDO_VALUE;
            else {
                memcpy(req->scheme, value, value_len);
                req->scheme[value_len] = 0;
            }
        } else if (name_len == 5 && memcmp(name, ":path", 5) == 0) {
            known = 1; dup = st->has_path; st->has_path = 1;
            if (value_len == 0 || value_len >= sizeof(req->target)) rc = REQ_ERR_H2_PSEUDO_VALUE;
            else {
                memcpy(req->target, value, value_len);
                req->target[value_len] = 0;
            }
        } else if (name_len == 10 && memcmp(name, ":authority", 10) == 0) {
            known = 1; dup = st->has_authority; st->has_authority = 1;
            if (value_len >= sizeof(req->authority)) rc = REQ_ERR_H2_PSEUDO_VALUE;
            else {
                memcpy(req->authority, value, value_len);
                req->authority[value_len] = 0;
            }
        }
        if (!known) { ctx->err = REQ_ERR_H2_PSEUDO_UNKNOWN; return 0; }
        if (dup) { ctx->err = REQ_ERR_H2_PSEUDO_DUP; return 0; }
        st->n_pseudo++;
        if (rc != REQ_OK) ctx->err = rc;
        return 0;
    }

    st->seen_regular = 1;

    if (h2_connection_field(name, name_len)) { ctx->err = REQ_ERR_H2_CONNECTION; return 0; }

    if (name_len == 2 && memcmp(name, "te", 2) == 0) {
        if (!(value_len == 8 && strncasecmp(value, "trailers", 8) == 0)) {
            ctx->err = REQ_ERR_H2_TE;
            return 0;
        }
    }

    if (name_len == 14 && memcmp(name, "content-length", 14) == 0) {
        if (st->seen_cl) { ctx->err = REQ_ERR_DUP_CL; return 0; }
        st->seen_cl = 1;
        long v = 0;
        if (value_len == 0) { ctx->err = REQ_ERR_BAD_CL; return 0; }
        for (size_t i = 0; i < value_len; i++) {
            if (value[i] < '0' || value[i] > '9') { ctx->err = REQ_ERR_BAD_CL; return 0; }
            if (v > (2147483647L - (value[i] - '0')) / 10) { ctx->err = REQ_ERR_BAD_CL; return 0; }
            v = v * 10 + (value[i] - '0');
        }
        req->content_length = v;
    }

    if (name_len >= sizeof(req->headers[0].name) ||
        value_len >= sizeof(req->headers[0].value)) { ctx->err = REQ_ERR_TOO_LARGE; return 0; }
    if (req->header_count >= MAX_HEADERS) { ctx->err = REQ_ERR_TOO_MANY_HEADERS; return 0; }

    memcpy(req->headers[req->header_count].name, name, name_len);
    req->headers[req->header_count].name[name_len] = 0;
    memcpy(req->headers[req->header_count].value, value, value_len);
    req->headers[req->header_count].value[value_len] = 0;
    req->header_count++;
    return 0;
}

/* Post-decode request shape checks (RFC 9113 section 8.3.1 and 8.5). */
static ReqErr h2_finish(Request* req, const H2State* st) {
    int connect = strcmp(req->method, "CONNECT") == 0;

    if (!st->has_method) return REQ_ERR_H2_PSEUDO_MISSING;
    if (connect) {
        if (!st->has_authority) return REQ_ERR_H2_PSEUDO_MISSING;
        /* CONNECT carries authority only; :scheme/:path MUST be omitted. */
        if (st->has_scheme || st->has_path) return REQ_ERR_H2_PSEUDO_VALUE;
        strcpy(req->target, req->authority);
        return REQ_OK;
    }
    if (!st->has_scheme || !st->has_path) return REQ_ERR_H2_PSEUDO_MISSING;
    if (req->target[0] != '/' && strcmp(req->target, "*") != 0)
        return REQ_ERR_H2_PSEUDO_VALUE;
    return REQ_OK;
}

/* Decode one complete field section and validate it as a request. The
   optional sink sees every field the HPACK layer produced, including
   the one that fails validation, which is what the parity trace uses. */
ReqErr parse_h2_block(ReqConn* c, const uint8_t* block, size_t len,
                      Request* req, ReqFieldFn sink, void* sink_user) {
    memset(req, 0, sizeof(*req));
    req->proto = REQ_PROTO_HTTP2;
    req->content_length = -1;
    strcpy(req->version, "HTTP/2");

    H2State st;
    memset(&st, 0, sizeof(st));
    H2Ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.req = req;
    ctx.st = &st;
    ctx.sink = sink;
    ctx.sink_user = sink_user;

    if (c->proto != REQ_PROTO_HTTP2) return REQ_ERR_VERSION;

    int rc = hpack_decode(&c->hpack, block, len, h2_field, &ctx);
    if (rc != HPACK_OK) return hpack_req_err(rc);
    if (ctx.err != REQ_OK) return ctx.err;
    return h2_finish(req, &st);
}

/* The single parsing entry point both protocols use. */
ReqErr parse_request(ReqConn* c, const char* buf, size_t len, Request* req) {
    if (c->proto == REQ_PROTO_HTTP2)
        return parse_h2_block(c, (const uint8_t*)buf, len, req, NULL, NULL);
    return parse_http1(buf, len, req);
}

/* ------------------------------------------------------- encoder (tests) */

/* Minimal HPACK encoder, used only by the self-tests and the benchmark
   to build blocks; it deliberately covers just the representations
   those need. */
static size_t enc_int(uint8_t* out, unsigned prefix, uint8_t flags, uint32_t v) {
    uint32_t max = (1u << prefix) - 1u;
    size_t n = 0;
    if (v < max) {
        out[n++] = (uint8_t)(flags | v);
        return n;
    }
    out[n++] = (uint8_t)(flags | max);
    v -= max;
    while (v >= 128) {
        out[n++] = (uint8_t)(0x80 | (v & 0x7f));
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

/* Huffman-encode `s`; output must have room for 4 * len + 1 bytes. */
static size_t huff_encode(const char* s, size_t len, uint8_t* out) {
    uint64_t acc = 0;
    unsigned bits = 0;
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char sym = (unsigned char)s[i];
        acc = (acc << hpack_huff_len[sym]) | hpack_huff_code[sym];
        bits += hpack_huff_len[sym];
        while (bits >= 8) {
            out[n++] = (uint8_t)(acc >> (bits - 8));
            bits -= 8;
            acc &= (bits == 0) ? 0 : ((1ull << bits) - 1ull);
        }
    }
    if (bits > 0) out[n++] = (uint8_t)((acc << (8 - bits)) | ((1u << (8 - bits)) - 1u));
    return n;
}

static size_t enc_literal_indexed(uint8_t* out, uint32_t name_idx,
                                  const char* value, size_t vlen, int huffman) {
    size_t n = enc_int(out, 6, 0x40, name_idx);
    if (!huffman) {
        n += enc_int(out + n, 7, 0, (uint32_t)vlen);
        memcpy(out + n, value, vlen);
        return n + vlen;
    }
    uint8_t* tmp = malloc(4 * vlen + 1);
    size_t hl = huff_encode(value, vlen, tmp);
    n += enc_int(out + n, 7, 0x80, (uint32_t)hl);
    memcpy(out + n, tmp, hl);
    free(tmp);
    return n + hl;
}

static int run_bench(unsigned streams);

/* ------------------------------------------------------------- self-tests */

static int failures = 0;
static void check(const char* name, int ok) {
    printf("%s=%d\n", name, ok ? 1 : 0);
    if (!ok) failures++;
}

static ReqErr parse1(const char* s, Request* r) {
    ReqConn c;
    req_conn_init(&c, REQ_PROTO_HTTP1);
    return parse_request(&c, s, strlen(s), r);
}

static ReqErr parse_h2_hex(ReqConn* c, const char* hex, Request* r) {
    uint8_t buf[4096];
    size_t n = 0;
    int hi = -1;
    for (const char* p = hex; *p; p++) {
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else return REQ_ERR_CONTROL;
        if (hi < 0) hi = v;
        else { if (n >= sizeof(buf)) return REQ_ERR_TOO_LARGE; buf[n++] = (uint8_t)((hi << 4) | v); hi = -1; }
    }
    if (hi >= 0) return REQ_ERR_CONTROL;
    return parse_h2_block(c, buf, n, r, NULL, NULL);
}

static void self_test_hpack(void) {
    ReqConn c;
    Request r;

    /* RFC 7541 C.3.1 / C.3.2 / C.3.3: request sequence sharing the
       dynamic table across blocks (no Huffman). */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("rfc_c31", parse_h2_hex(&c, "828684410f7777772e6578616d706c652e636f6d", &r) == REQ_OK &&
          strcmp(r.method, "GET") == 0 && strcmp(r.target, "/") == 0 &&
          strcmp(r.authority, "www.example.com") == 0 && r.header_count == 0);
    check("rfc_c32_dynamic_index",
          parse_h2_hex(&c, "828684be58086e6f2d6361636865", &r) == REQ_OK &&
          strcmp(r.authority, "www.example.com") == 0 && r.header_count == 1 &&
          strcmp(r.headers[0].name, "cache-control") == 0 &&
          strcmp(r.headers[0].value, "no-cache") == 0);
    check("rfc_c33_new_entry",
          parse_h2_hex(&c, "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565", &r) == REQ_OK &&
          strcmp(r.scheme, "https") == 0 && strcmp(r.target, "/index.html") == 0 &&
          r.header_count == 1 && strcmp(r.headers[0].name, "custom-key") == 0);

    /* RFC 7541 C.4.1: same request with a Huffman-coded value. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("rfc_c41_huffman",
          parse_h2_hex(&c, "828684418cf1e3c2e5f23a6ba0ab90f4ff", &r) == REQ_OK &&
          strcmp(r.authority, "www.example.com") == 0);

    /* Dynamic table reuse from a second block on the same connection: a
       fresh connection must not resolve that dynamic index. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("dynamic_needs_state", parse_h2_hex(&c, "82be", &r) == REQ_ERR_HPACK_INDEX_RANGE);

    /* Indexed field with index 0 is a decoding error (RFC 7541 6.1). */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("index_zero", parse_h2_hex(&c, "80", &r) == REQ_ERR_HPACK_INDEX_ZERO);

    /* Truncated literal value. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("truncated", parse_h2_hex(&c, "400a637573746f6d2d6b6579", &r) == REQ_ERR_HPACK_TRUNCATED);

    /* Integer with too many continuation octets. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("integer_overflow", parse_h2_hex(&c, "ffffffffffff7f", &r) == REQ_ERR_HPACK_INTEGER);

    /* Huffman value containing EOS, and bad padding (0x00 tail). */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("huffman_eos", parse_h2_hex(&c, "41843fffffff", &r) == REQ_ERR_HPACK_HUFFMAN);
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("huffman_padding", parse_h2_hex(&c, "8286844182ff00", &r) == REQ_ERR_HPACK_HUFFMAN);

    /* Table size update above the advertised maximum. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("size_update_exceeds",
          parse_h2_hex(&c, "3fe21f82", &r) == REQ_ERR_HPACK_TABLE_UPDATE);

    /* Size update after a field has been emitted. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("size_update_position",
          parse_h2_hex(&c, "8220", &r) == REQ_ERR_HPACK_UPDATE_POSITION);

    /* A valid update first, then fields. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("size_update_first",
          parse_h2_hex(&c, "3fe01f828684", &r) == REQ_OK);

    /* Lowering the advertised maximum without an update in the next
       block must be reported (RFC 9113 4.3.1). */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("lower_settings",
          parse_h2_hex(&c, "828684418cf1e3c2e5f23a6ba0ab90f4ff", &r) == REQ_OK);
    hpack_decoder_set_allowed_table_size(&c.hpack, 128);
    check("size_update_missing", parse_h2_hex(&c, "82", &r) == REQ_ERR_HPACK_UPDATE_MISSING);
    check("size_update_ack", parse_h2_hex(&c, "3f61828684", &r) == REQ_OK);
    check("table_after_ack", hpack_dynamic_size(&c.hpack) <= 128);

    /* The smallest size seen in the interval must be signalled (RFC
       7541 4.2), even if the final size is back above the new limit. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("smallest_update_seed",
          parse_h2_hex(&c, "828684418cf1e3c2e5f23a6ba0ab90f4ff", &r) == REQ_OK);
    hpack_decoder_set_allowed_table_size(&c.hpack, 128);
    hpack_decoder_set_allowed_table_size(&c.hpack, 4096);
    check("size_update_smallest_missing",
          parse_h2_hex(&c, "3fe11f828684", &r) == REQ_ERR_HPACK_UPDATE_MISSING);
    check("size_update_smallest_present",
          parse_h2_hex(&c, "3f213fe11f828684", &r) == REQ_OK);

    /* An entry larger than the table empties it rather than truncating. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    hpack_decoder_set_allowed_table_size(&c.hpack, 64);
    check("evict_oversized_entry", parse_h2_hex(&c, "3f218286840028787878787878787878787878787878787878787878787878787878787878787878787878787878780179", &r) == REQ_OK);
    check("table_cleared", hpack_dynamic_count(&c.hpack) == 0);

    /* Shrinking to zero clears the table; restoring keeps it empty. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("resize_zero", parse_h2_hex(&c, "20828684", &r) == REQ_OK);
    check("table_zero_count", hpack_dynamic_count(&c.hpack) == 0 && hpack_dynamic_size(&c.hpack) == 0);
}

static void self_test_h2_fields(void) {
    ReqConn c;
    Request r;

    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_minimal",
          parse_h2_hex(&c, "828684", &r) == REQ_OK && r.header_count == 0);

    /* Uppercase field name is forbidden (RFC 9113 8.2.1). */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_uppercase_name",
          parse_h2_hex(&c, "8286840005582d466f6f0176", &r) == REQ_ERR_H2_FIELD_NAME);

    /* Connection-specific fields are forbidden (RFC 9113 8.2.2). */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_connection_header",
          parse_h2_hex(&c, "828684400a636f6e6e656374696f6e05636c6f7365", &r) == REQ_ERR_H2_CONNECTION);
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_transfer_encoding",
          parse_h2_hex(&c, "82868400117472616e736665722d656e636f64696e67076368756e6b6564", &r) == REQ_ERR_H2_CONNECTION);

    /* TE is allowed only with the value "trailers". */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_te_trailers", parse_h2_hex(&c, "8286844002746508747261696c657273", &r) == REQ_OK);
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_te_bad", parse_h2_hex(&c, "8286840002746504677a6970", &r) == REQ_ERR_H2_TE);

    /* Pseudo-headers must precede regular fields and not repeat. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_pseudo_order",
          parse_h2_hex(&c, "8286840006782d74657374017682", &r) == REQ_ERR_H2_PSEUDO_ORDER);
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_pseudo_dup", parse_h2_hex(&c, "828284", &r) == REQ_ERR_H2_PSEUDO_DUP);
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_pseudo_unknown", parse_h2_hex(&c, "82868440073a6e6f737563680178", &r) == REQ_ERR_H2_PSEUDO_UNKNOWN);
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_pseudo_missing", parse_h2_hex(&c, "82", &r) == REQ_ERR_H2_PSEUDO_MISSING);

    /* :path must be absolute for http/https. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_path_relative",
          parse_h2_hex(&c, "828600053a706174680178", &r) == REQ_ERR_H2_PSEUDO_VALUE);

    /* CONNECT omits :scheme/:path and requires :authority. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_connect_ok", parse_h2_hex(&c, "4207434f4e4e454354000a3a617574686f726974790b6578616d706c653a343433", &r) == REQ_OK &&
          strcmp(r.target, "example:443") == 0);
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_connect_with_scheme", parse_h2_hex(&c, "4207434f4e4e4543548600053a70617468012f000a3a617574686f726974790b6578616d706c653a343433", &r) == REQ_ERR_H2_PSEUDO_VALUE);

    /* Header value rules: leading space / CR are malformed. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_value_space", parse_h2_hex(&c, "8286844001780120", &r) == REQ_ERR_H2_FIELD_VALUE);
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_value_cr", parse_h2_hex(&c, "828684400178010d", &r) == REQ_ERR_H2_FIELD_VALUE);

    /* content-length checks match the HTTP/1.1 parser's names. */
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_cl_ok",
          parse_h2_hex(&c, "828684400e636f6e74656e742d6c656e6774680135", &r) == REQ_OK &&
          r.content_length == 5);
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_cl_dup",
          parse_h2_hex(&c, "828684400e636f6e74656e742d6c656e6774680135400e636f6e74656e742d6c656e6774680136", &r) == REQ_ERR_DUP_CL);
    req_conn_init(&c, REQ_PROTO_HTTP2);
    check("h2_cl_bad",
          parse_h2_hex(&c, "828684400e636f6e74656e742d6c656e677468022d31", &r) == REQ_ERR_BAD_CL);

    /* The HTTP/1.1 entry still behaves exactly as before. */
    Request r1;
    check("h1_simple_ok", parse1("GET /a HTTP/1.1\r\nHost: x\r\n\r\n", &r1) == REQ_OK &&
          r1.header_count == 1 && r1.proto == REQ_PROTO_HTTP1);
    check("h1_cl_te_rejected",
          parse1("POST /a HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", &r1) == REQ_ERR_CL_TE);
}

static void self_test_http1(void) {
    Request r;

    check("simple_ok", parse1("GET /a HTTP/1.1\r\nHost: x\r\n\r\n", &r) == REQ_OK && r.header_count == 1);
    check("post_cl_ok", parse1("POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\n", &r) == REQ_OK && r.content_length == 5);
    check("te_ok", parse1("POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", &r) == REQ_OK && r.has_te);
    check("dup_cl_rejected", parse1("POST /a HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", &r) == REQ_ERR_DUP_CL);
    check("cl_te_rejected", parse1("POST /a HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", &r) == REQ_ERR_CL_TE);
    check("obs_fold_rejected", parse1("GET /a HTTP/1.1\r\nX: a\r\n b\r\n\r\n", &r) == REQ_ERR_OBS_FOLD);
    check("bad_cl_rejected", parse1("POST /a HTTP/1.1\r\nContent-Length: -1\r\n\r\n", &r) == REQ_ERR_BAD_CL);
    check("bad_version", parse1("GET /a HTTP/2.0\r\n\r\n", &r) == REQ_ERR_VERSION);
    check("bad_target", parse1("GET a HTTP/1.1\r\n\r\n", &r) == REQ_ERR_TARGET);
    check("control_rejected", parse1("GET /a\x01 HTTP/1.1\r\n\r\n", &r) == REQ_ERR_CONTROL);
    check("no_colon", parse1("GET /a HTTP/1.1\r\nBadHeader\r\n\r\n", &r) == REQ_ERR_HEADER_SYNTAX);

    char big[MAX_BUF + 2];
    memset(big, 'A', sizeof(big));
    big[sizeof(big) - 1] = 0;
    check("too_large", parse1(big, &r) == REQ_ERR_TOO_LARGE);
}

/* --------------------------------------------------------------- benchmark */

/* 10,000 streams over one connection: each block reuses static indexes,
   adds two Huffman-coded literals to the dynamic table, then resolves
   the newest entry by index. */
static size_t build_stream_block(uint8_t* out) {
    size_t n = 0;
    n += enc_int(out + n, 7, 0x80, 2);                     /* :method GET */
    n += enc_int(out + n, 7, 0x80, 7);                     /* :scheme https */
    n += enc_int(out + n, 7, 0x80, 4);                     /* :path / */
    n += enc_literal_indexed(out + n, 1, "www.example.com", 15, 1);   /* :authority */
    n += enc_literal_indexed(out + n, 58, "bench-agent/1.0", 15, 1);  /* user-agent */
    n += enc_int(out + n, 7, 0x80, HPACK_STATIC_COUNT + 1); /* newest entry */
    return n;
}

static int run_bench(unsigned streams) {
    ReqConn* c = malloc(sizeof(*c));
    Request* req = malloc(sizeof(*req));
    uint8_t block[4096];
    if (!c || !req) { free(c); free(req); return 2; }
    req_conn_init(c, REQ_PROTO_HTTP2);

    size_t blen = build_stream_block(block);
    size_t fields = 0;
    ReqErr e = REQ_OK;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (unsigned i = 0; i < streams; i++) {
        e = parse_h2_block(c, block, blen, req, NULL, NULL);
        if (e != REQ_OK) break;
        fields += 6;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1.0e6;
    double bytes = (double)blen * (double)streams;
    double rate = ms > 0 ? streams / (ms / 1000.0) : 0.0;

    printf("bench_streams=%u\n", streams);
    printf("bench_fields=%zu\n", fields);
    printf("bench_block_bytes=%zu\n", blen);
    printf("bench_elapsed_ms=%.3f\n", ms);
    printf("bench_streams_per_s=%.0f\n", rate);
    printf("bench_mib_s=%.2f\n", ms > 0 ? bytes / (1024.0 * 1024.0) / (ms / 1000.0) : 0.0);
    printf("bench_result=%s\n", err_name(e));
    printf("mem_context_bytes=%zu\n", sizeof(ReqConn));
    printf("mem_request_bytes=%zu\n", sizeof(Request));
    free(c);
    free(req);

    if (e != REQ_OK) return 1;
    return streams == 10000 && rate >= BENCH_MIN_STREAMS_PER_S ? 0 : 1;
}

/* -------------------------------------------------------------------- CLI */

/* Parity trace. Reads a script on stdin: "table N" sets the advertised
   maximum, "block HEX" decodes one field section. Output is line-based
   and compared byte for byte with tools/ref_hpack.py. */
static void trace_field(void* user, const char* name, size_t nlen,
                        const char* value, size_t vlen) {
    (void)user;
    printf("field ");
    for (size_t i = 0; i < nlen; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c >= 0x20 && c <= 0x7e && c != '\\') putchar(c);
        else printf("\\x%02x", c);
    }
    putchar(' ');
    for (size_t i = 0; i < vlen; i++) {
        unsigned char c = (unsigned char)value[i];
        if (c >= 0x20 && c <= 0x7e && c != '\\') putchar(c);
        else printf("\\x%02x", c);
    }
    putchar('\n');
}

static int hexval(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int run_trace(void) {
    ReqConn* c = malloc(sizeof(*c));
    Request* req = malloc(sizeof(*req));
    char* line = malloc(1 << 20);
    uint8_t* block = malloc(1 << 20);
    if (!c || !req || !line || !block) return 2;
    req_conn_init(c, REQ_PROTO_HTTP2);

    int rc = 0, block_no = 0;
    while (fgets(line, 1 << 20, stdin)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        if (n == 0 || line[0] == '#') continue;

        if (strncmp(line, "table ", 6) == 0) {
            unsigned long v = strtoul(line + 6, NULL, 10);
            int r = hpack_decoder_set_allowed_table_size(&c->hpack, (uint32_t)v);
            printf("table max=%lu accepted=%d\n", v, r == HPACK_OK ? 1 : 0);
            if (r != HPACK_OK) {
                printf("result=%s\n", err_name(hpack_req_err(r)));
                rc = 1;
                break;
            }
            continue;
        }

        if (strncmp(line, "block ", 6) == 0) {
            size_t bn = 0;
            int hi = -1;
            int ok = 1;
            for (const char* p = line + 6; *p; p++) {
                int v = hexval(*p);
                if (v < 0) { ok = 0; break; }
                if (hi < 0) hi = v;
                else { block[bn++] = (uint8_t)((hi << 4) | v); hi = -1; }
            }
            if (!ok || hi >= 0) { fprintf(stderr, "bad hex\n"); rc = 2; break; }
            printf("block %d\n", block_no++);
            ReqErr e = parse_h2_block(c, block, bn, req, trace_field, NULL);
            printf("result=%s\n", err_name(e));
            printf("table size=%u entries=%u max=%u\n",
                   hpack_dynamic_size(&c->hpack), hpack_dynamic_count(&c->hpack),
                   c->hpack.max_size);
            continue;
        }

        fprintf(stderr, "bad script line\n");
        rc = 2;
        break;
    }

    free(c);
    free(req);
    free(line);
    free(block);
    return rc;
}

int main(int argc, char** argv) {
    if (argc >= 2 && strcmp(argv[1], "bench") == 0) {
        unsigned n = argc >= 3 ? (unsigned)strtoul(argv[2], NULL, 10) : 10000;
        if (n == 0) n = 10000;
        return run_bench(n);
    }
    if (argc >= 2 && strcmp(argv[1], "h2trace") == 0) return run_trace();

    self_test_http1();
    self_test_hpack();
    self_test_h2_fields();
    check("bench_10000_streams", run_bench(10000) == 0);
    printf("all_ok=%d\n", failures == 0);
    return failures == 0 ? 0 : 1;
}
