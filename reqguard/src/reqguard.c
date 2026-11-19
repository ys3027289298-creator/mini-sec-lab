
/* reqguard: HTTP/1.1 request parsing hardened against request smuggling.
   Rejects CL+TE, duplicate Content-Length, obs-fold, control chars,
   over-long header lines and oversized buffers.  Decodes chunked request
   bodies incrementally: hex chunk sizes, mandatory CRLF after chunk data,
   trailer headers, and loud rejection of malformed or oversized chunks. */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>

#define MAX_HEADERS 32
#define MAX_LINE 256
#define MAX_BUF 4096
#define MAX_TARGET 128
#define MAX_CHUNK_SIZE 4096        /* largest single chunk we accept */
#define MAX_BODY (4 * MAX_BUF)     /* decoded body kept in ChunkParser */

typedef enum {
    REQ_OK = 0,
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
    REQ_ERR_BAD_TE,
    REQ_ERR_BAD_CHUNK_SIZE,
    REQ_ERR_CHUNK_CRLF,
    REQ_ERR_CHUNK_TOO_LARGE,
    REQ_ERR_TRAILER
} ReqErr;

typedef struct { char name[64]; char value[128]; } Header;

typedef enum {
    CHUNK_STATE_SIZE = 0,   /* reading a chunk-size line */
    CHUNK_STATE_DATA,       /* copying chunk data */
    CHUNK_STATE_DATA_CRLF,  /* expecting CRLF after chunk data */
    CHUNK_STATE_TRAILER,    /* reading trailer-section lines */
    CHUNK_STATE_DONE,       /* terminal CRLF seen */
    CHUNK_STATE_ERROR
} ChunkState;

/* Incremental chunked decoder. The caller owns the state, so partial input
   may be fed across many calls; chunk_feed resumes exactly where it stopped
   and never discards a partially read size line or CRLF. */
typedef struct {
    ChunkState state;
    ReqErr error;
    unsigned long long chunk_size;
    unsigned long long remaining;
    int data_cr_seen;         /* DATA_CRLF: saw the CR, waiting for LF */
    int line_cr_seen;         /* SIZE/TRAILER: saw the CR, waiting for LF */
    size_t line_len;
    char line[MAX_LINE + 1];
    int chunk_count;          /* chunk-size lines seen, including last */
    char body[MAX_BODY];
    size_t body_len;
    int trailer_count;
    Header trailers[MAX_HEADERS];
} ChunkParser;

typedef struct {
    char method[16];
    char target[MAX_TARGET];
    char version[16];
    Header headers[MAX_HEADERS];
    int header_count;
    long content_length;   /* -1 when absent */
    int has_te;
    int is_chunked;        /* Transfer-Encoding is exactly "chunked" */
    ChunkParser chunk;     /* chunked body and its incremental state */
} Request;

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
    case REQ_ERR_BAD_TE: return "bad_transfer_encoding";
    case REQ_ERR_BAD_CHUNK_SIZE: return "bad_chunk_size";
    case REQ_ERR_CHUNK_CRLF: return "chunk_crlf";
    case REQ_ERR_CHUNK_TOO_LARGE: return "chunk_too_large";
    case REQ_ERR_TRAILER: return "bad_trailer";
    }
    return "?";
}

static int is_token_char(unsigned char c) {
    if (isalnum(c)) return 1;
    return strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int ci_equal_n(const char* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return 0;
    return 1;
}

static int ci_equal(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

static int ci_name_eq(const char* s, size_t n, const char* lit) {
    size_t m = strlen(lit);
    return n == m && ci_equal_n(s, lit, m);
}

/* ---- chunked-body parser (RFC 7230 section 4.1) ---- */

static void chunk_init(ChunkParser* cp) {
    memset(cp, 0, sizeof(*cp));
    cp->state = CHUNK_STATE_SIZE;
    cp->error = REQ_OK;
}

/* chunk-ext = *( ";" token [ "=" ( token / quoted-string ) ] ) */
static int valid_chunk_ext(const char* s, size_t n) {
    size_t i = 0;
    for (;;) {
        if (i >= n || s[i] != ';') return 0;
        i++;
        size_t t = i;
        while (i < n && is_token_char((unsigned char)s[i])) i++;
        if (i == t) return 0;
        if (i < n && s[i] == '=') {
            i++;
            if (i < n && s[i] == '"') {
                i++;
                for (;;) {
                    if (i >= n) return 0;
                    unsigned char c = (unsigned char)s[i];
                    if (c == '"') { i++; break; }
                    if (c == '\\') {
                        i++;
                        if (i >= n) return 0;
                        unsigned char e = (unsigned char)s[i];
                        if (!(e == '\t' || e == ' ' || (e >= 0x21 && e <= 0x7e) || e >= 0x80))
                            return 0;
                        i++;
                    } else if (c == '\t' || c == ' ' || c == 0x21 ||
                               (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e) || c >= 0x80) {
                        i++;
                    } else {
                        return 0;
                    }
                }
            } else {
                size_t v = i;
                while (i < n && is_token_char((unsigned char)s[i])) i++;
                if (i == v) return 0;
            }
        }
        if (i >= n) return 1;
        if (s[i] != ';') return 0;
    }
}

/* Accumulate one CRLF-terminated line from data[*i..len).  Returns 1 when a
   line is complete (cp->line/cp->line_len), 0 when more input is needed, or
   -1 with cp->error set when the terminator is malformed. */
static int chunk_take_line(ChunkParser* cp, const char* data, size_t len,
                           size_t* i, ReqErr on_bad_terminator) {
    while (*i < len) {
        unsigned char c = (unsigned char)data[(*i)++];
        if (cp->line_cr_seen) {
            if (c != '\n') { cp->error = on_bad_terminator; return -1; }
            cp->line_cr_seen = 0;
            cp->line[cp->line_len] = 0;
            return 1;
        }
        if (c == '\r') { cp->line_cr_seen = 1; continue; }
        if (c == '\n') { cp->error = on_bad_terminator; return -1; }
        if (cp->line_len >= MAX_LINE) { cp->error = REQ_ERR_LINE_TOO_LONG; return -1; }
        cp->line[cp->line_len++] = (char)c;
    }
    return 0;
}

/* Parse 1*HEXDIG at the start of s[0..n); returns -1 if there is no digit or
   the value overflows 64 bits.  *used receives the digit count. */
static int parse_hex_size(const char* s, size_t n, size_t* used, unsigned long long* out) {
    unsigned long long v = 0;
    size_t i = 0;
    while (i < n) {
        int d = hexval(s[i]);
        if (d < 0) break;
        if (v > (ULLONG_MAX - (unsigned long long)d) / 16) return -1;
        v = v * 16 + (unsigned long long)d;
        i++;
    }
    if (i == 0) return -1;
    *used = i;
    *out = v;
    return 0;
}

static ReqErr chunk_parse_size_line(ChunkParser* cp) {
    size_t used = 0;
    unsigned long long v = 0;
    if (parse_hex_size(cp->line, cp->line_len, &used, &v) < 0)
        return REQ_ERR_BAD_CHUNK_SIZE;
    if (used < cp->line_len) {
        if (cp->line[used] != ';') return REQ_ERR_BAD_CHUNK_SIZE;
        if (!valid_chunk_ext(cp->line + used, cp->line_len - used))
            return REQ_ERR_BAD_CHUNK_SIZE;
    }

    cp->chunk_size = v;
    cp->chunk_count++;
    if (v == 0) {
        cp->state = CHUNK_STATE_TRAILER;
        return REQ_OK;
    }
    /* Refuse an oversized chunk outright; never read and truncate it. */
    if (v > MAX_CHUNK_SIZE) return REQ_ERR_CHUNK_TOO_LARGE;
    if (v > (unsigned long long)(MAX_BODY - cp->body_len)) return REQ_ERR_TOO_LARGE;
    cp->remaining = v;
    cp->state = CHUNK_STATE_DATA;
    return REQ_OK;
}

static ReqErr chunk_parse_trailer_line(ChunkParser* cp) {
    const char* line = cp->line;
    size_t n = cp->line_len;

    if (n == 0) { cp->state = CHUNK_STATE_DONE; return REQ_OK; }
    if (line[0] == ' ' || line[0] == '\t') return REQ_ERR_TRAILER; /* obs-fold */

    size_t colon = n;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)line[i];
        if (c == ':') { colon = i; break; }
        if (c < 0x20 || c == 0x7f || !is_token_char(c)) return REQ_ERR_TRAILER;
    }
    if (colon == 0 || colon == n) return REQ_ERR_TRAILER;

    size_t vs = colon + 1, ve = n;
    while (vs < ve && (line[vs] == ' ' || line[vs] == '\t')) vs++;
    while (ve > vs && (line[ve - 1] == ' ' || line[ve - 1] == '\t')) ve--;
    for (size_t i = vs; i < ve; i++) {
        unsigned char c = (unsigned char)line[i];
        if (c == 0x7f || (c < 0x20 && c != '\t')) return REQ_ERR_TRAILER;
    }

    /* A sender MUST NOT generate framing headers in the trailer section. */
    if (ci_name_eq(line, colon, "Transfer-Encoding") ||
        ci_name_eq(line, colon, "Content-Length"))
        return REQ_ERR_TRAILER;

    if (cp->trailer_count >= MAX_HEADERS) return REQ_ERR_TOO_MANY_HEADERS;
    if (colon >= sizeof(cp->trailers[0].name)) return REQ_ERR_TRAILER;
    if (ve - vs >= sizeof(cp->trailers[0].value)) return REQ_ERR_TRAILER;

    Header* h = &cp->trailers[cp->trailer_count];
    memcpy(h->name, line, colon);
    h->name[colon] = 0;
    memcpy(h->value, line + vs, ve - vs);
    h->value[ve - vs] = 0;
    cp->trailer_count++;
    return REQ_OK;
}

/* Feed len bytes.  *consumed receives how many bytes were examined; bytes
   after the terminal CRLF are left unconsumed so a pipelined request can be
   parsed next.  Returns REQ_OK while the body is merely incomplete; once an
   error is latched it is returned by every subsequent call. */
static ReqErr chunk_feed(ChunkParser* cp, const char* data, size_t len, size_t* consumed) {
    size_t i = 0;

    if (cp->state == CHUNK_STATE_ERROR) {
        if (consumed) *consumed = 0;
        return cp->error;
    }

    while (i < len && cp->state != CHUNK_STATE_DONE) {
        switch (cp->state) {
        case CHUNK_STATE_SIZE: {
            int r = chunk_take_line(cp, data, len, &i, REQ_ERR_BAD_CHUNK_SIZE);
            if (r < 0) goto error;
            if (r == 0) goto out;
            ReqErr e = chunk_parse_size_line(cp);
            cp->line_len = 0;
            if (e != REQ_OK) { cp->error = e; goto error; }
            break;
        }
        case CHUNK_STATE_DATA: {
            size_t avail = len - i;
            size_t take = cp->remaining < avail ? (size_t)cp->remaining : avail;
            /* body_len + chunk_size was bounded when the size line was parsed */
            memcpy(cp->body + cp->body_len, data + i, take);
            cp->body_len += take;
            cp->remaining -= take;
            i += take;
            if (cp->remaining == 0) {
                cp->state = CHUNK_STATE_DATA_CRLF;
                cp->data_cr_seen = 0;
            }
            break;
        }
        case CHUNK_STATE_DATA_CRLF: {
            unsigned char c = (unsigned char)data[i++];
            if (!cp->data_cr_seen) {
                if (c != '\r') { cp->error = REQ_ERR_CHUNK_CRLF; goto error; }
                cp->data_cr_seen = 1;
            } else {
                if (c != '\n') { cp->error = REQ_ERR_CHUNK_CRLF; goto error; }
                cp->data_cr_seen = 0;
                cp->state = CHUNK_STATE_SIZE;
                cp->line_len = 0;
            }
            break;
        }
        case CHUNK_STATE_TRAILER: {
            int r = chunk_take_line(cp, data, len, &i, REQ_ERR_TRAILER);
            if (r < 0) goto error;
            if (r == 0) goto out;
            ReqErr e = chunk_parse_trailer_line(cp);
            cp->line_len = 0;
            if (e != REQ_OK) { cp->error = e; goto error; }
            break;
        }
        case CHUNK_STATE_DONE:
        case CHUNK_STATE_ERROR:
            break;
        }
    }

out:
    if (consumed) *consumed = i;
    return REQ_OK;

error:
    cp->state = CHUNK_STATE_ERROR;
    if (consumed) *consumed = i;
    return cp->error;
}

static int chunk_done(const ChunkParser* cp) {
    return cp->state == CHUNK_STATE_DONE;
}

/* ---- request-line / header parsing ---- */

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

/* End of the header section (index just past CRLFCRLF), or len if absent.
   Control-byte checks apply only here: a chunked body may be binary. */
static size_t header_span(const char* buf, size_t len) {
    for (size_t i = 0; i + 3 < len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return i + 4;
    return len;
}

/* Only "chunked", exactly once, is accepted: any other or repeated coding
   makes the message length ambiguous, which is how smuggling starts. */
static ReqErr check_te_value(const char* value, int* chunked_seen) {
    const char* p = value;
    for (;;) {
        while (*p == ' ' || *p == '\t') p++;
        const char* start = p;
        while (*p && *p != ',') p++;
        const char* end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
        if (end == start) return REQ_ERR_BAD_TE;
        if (end - start != 7 || !ci_equal_n(start, "chunked", 7)) return REQ_ERR_BAD_TE;
        if (*chunked_seen) return REQ_ERR_BAD_TE;
        *chunked_seen = 1;
        if (*p == ',') { p++; continue; }
        break;
    }
    return REQ_OK;
}

static ReqErr parse_request(const char* buf, size_t len, Request* req) {
    memset(req, 0, sizeof(*req));
    req->content_length = -1;

    size_t hspan = header_span(buf, len);
    /* The header section is bounded by MAX_BUF.  A chunked body may exceed it
       (up to MAX_BODY), but an unterminated section is still "too large". */
    if (hspan > MAX_BUF || (len > MAX_BUF && hspan == len)) return REQ_ERR_TOO_LARGE;
    for (size_t i = 0; i < hspan; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == 0 || (c < 0x20 && c != '\r' && c != '\n' && c != '\t'))
            return REQ_ERR_CONTROL;
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
    int te_chunked = 0;
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
            ReqErr te = check_te_value(value, &te_chunked);
            if (te != REQ_OK) return te;
        }

        strncpy(req->headers[req->header_count].name, line, sizeof(req->headers[0].name) - 1);
        strncpy(req->headers[req->header_count].value, value, sizeof(req->headers[0].value) - 1);
        req->header_count++;
    }

    if (req->has_te && seen_cl) return REQ_ERR_CL_TE;
    if (req->has_te) req->is_chunked = 1;

    if (!req->is_chunked) {
        /* No chunked body to decode: keep the original strictness and treat
           every byte after the header section as data we will not accept. */
        for (size_t i = hspan; i < len; i++) {
            unsigned char c = (unsigned char)buf[i];
            if (c == 0 || (c < 0x20 && c != '\r' && c != '\n' && c != '\t'))
                return REQ_ERR_CONTROL;
        }
        if (len > MAX_BUF) return REQ_ERR_TOO_LARGE;
    }

    if (req->is_chunked) {
        chunk_init(&req->chunk);
        size_t used = 0;
        ReqErr ce = chunk_feed(&req->chunk, buf + pos, len - pos, &used);
        if (ce != REQ_OK) return ce;
    }
    return REQ_OK;
}

/* ---- self-tests ---- */

static int failures = 0;
static void check(const char* name, int ok) {
    printf("%s=%d\n", name, ok ? 1 : 0);
    if (!ok) failures++;
}

static ReqErr parse_str(const char* s, Request* r) { return parse_request(s, strlen(s), r); }

static ReqErr chunk_feed_str(ChunkParser* cp, const char* s, size_t n) {
    size_t used = 0;
    return chunk_feed(cp, s, n, &used);
}

static ReqErr chunk_parse_str(const char* s, ChunkParser* cp) {
    chunk_init(cp);
    return chunk_feed_str(cp, s, strlen(s));
}

static int body_is(const ChunkParser* cp, const char* s) {
    size_t n = strlen(s);
    return cp->body_len == n && memcmp(cp->body, s, n) == 0;
}

/* Feeding the same bytes one at a time must reach the identical state. */
static int incremental_matches(const char* s, size_t n) {
    ChunkParser whole, inc;
    chunk_init(&whole);
    chunk_init(&inc);
    ReqErr rw = chunk_feed_str(&whole, s, n);
    ReqErr ri = REQ_OK;
    size_t total = 0;
    while (total < n && ri == REQ_OK && !chunk_done(&inc)) {
        size_t used = 0;
        ri = chunk_feed(&inc, s + total, 1, &used);
        total += used;
        if (ri == REQ_OK && used != 1 && !chunk_done(&inc)) return 0;
    }
    return rw == ri && whole.state == inc.state &&
           whole.chunk_count == inc.chunk_count &&
           whole.trailer_count == inc.trailer_count &&
           whole.body_len == inc.body_len &&
           memcmp(whole.body, inc.body, whole.body_len) == 0;
}

static int run_selftests(void) {
    Request r;
    ChunkParser cp;

    check("simple_ok", parse_str("GET /a HTTP/1.1\r\nHost: x\r\n\r\n", &r) == REQ_OK && r.header_count == 1);
    check("post_cl_ok", parse_str("POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\n", &r) == REQ_OK && r.content_length == 5);
    check("te_ok", parse_str("POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", &r) == REQ_OK && r.has_te);
    check("dup_cl_rejected", parse_str("POST /a HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", &r) == REQ_ERR_DUP_CL);
    check("cl_te_rejected", parse_str("POST /a HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", &r) == REQ_ERR_CL_TE);
    check("obs_fold_rejected", parse_str("GET /a HTTP/1.1\r\nX: a\r\n b\r\n\r\n", &r) == REQ_ERR_OBS_FOLD);
    check("bad_cl_rejected", parse_str("POST /a HTTP/1.1\r\nContent-Length: -1\r\n\r\n", &r) == REQ_ERR_BAD_CL);
    check("bad_version", parse_str("GET /a HTTP/2.0\r\n\r\n", &r) == REQ_ERR_VERSION);
    check("bad_target", parse_str("GET a HTTP/1.1\r\n\r\n", &r) == REQ_ERR_TARGET);
    check("control_rejected", parse_str("GET /a\x01 HTTP/1.1\r\n\r\n", &r) == REQ_ERR_CONTROL);
    check("no_colon", parse_str("GET /a HTTP/1.1\r\nBadHeader\r\n\r\n", &r) == REQ_ERR_HEADER_SYNTAX);

    char big[MAX_BUF + 2];
    memset(big, 'A', sizeof(big));
    big[sizeof(big) - 1] = 0;
    check("too_large", parse_str(big, &r) == REQ_ERR_TOO_LARGE);

    /* --- twenty chunked-body vectors; the same cases are mirrored by
           tests/ref_chunked.py and compared by tests/crosscheck.py --- */
    check("chunk_simple", chunk_parse_str("5\r\nhello\r\n0\r\n\r\n", &cp) == REQ_OK &&
          chunk_done(&cp) && cp.chunk_count == 2 && body_is(&cp, "hello"));
    check("chunk_multi", chunk_parse_str("1\r\na\r\n1\r\nb\r\n0\r\n\r\n", &cp) == REQ_OK &&
          chunk_done(&cp) && cp.chunk_count == 3 && body_is(&cp, "ab"));
    check("chunk_empty", chunk_parse_str("0\r\n\r\n", &cp) == REQ_OK &&
          chunk_done(&cp) && cp.chunk_count == 1 && cp.body_len == 0);
    check("chunk_upper_hex", chunk_parse_str("A\r\n0123456789\r\n0\r\n\r\n", &cp) == REQ_OK &&
          chunk_done(&cp) && body_is(&cp, "0123456789"));
    check("chunk_lower_hex", chunk_parse_str("a\r\n0123456789\r\n0\r\n\r\n", &cp) == REQ_OK &&
          chunk_done(&cp) && body_is(&cp, "0123456789"));
    check("chunk_leading_zero", chunk_parse_str("03\r\nabc\r\n0\r\n\r\n", &cp) == REQ_OK &&
          chunk_done(&cp) && body_is(&cp, "abc"));
    check("chunk_ext_value", chunk_parse_str("5;foo=bar\r\nhello\r\n0\r\n\r\n", &cp) == REQ_OK &&
          chunk_done(&cp) && body_is(&cp, "hello"));
    check("chunk_ext_bare", chunk_parse_str("5;ext\r\nhello\r\n0\r\n\r\n", &cp) == REQ_OK &&
          chunk_done(&cp) && body_is(&cp, "hello"));
    check("chunk_ext_quoted", chunk_parse_str("5;q=\"a b\"\r\nhello\r\n0\r\n\r\n", &cp) == REQ_OK &&
          chunk_done(&cp) && body_is(&cp, "hello"));
    check("chunk_ext_empty", chunk_parse_str("5;\r\nhello\r\n0\r\n\r\n", &cp) == REQ_ERR_BAD_CHUNK_SIZE);
    check("chunk_ext_bad_quote", chunk_parse_str("5;q=\"a\r\nhello\r\n0\r\n\r\n", &cp) == REQ_ERR_BAD_CHUNK_SIZE);
    check("chunk_one_trailer", chunk_parse_str("5\r\nhello\r\n0\r\nX-T: v\r\n\r\n", &cp) == REQ_OK &&
          chunk_done(&cp) && cp.trailer_count == 1 && strcmp(cp.trailers[0].name, "X-T") == 0 &&
          strcmp(cp.trailers[0].value, "v") == 0);
    check("chunk_two_trailers", chunk_parse_str("5\r\nhello\r\n0\r\nX-T: v\r\nX-U: w\r\n\r\n", &cp) == REQ_OK &&
          chunk_done(&cp) && cp.trailer_count == 2);
    check("chunk_trailer_cl", chunk_parse_str("5\r\nhello\r\n0\r\nContent-Length: 3\r\n\r\n", &cp) == REQ_ERR_TRAILER);
    check("chunk_trailer_obsfold", chunk_parse_str("5\r\nhello\r\n0\r\nX-T: a\r\n b\r\n\r\n", &cp) == REQ_ERR_TRAILER);
    check("chunk_trailer_nocolon", chunk_parse_str("5\r\nhello\r\n0\r\nNoColon\r\n\r\n", &cp) == REQ_ERR_TRAILER);
    check("chunk_bad_hex", chunk_parse_str("g\r\nhello\r\n0\r\n\r\n", &cp) == REQ_ERR_BAD_CHUNK_SIZE);
    check("chunk_missing_crlf", chunk_parse_str("5\r\nhelloX\r\n0\r\n\r\n", &cp) == REQ_ERR_CHUNK_CRLF);
    check("chunk_bare_lf", chunk_parse_str("5\r\nhello\n0\r\n\r\n", &cp) == REQ_ERR_CHUNK_CRLF);
    check("chunk_incomplete", chunk_parse_str("5\r\nhello\r\n", &cp) == REQ_OK &&
          !chunk_done(&cp) && body_is(&cp, "hello"));
    check("chunk_oversized", chunk_parse_str("1001\r\n", &cp) == REQ_ERR_CHUNK_TOO_LARGE);
    check("chunk_hex_overflow", chunk_parse_str("FFFFFFFFFFFFFFFFF\r\n", &cp) == REQ_ERR_BAD_CHUNK_SIZE);

    /* --- edge cases beyond the reference set --- */
    check("chunk_leading_space", chunk_parse_str(" 5\r\nhello\r\n0\r\n\r\n", &cp) == REQ_ERR_BAD_CHUNK_SIZE);
    check("chunk_0x_prefix", chunk_parse_str("0x5\r\nhello\r\n0\r\n\r\n", &cp) == REQ_ERR_BAD_CHUNK_SIZE);
    check("chunk_plus_sign", chunk_parse_str("+5\r\nhello\r\n0\r\n\r\n", &cp) == REQ_ERR_BAD_CHUNK_SIZE);
    check("chunk_dup_last", chunk_parse_str("0\r\n0\r\n\r\n", &cp) == REQ_ERR_TRAILER);

    {
        /* four full chunks fill MAX_BODY; the fifth must be refused whole */
        char many[4 * (MAX_CHUNK_SIZE + 8) + 8];
        size_t n = 0;
        for (int k = 0; k < 4; k++) {
            n += (size_t)snprintf(many + n, sizeof(many) - n, "1000\r\n");
            memset(many + n, 'x', MAX_CHUNK_SIZE);
            n += MAX_CHUNK_SIZE;
            n += (size_t)snprintf(many + n, sizeof(many) - n, "\r\n");
        }
        n += (size_t)snprintf(many + n, sizeof(many) - n, "1000\r\n");
        chunk_init(&cp);
        check("chunk_total_limit", chunk_feed_str(&cp, many, n) == REQ_ERR_TOO_LARGE &&
              cp.body_len == MAX_BODY);
    }

    {
        /* bytes after the terminal CRLF stay unconsumed for the next request */
        static const char pipelined[] = "0\r\n\r\nGET /next HTTP/1.1\r\n\r\n";
        chunk_init(&cp);
        size_t used = 0;
        ReqErr e = chunk_feed(&cp, pipelined, sizeof(pipelined) - 1, &used);
        check("chunk_pipelined_leftover", e == REQ_OK && chunk_done(&cp) && used == 5);
    }

    {
        /* the decoder state lives in Request: parse what arrived, then feed
           the remaining body bytes on a later call without reparsing headers */
        const char head[] = "POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        const char rest[] = "lo\r\n0\r\n\r\n";
        ReqErr e = parse_str(head, &r);
        size_t used = 0;
        check("req_chunked_resume_before", e == REQ_OK && r.is_chunked &&
              !chunk_done(&r.chunk) && body_is(&r.chunk, "hel"));
        e = chunk_feed(&r.chunk, rest, sizeof(rest) - 1, &used);
        check("req_chunked_resume_after", e == REQ_OK && chunk_done(&r.chunk) &&
              body_is(&r.chunk, "hello") && used == sizeof(rest) - 1);
    }

    check("incremental_valid",
          incremental_matches("5\r\nhello\r\n0\r\nX-T: v\r\n\r\n",
                              strlen("5\r\nhello\r\n0\r\nX-T: v\r\n\r\n")));
    check("incremental_error",
          incremental_matches("5\r\nhelloX\r\n0\r\n\r\n", strlen("5\r\nhelloX\r\n0\r\n\r\n")));

    /* --- chunked requests through the header parser --- */
    check("req_chunked_ok", parse_str("POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                                      "5\r\nhello\r\n0\r\n\r\n", &r) == REQ_OK &&
          r.is_chunked && chunk_done(&r.chunk) && body_is(&r.chunk, "hello"));
    check("req_chunked_bad", parse_str("POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                                       "z\r\n", &r) == REQ_ERR_BAD_CHUNK_SIZE);
    check("req_te_gzip", parse_str("POST /a HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n", &r) == REQ_ERR_BAD_TE);
    check("req_te_not_last", parse_str("POST /a HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", &r) == REQ_ERR_BAD_TE);
    check("req_te_duplicate", parse_str("POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n"
                                        "Transfer-Encoding: chunked\r\n\r\n", &r) == REQ_ERR_BAD_TE);
    check("req_chunked_incomplete", parse_str("POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                                              "5\r\nhel", &r) == REQ_OK &&
          !chunk_done(&r.chunk) && body_is(&r.chunk, "hel"));

    printf("all_ok=%d\n", failures == 0);
    return failures == 0 ? 0 : 1;
}

/* ---- decode CLI, used by tests/crosscheck.py ---- */

static int hex_decode(const char* in, size_t n, unsigned char* out, size_t cap, size_t* out_len) {
    size_t o = 0;
    int hi = -1;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)in[i];
        if (isspace(c)) continue;
        int v = hexval((char)c);
        if (v < 0) return 0;
        if (hi < 0) { hi = v; continue; }
        if (o >= cap) return 0;
        out[o++] = (unsigned char)((hi << 4) | v);
        hi = -1;
    }
    if (hi >= 0) return 0;
    *out_len = o;
    return 1;
}

static int run_decode(int split) {
    size_t cap = 1 << 20;
    char* hex = malloc(cap);
    if (!hex) return 2;
    size_t n = fread(hex, 1, cap, stdin);
    if (n == cap) { free(hex); fprintf(stderr, "input too large\n"); return 2; }

    size_t rawcap = n / 2 + 1;
    unsigned char* raw = malloc(rawcap);
    if (!raw) { free(hex); return 2; }
    size_t rawlen = 0;
    if (!hex_decode(hex, n, raw, rawcap, &rawlen)) {
        free(hex); free(raw);
        fprintf(stderr, "invalid hex input\n");
        return 2;
    }
    free(hex);

    ChunkParser cp;
    chunk_init(&cp);
    size_t off = 0, consumed_total = 0;
    ReqErr e = REQ_OK;
    while (off < rawlen && e == REQ_OK && !chunk_done(&cp)) {
        size_t chunk = rawlen - off;
        if (split > 0 && chunk > (size_t)split) chunk = (size_t)split;
        size_t used = 0;
        e = chunk_feed(&cp, (const char*)raw + off, chunk, &used);
        off += used;
        consumed_total += used;
        if (used == 0) break;
    }
    free(raw);

    printf("status=%s\n", err_name(e));
    printf("done=%d\n", chunk_done(&cp) ? 1 : 0);
    printf("chunks=%d\n", cp.chunk_count);
    printf("trailers=%d\n", cp.trailer_count);
    printf("body_len=%zu\n", cp.body_len);
    printf("consumed=%zu\n", consumed_total);
    printf("body_hex=");
    for (size_t i = 0; i < cp.body_len; i++) printf("%02x", (unsigned char)cp.body[i]);
    printf("\n");
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 1) return run_selftests();
    if (strcmp(argv[1], "--decode") == 0) {
        int split = 0;
        for (int i = 2; i < argc; i++) {
            if (strncmp(argv[i], "--split=", 8) == 0) split = atoi(argv[i] + 8);
        }
        return run_decode(split);
    }
    fprintf(stderr, "usage: %s [--decode [--split=N]]\n", argv[0]);
    return 2;
}
