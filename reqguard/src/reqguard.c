
/* reqguard: HTTP/1.1 request parsing hardened against request smuggling.
   Rejects CL+TE, duplicate Content-Length, obs-fold, control chars,
   over-long header lines and oversized buffers. */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define MAX_HEADERS 32
#define MAX_LINE 256
#define MAX_BUF 4096
#define MAX_TARGET 128

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
    REQ_ERR_TOO_MANY_HEADERS
} ReqErr;

typedef struct { char name[64]; char value[128]; } Header;

typedef struct {
    char method[16];
    char target[MAX_TARGET];
    char version[16];
    Header headers[MAX_HEADERS];
    int header_count;
    long content_length;   /* -1 when absent */
    int has_te;
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
    }
    return "?";
}

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

static int ci_starts(const char* s, const char* prefix) {
    while (*prefix) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix)) return 0;
        s++; prefix++;
    }
    return 1;
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

static ReqErr parse_request(const char* buf, size_t len, Request* req) {
    if (len > MAX_BUF) return REQ_ERR_TOO_LARGE;
    memset(req, 0, sizeof(*req));
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

        strncpy(req->headers[req->header_count].name, line, sizeof(req->headers[0].name) - 1);
        strncpy(req->headers[req->header_count].value, value, sizeof(req->headers[0].value) - 1);
        req->header_count++;
    }

    if (req->has_te && seen_cl) return REQ_ERR_CL_TE;
    return REQ_OK;
}

#ifdef SELF_TEST
static int failures = 0;
static void check(const char* name, int ok) {
    printf("%s=%d\n", name, ok ? 1 : 0);
    if (!ok) failures++;
}

static ReqErr parse_str(const char* s, Request* r) { return parse_request(s, strlen(s), r); }

int main(void) {
    Request r;

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

    printf("all_ok=%d\n", failures == 0);
    return failures == 0 ? 0 : 1;
}
#endif /* SELF_TEST */
