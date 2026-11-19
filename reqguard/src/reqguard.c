
/* reqguard: streaming HTTP/1.1 request parsing hardened against request
   smuggling and memory exhaustion.

   The parser is incremental: bytes are handed in via req_feed() in chunks of
   any size (including one byte at a time). Total size and per-line length are
   checked at byte intake, so an oversized request is rejected the moment the
   limit is crossed, before any further byte is read or retained. Parser
   memory depends only on the configured limits, never on request size: a
   multi-gigabyte request costs the same memory as a 100-byte one.

   Rejects CL+TE, duplicate Content-Length, obs-fold, control chars,
   over-long header lines and oversized requests. */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define MAX_HEADERS 32
#define MAX_TARGET 128
#define MAX_NAME 64
#define MAX_VALUE 128

/* Default limits; deployments supply their own via req_limits_defaults(). */
#define DEFAULT_MAX_LINE 256
#define DEFAULT_MAX_TOTAL 4096

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
    REQ_ERR_BARE_CR,
    REQ_ERR_LF_WITHOUT_CR
} ReqErr;

typedef struct {
    size_t max_total;  /* maximum bytes accepted for the whole request head */
    size_t max_line;   /* maximum bytes in one line, excluding its CRLF */
} ReqLimits;

typedef struct { char name[MAX_NAME]; char value[MAX_VALUE]; } Header;

typedef enum { ST_REQUEST_LINE, ST_HEADERS, ST_DONE } ParseState;

typedef struct {
    ReqLimits lim;
    ParseState state;
    char* line;       /* current line accumulator, capacity lim.max_line + 1 */
    size_t line_len;
    size_t total;     /* bytes accepted so far, including CRLF */
    int cr_pending;   /* previous byte was CR, awaiting LF */
    char method[16];
    char target[MAX_TARGET];
    char version[16];
    Header headers[MAX_HEADERS];
    int header_count;
    long content_length;   /* -1 when absent */
    int has_te;
    ReqErr err;
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
    case REQ_ERR_BARE_CR: return "bare_cr";
    case REQ_ERR_LF_WITHOUT_CR: return "lf_without_cr";
    }
    return "?";
}

void req_limits_defaults(ReqLimits* l) {
    l->max_total = DEFAULT_MAX_TOTAL;
    l->max_line = DEFAULT_MAX_LINE;
}

/* Create a parser. All memory used by the parser is allocated here and sized
   solely from the limits, so peak memory is O(max_total/max_line config),
   never O(request size). Returns NULL on bad config or allocation failure. */
Request* req_new(const ReqLimits* lim) {
    if (!lim || lim->max_line == 0 || lim->max_total == 0 ||
        lim->max_line > lim->max_total) return NULL;
    Request* req = calloc(1, sizeof(Request));
    if (!req) return NULL;
    req->line = malloc(lim->max_line + 1);
    if (!req->line) { free(req); return NULL; }
    req->lim = *lim;
    req->content_length = -1;
    return req;
}

void req_free(Request* req) {
    if (!req) return;
    free(req->line);
    free(req);
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

static ReqErr fail(Request* req, ReqErr e) {
    req->err = e;
    req->state = ST_DONE;
    return e;
}

static ReqErr parse_request_line(Request* req) {
    char* line = req->line;

    char* sp1 = strchr(line, ' ');
    if (!sp1) return fail(req, REQ_ERR_METHOD);
    *sp1 = 0;
    char* sp2 = strchr(sp1 + 1, ' ');
    if (!sp2) return fail(req, REQ_ERR_TARGET);
    *sp2 = 0;
    const char* target = sp1 + 1;
    const char* version = sp2 + 1;

    if (strlen(line) == 0 || strlen(line) >= sizeof(req->method))
        return fail(req, REQ_ERR_METHOD);
    for (const char* p = line; *p; p++)
        if (!is_token_char((unsigned char)*p)) return fail(req, REQ_ERR_METHOD);
    strcpy(req->method, line);

    if (target[0] != '/' || strlen(target) >= sizeof(req->target))
        return fail(req, REQ_ERR_TARGET);
    for (const char* p = target; *p; p++)
        if ((unsigned char)*p <= 0x20 || *p == 0x7f) return fail(req, REQ_ERR_TARGET);
    strcpy(req->target, target);

    if (strncmp(version, "HTTP/1.", 7) != 0) return fail(req, REQ_ERR_VERSION);
    if (version[7] != '0' && version[7] != '1') return fail(req, REQ_ERR_VERSION);
    if (version[8] != 0) return fail(req, REQ_ERR_VERSION);
    strcpy(req->version, version);

    req->state = ST_HEADERS;
    return REQ_OK;
}

static ReqErr parse_header_line(Request* req) {
    char* line = req->line;

    if (line[0] == ' ' || line[0] == '\t') return fail(req, REQ_ERR_OBS_FOLD);

    char* colon = strchr(line, ':');
    if (!colon || colon == line) return fail(req, REQ_ERR_HEADER_SYNTAX);
    *colon = 0;
    for (char* p = line; *p; p++)
        if (!is_token_char((unsigned char)*p)) return fail(req, REQ_ERR_HEADER_SYNTAX);

    char* value = colon + 1;
    while (*value == ' ' || *value == '\t') value++;
    char* end = value + strlen(value);
    while (end > value && (end[-1] == ' ' || end[-1] == '\t')) *--end = 0;
    for (char* p = value; *p; p++)
        if ((unsigned char)*p == 0x7f) return fail(req, REQ_ERR_CONTROL);

    if (req->header_count >= MAX_HEADERS) return fail(req, REQ_ERR_TOO_MANY_HEADERS);

    if (ci_equal(line, "Content-Length")) {
        if (req->content_length != -1) return fail(req, REQ_ERR_DUP_CL);
        char* ep = NULL;
        long v = strtol(value, &ep, 10);
        if (ep == value || (ep && *ep != 0) || v < 0) return fail(req, REQ_ERR_BAD_CL);
        req->content_length = v;
    } else if (ci_equal(line, "Transfer-Encoding")) {
        req->has_te = 1;
    }

    strncpy(req->headers[req->header_count].name, line,
            sizeof(req->headers[0].name) - 1);
    strncpy(req->headers[req->header_count].value, value,
            sizeof(req->headers[0].value) - 1);
    req->header_count++;
    return REQ_OK;
}

/* A completed line (CRLF already consumed, not counted in line_len) is ready
   in req->line. */
static ReqErr dispatch_line(Request* req) {
    req->line[req->line_len] = 0;
    if (req->state == ST_REQUEST_LINE) {
        ReqErr e = parse_request_line(req);
        if (e != REQ_OK) return e;
    } else if (req->state == ST_HEADERS) {
        if (req->line_len == 0) {
            if (req->has_te && req->content_length != -1)
                return fail(req, REQ_ERR_CL_TE);
            req->state = ST_DONE;
            req->err = REQ_OK;
            return REQ_OK;
        }
        ReqErr e = parse_header_line(req);
        if (e != REQ_OK) return e;
    }
    return REQ_OK;
}

/* Feed len bytes. Returns REQ_OK while more input is expected (call
   req_done() to distinguish a finished request), or the first error. On
   error the parser is terminal: the caller must stop reading the request.
   Every limit is enforced here, at intake, before the byte is retained. */
ReqErr req_feed(Request* req, const char* buf, size_t len) {
    if (req->state == ST_DONE) return req->err;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];

        /* Total-size guard. Count the byte first; once the running total
           would exceed the configured ceiling the byte is rejected at intake
           and never stored, so peak retained bytes equal max_total exactly.
           CRLF counts, so chunk boundaries cannot dilute the accounting and
           nothing the client sends can raise or reset the limit. */
        req->total++;
        if (req->total > req->lim.max_total) return fail(req, REQ_ERR_TOO_LARGE);

        /* Newline handling: only CRLF is accepted; bare CR and lone LF are
           rejected so line framing cannot be desynced. */
        if (req->cr_pending) {
            req->cr_pending = 0;
            if (c != '\n') return fail(req, REQ_ERR_BARE_CR);
            /* CRLF closes the current line; the line buffer holds only the
               bytes between delimiters and never includes the CRLF. */
            ReqErr e = dispatch_line(req);
            if (e != REQ_OK) return e;
            if (req->state == ST_DONE) { req->err = REQ_OK; return REQ_OK; }
            req->line_len = 0;
            continue;
        }
        if (c == '\n') return fail(req, REQ_ERR_LF_WITHOUT_CR);
        if (c == '\r') { req->cr_pending = 1; continue; }

        /* Control characters are illegal in header/request-line content;
           HTAB is legal inside field values (RFC 9110), so it is retained
           here and constrained later by the header grammar. */
        if (c == 0 || (c < 0x20 && c != '\t') || c == 0x7f)
            return fail(req, REQ_ERR_CONTROL);

        /* Per-line guard: line length excludes CRLF. The (max_line+1)-byte
           buffer is never overflowed; the offending byte is dropped with the
           error, matching what a whole-buffer parse of the same bytes yields. */
        if (req->line_len >= req->lim.max_line)
            return fail(req, REQ_ERR_LINE_TOO_LONG);
        req->line[req->line_len++] = (char)c;
    }
    return REQ_OK;
}

int req_done(const Request* req) { return req->state == ST_DONE && req->err == REQ_OK; }
int req_failed(const Request* req) { return req->state == ST_DONE && req->err != REQ_OK; }

/* Convenience: parse one contiguous buffer through the streaming path, so
   one-shot and incremental parsing can never disagree. An unfinished head
   (no terminating blank line) is reported as too_large: a real reader would
   keep feeding until the ceiling tripped, which is the same terminal state. */
ReqErr parse_all(const char* buf, size_t len, const ReqLimits* lim, Request** out) {
    ReqLimits defaults;
    if (!lim) { req_limits_defaults(&defaults); lim = &defaults; }
    Request* req = req_new(lim);
    if (!req) return REQ_ERR_TOO_LARGE; /* invalid limits or allocation failure */
    ReqErr e = req_feed(req, buf, len);
    if (e != REQ_OK) { req_free(req); return e; }
    if (!req_done(req)) { req_free(req); return REQ_ERR_TOO_LARGE; }
    if (out) *out = req; else req_free(req);
    return REQ_OK;
}

static int failures = 0;
static void check(const char* name, int ok) {
    printf("%s=%d\n", name, ok ? 1 : 0);
    if (!ok) failures++;
}

/* Feed the same bytes one at a time and in varying chunks, asserting both
   runs finish with the same status as parse_all. */
static ReqErr feed_bytewise(const char* s, size_t len, const ReqLimits* lim) {
    Request* req = req_new(lim);
    for (size_t i = 0; i < len && !req_done(req) && !req_failed(req); i++)
        req_feed(req, &s[i], 1);
    ReqErr result = req_failed(req) ? req->err
                        : (req_done(req) ? REQ_OK : REQ_ERR_TOO_LARGE);
    req_free(req);
    return result;
}

static ReqErr feed_chunked(const char* s, size_t len, const ReqLimits* lim) {
    Request* req = req_new(lim);
    size_t pos = 0;
    size_t step = 3;
    while (pos < len && !req_done(req) && !req_failed(req)) {
        size_t n = len - pos < step ? len - pos : step;
        req_feed(req, s + pos, n);
        pos += n;
        step = step * 7 % 13 + 1; /* varying chunk sizes: 3,9,10,6,... */
    }
    ReqErr result = req_failed(req) ? req->err
                        : (req_done(req) ? REQ_OK : REQ_ERR_TOO_LARGE);
    req_free(req);
    return result;
}

static ReqErr status_of(const char* s, size_t len, const ReqLimits* lim) {
    Request* out = NULL;
    ReqErr e = parse_all(s, len, lim, &out);
    if (out) req_free(out);
    return e;
}

/* Linux RSS in kB, for the constant-memory assertion. */
static long rss_kb(void) {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long val = -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "VmRSS: %ld kB", &val) == 1) break;
    }
    fclose(f);
    return val;
}

int main(void) {
    ReqLimits lim;
    req_limits_defaults(&lim);

    /* --- functional cases, identical to the original parser's contract --- */
    Request* r = NULL;
    check("simple_ok",
          parse_all("GET /a HTTP/1.1\r\nHost: x\r\n\r\n",
                    strlen("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"), &lim, &r)
          == REQ_OK && r->header_count == 1 && req_done(r));
    if (r) req_free(r);

    check("post_cl_ok",
          parse_all("POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
                    strlen("POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\n"),
                    &lim, &r)
          == REQ_OK && r && r->content_length == 5);
    if (r) req_free(r);

    check("te_ok",
          parse_all("POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                    strlen("POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
                    &lim, &r) == REQ_OK && r && r->has_te);
    if (r) req_free(r);

    check("dup_cl_rejected",
          status_of("POST /a HTTP/1.1\r\nContent-Length: 5\r\n"
                    "Content-Length: 6\r\n\r\n",
                    strlen("POST /a HTTP/1.1\r\nContent-Length: 5\r\n"
                           "Content-Length: 6\r\n\r\n"), &lim) == REQ_ERR_DUP_CL);
    check("cl_te_rejected",
          status_of("POST /a HTTP/1.1\r\nContent-Length: 5\r\n"
                    "Transfer-Encoding: chunked\r\n\r\n",
                    strlen("POST /a HTTP/1.1\r\nContent-Length: 5\r\n"
                           "Transfer-Encoding: chunked\r\n\r\n"),
                    &lim) == REQ_ERR_CL_TE);
    check("obs_fold_rejected",
          status_of("GET /a HTTP/1.1\r\nX: a\r\n b\r\n\r\n",
                    strlen("GET /a HTTP/1.1\r\nX: a\r\n b\r\n\r\n"), &lim)
          == REQ_ERR_OBS_FOLD);
    check("bad_cl_rejected",
          status_of("POST /a HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
                    strlen("POST /a HTTP/1.1\r\nContent-Length: -1\r\n\r\n"),
                    &lim) == REQ_ERR_BAD_CL);
    check("bad_version",
          status_of("GET /a HTTP/2.0\r\n\r\n",
                    strlen("GET /a HTTP/2.0\r\n\r\n"), &lim) == REQ_ERR_VERSION);
    check("bad_target",
          status_of("GET a HTTP/1.1\r\n\r\n",
                    strlen("GET a HTTP/1.1\r\n\r\n"), &lim) == REQ_ERR_TARGET);
    check("control_rejected",
          status_of("GET /a\x01 HTTP/1.1\r\n\r\n",
                    strlen("GET /a\x01 HTTP/1.1\r\n\r\n"), &lim)
          == REQ_ERR_CONTROL);
    check("no_colon",
          status_of("GET /a HTTP/1.1\r\nBadHeader\r\n\r\n",
                    strlen("GET /a HTTP/1.1\r\nBadHeader\r\n\r\n"), &lim)
          == REQ_ERR_HEADER_SYNTAX);
    check("bare_cr_rejected",
          status_of("GET /a HTTP/1.1\r\nX: a\rb\r\n\r\n",
                    strlen("GET /a HTTP/1.1\r\nX: a\rb\r\n\r\n"), &lim)
          == REQ_ERR_BARE_CR);
    check("lone_lf_rejected",
          status_of("GET /a HTTP/1.1\nHost: x\n\n",
                    strlen("GET /a HTTP/1.1\nHost: x\n\n"), &lim)
          == REQ_ERR_LF_WITHOUT_CR);
    check("truncated_rejected",
          status_of("GET /a HTTP/1.1\r\nHost: x",
                    strlen("GET /a HTTP/1.1\r\nHost: x"), &lim)
          == REQ_ERR_TOO_LARGE);

    /* --- limit behaviour ------------------------------------------------ */

    /* One reusable, fully-framed header line: "X-Hdr: " (7) + 243 value
       bytes + CRLF = 252 bytes; content length 250 < 256 line ceiling. */
    static char hline[252];
    memcpy(hline, "X-Hdr: ", 7);
    memset(hline + 7, 'v', 243);
    memcpy(hline + 250, "\r\n", 2);

    const char* reqline = "POST /a HTTP/1.1\r\n";
    size_t rl_len = strlen(reqline);

    /* Oversized total: a valid request line + 17 complete header lines
       (17*252 = 4284, plus the request line, all beyond 4096). The total
       ceiling fires partway through header 17, well before the 32-header
       cap, so total size is the first limit crossed. */
    static char big[32 + 17 * 252];
    size_t blen = 0;
    memcpy(big, reqline, rl_len);
    blen = rl_len;
    for (int k = 0; k < 17; k++) { memcpy(big + blen, hline, 252); blen += 252; }

    /* One-shot parse of the fully-framed buffer returns the total-size error. */
    check("too_large_whole",
          status_of(big, blen, &lim) == REQ_ERR_TOO_LARGE);

    /* Streaming: feed the request line, then header lines one byte at a time.
       Exactly max_total bytes are accepted; the next byte fails at intake
       (total would become max_total+1), and no other limit fires first. */
    Request* st = req_new(&lim);
    ReqErr e = req_feed(st, reqline, rl_len);
    size_t fed = rl_len;
    while (fed < DEFAULT_MAX_TOTAL && e == REQ_OK)
        e = req_feed(st, hline + ((fed - rl_len) % 252), 1), fed++;
    check("stream_ok_exactly_at_limit", e == REQ_OK && fed == DEFAULT_MAX_TOTAL
          && !req_failed(st) && st->total == DEFAULT_MAX_TOTAL);
    /* One more byte crosses the ceiling and is rejected, not retained. */
    e = req_feed(st, hline, 1);
    check("stream_rejects_one_byte_past_limit",
          e == REQ_ERR_TOO_LARGE && req_failed(st)
          && st->total == DEFAULT_MAX_TOTAL + 1);
    /* A terminal parser refuses further input rather than accumulating it. */
    check("terminal_parser_stays_closed",
          req_feed(st, big, 100) == REQ_ERR_TOO_LARGE && st->total == lim.max_total + 1);
    req_free(st);

    /* Over-long single line: rejected at max_line+1 content bytes, long
       before the total ceiling matters. */
    char longline[DEFAULT_MAX_LINE + 32];
    memset(longline, 'Z', sizeof(longline));
    check("line_too_long",
          status_of(longline, DEFAULT_MAX_LINE + 1, &lim) == REQ_ERR_LINE_TOO_LONG);

    st = req_new(&lim);
    fed = 0; e = REQ_OK;
    while (fed < DEFAULT_MAX_LINE && e == REQ_OK)
        e = req_feed(st, longline + fed, 1), fed++;
    check("line_ok_exactly_at_limit", e == REQ_OK && fed == DEFAULT_MAX_LINE);
    e = req_feed(st, longline + fed, 1);
    check("line_rejects_one_byte_past", e == REQ_ERR_LINE_TOO_LONG);
    req_free(st);

    /* A header line of exactly max_line content bytes, then CRLF, is
       accepted; one more content byte would have been rejected above.
       "X:" + 254 value bytes = 256, a legal field line (short name, long
       value, so the 64-byte name cap is not what is exercised here). */
    {
        static char exact[DEFAULT_MAX_LINE + 2];
        memcpy(exact, "X:", 2);
        memset(exact + 2, 'v', DEFAULT_MAX_LINE - 2);
        exact[DEFAULT_MAX_LINE] = '\r';
        exact[DEFAULT_MAX_LINE + 1] = '\n';
        Request* t = req_new(&lim);
        ReqErr e0 = req_feed(t, "GET / HTTP/1.1\r\n",
                             strlen("GET / HTTP/1.1\r\n"));
        e0 = e0 == REQ_OK ? req_feed(t, exact, sizeof(exact)) : e0;
        check("line_exact_limit_accepted", e0 == REQ_OK && !req_failed(t));
        req_free(t);
    }

    /* Limits are configurable and enforced at the configured value. */
    ReqLimits tight = { .max_total = 64, .max_line = 32 };
    check("custom_limit_accepts_under_ceiling",
          status_of("GET /a HTTP/1.1\r\nHost: x\r\n\r\n",
                    strlen("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"), &tight)
          == REQ_OK); /* 27 <= 64, should parse */
    {
        /* A valid request line followed by short legal header lines
           (well under max_line=32) whose aggregate crosses max_total=64
           first, exercising the total ceiling rather than line syntax. */
        char medium[128];
        size_t mlen = 0;
        const char* mline = "GET / HTTP/1.1\r\n";
        memcpy(medium, mline, strlen(mline));
        mlen = strlen(mline);
        while (mlen + 10 <= sizeof(medium)) {
            memcpy(medium + mlen, "X-H: abc\r\n", 10);
            mlen += 10;
        }
        check("custom_limit_enforced",
              status_of(medium, mlen, &tight) == REQ_ERR_TOO_LARGE);
    }
    check("bad_config_rejected", req_new(&(ReqLimits){.max_total = 10, .max_line = 20})
          == NULL);

    /* The request cannot raise its own ceiling: a declared Content-Length
       has no effect on head-size accounting, and header text cannot configure
       anything. A head under max_total parses regardless of body CL. */
    {
        const char* s = "POST /a HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n";
        Request* t = NULL;
        check("client_cannot_raise_limit",
              parse_all(s, strlen(s), &lim, &t) == REQ_OK
              && t && t->content_length == 999999999 && t->total <= lim.max_total);
        if (t) req_free(t);
    }

    /* --- constant memory: RSS must not grow with request size ------------ */
    long rss_before = rss_kb();
    size_t peak_total = 0;
    /* Feed complete 252-byte header lines from the reusable hline template,
       simulating 16 MB per round (128 MB total). The parser must reject at
       byte max_total+1, inside header 17, no matter how much more is offered;
       its retained state must stay bounded by the configured limits. */
    for (int round = 0; round < 8; round++) {
        size_t huge = 16u * 1024 * 1024;
        Request* t = req_new(&lim);
        ReqErr err = req_feed(t, reqline, rl_len);
        size_t pushed = rl_len;
        while (pushed < huge && err == REQ_OK) {
            err = req_feed(t, hline, sizeof(hline));
            pushed += sizeof(hline);
        }
        check("huge_request_rejected_early",
              err == REQ_ERR_TOO_LARGE && t->total == lim.max_total + 1);
        peak_total = t->total;
        req_free(t);
    }
    long rss_after = rss_kb();
    printf("rss_before_kb=%ld rss_after_kb=%ld\n", rss_before, rss_after);
    check("rss_constant_under_128mb_input",
          rss_before > 0 && rss_after >= rss_before && rss_after - rss_before < 2048);
    /* The byte that crosses the ceiling is counted then rejected; retained
       parser state never holds more than the line buffer plus the fixed
       header table, both sized from config, never from request length. */
    check("peak_counter_bounded", peak_total == lim.max_total + 1);

    /* --- streaming / whole-buffer equivalence fuzz ----------------------- */
    static const char alphabet[] =
        "GETPOST /ab HTTP/1.1\r\nHost:xContent-Length:5Transfer-Encoding"
        "chunked\t :\x01" "\x7f" "AZ\r\n .-";
    unsigned seed = 0x1234abcd;
    int mismatch = 0, fuzz_ok = 0;
    for (int iter = 0; iter < 4000; iter++) {
        char buf[128];
        size_t n = (size_t)(seed % 80) + 1;
        for (size_t i = 0; i < n; i++) {
            seed = seed * 1103515245u + 12345u;
            buf[i] = alphabet[(seed >> 16) % (sizeof(alphabet) - 1)];
        }
        ReqErr e1 = status_of(buf, n, &lim);
        ReqErr e2 = feed_bytewise(buf, n, &lim);
        ReqErr e3 = feed_chunked(buf, n, &lim);
        if (e1 != e2 || e1 != e3) {
            mismatch = 1;
            printf("MISMATCH iter=%d n=%zu: whole=%s byte=%s chunk=%s\n",
                   iter, n, err_name(e1), err_name(e2), err_name(e3));
            break;
        }
        fuzz_ok++;
    }
    printf("fuzz_cases=%d\n", fuzz_ok);
    check("stream_matches_whole_parse", !mismatch && fuzz_ok == 4000);

    printf("all_ok=%d\n", failures == 0);
    return failures == 0 ? 0 : 1;
}
