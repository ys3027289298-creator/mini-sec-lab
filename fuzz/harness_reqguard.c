/*
 * harness_reqguard.c — fuzzing entry point for the reqguard HTTP/1.1
 * parser. The whole component is one translation unit; include it with
 * main renamed so the harness owns the process entry.
 */
#include "engine.h"

#include <string.h>

#define main reqguard_demo_main
#include "../reqguard/src/reqguard.c"
#undef main

/* MAX_BUF is the parser's own hard cap, so clamp before calling. */
void fuzz_one(const uint8_t *data, size_t size) {
    if (size > MAX_BUF) size = MAX_BUF;

    char buf[MAX_BUF + 1];
    memcpy(buf, data, size);
    buf[size] = 0;

    Request req;
    ReqErr e = parse_request(buf, size, &req);

    /* Exercise the error-name table on every result so a missing enum
     * case stays covered. */
    if (err_name(e) == NULL)
        abort();
}

static const char *seed_lines[] = {
    "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
    "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
    "GET /a/b?c=1&d=2 HTTP/1.1\r\nHost: example.com\r\nX-Test: v\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
};

int fuzz_seed(void) {
    for (size_t i = 0; i < sizeof(seed_lines) / sizeof(seed_lines[0]); i++)
        engine_emit_seed((const uint8_t *)seed_lines[i],
                         strlen(seed_lines[i]));
    return 0;
}
