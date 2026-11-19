
/* tlshttp: hand decrypted application_data to the reqguard parser.
   The reqguard source is compiled into this translation unit (its
   symbols are file-static and the standalone main() is renamed), so
   reqguard/ stays untouched and keeps building on its own. */
#define main reqguard_standalone_main
#include "../../reqguard/src/reqguard.c"
#undef main

#include "tlsrecord.h"

const char* trl_http_ingest(const TlsRecordLayer* ctx) {
    if (ctx->app_len == 0) return NULL;

    /* reqguard refuses anything above its own MAX_BUF (4096); keep one
       extra byte for the terminating NUL. */
    static char http[4097];
    size_t n = ctx->app_len;
    if (n > 4096) n = 4096;
    memcpy(http, ctx->app, n);
    http[n] = 0;

    Request req;
    ReqErr rc = parse_request(http, n, &req);
    return err_name(rc);
}
