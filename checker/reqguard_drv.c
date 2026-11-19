/* reqguard driver: the checker's uniform entry point into reqguard.
   Line protocol (one JSON object per line, see checker/drv_json.h):

     in : {"op":"parse","request":"GET /a HTTP/1.1\r\n..."}
     out: {"status":"ok"|"bad_method"|...,"header_count":N,
           "content_length":N|-1,"has_te":0|1}
     unknown ops reply {"status":"bad_op"}. */
#include "drv_json.h"
#include "../reqguard/src/reqguard.c"

int main(void) {
    char line[JLINE_MAX];
    while (fgets(line, sizeof(line), stdin)) {
        JObj in;
        JOut out;
        jo_begin(&out);
        if (jparse(line, &in) < 0) {
            jo_str(&out, "status", "bad_json");
            jo_end(&out);
            continue;
        }
        const char* op = jstr(&in, "op");
        if (op && strcmp(op, "parse") == 0) {
            const char* req = jstr(&in, "request");
            Request r;
            ReqErr e = parse_request(req ? req : "", req ? strlen(req) : 0, &r);
            jo_str(&out, "status", err_name(e));
            if (e == REQ_OK) {
                jo_long(&out, "header_count", r.header_count);
                jo_long(&out, "content_length", r.content_length);
                jo_bool(&out, "has_te", r.has_te);
            }
        } else {
            jo_str(&out, "status", "bad_op");
        }
        jo_end(&out);
    }
    return 0;
}
