/* pathguard driver: uniform checker entry point into pathguard.

     in : {"op":"check","path":"a/b.txt"}
     out: {"status":"ok"|"absolute"|"traversal"|...} */
#include "drv_json.h"
#include "../pathguard/src/pathguard.c"

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
        if (op && strcmp(op, "check") == 0) {
            const char* path = jstr(&in, "path");
            PgErr e = check_rel(path ? path : "");
            jo_str(&out, "status", pg_name(e));
        } else {
            jo_str(&out, "status", "bad_op");
        }
        jo_end(&out);
    }
    return 0;
}
