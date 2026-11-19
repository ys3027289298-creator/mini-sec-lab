/* tokenauth driver: uniform checker entry point into tokenauth.
   State (Auth context) lives in this process; one process handles one case,
   so state never leaks between cases.

     {"op":"init","key_hex":"...","ttl":300,"skew":5}
         -> {"status":"ok"}
     {"op":"rotate","key_hex":"..."}
         -> {"status":"ok"}
     {"op":"build","uid":"u1","now":1000,"nonce":42}
         -> {"status":"ok","token":"..."}
     {"op":"verify","token":"...","now":1000}
         -> {"status":"ok"|"bad_sig"|"expired"|"replay"|...,"nonce":N}
     {"op":"flip_first_char","token":"..."}
         -> {"status":"ok","token":"..."}   (tamper helper for sig tests) */
#include "drv_json.h"
#include "../tokenauth/src/tokenauth.c"

/* one case runs in one process, so a single file-scope context is enough */
static Auth* auth_ctx = NULL;

static void drv_init(JOut* out, const JObj* in) {
    const char* kh = jstr(in, "key_hex");
    const JField* fttl = jget(in, "ttl");
    const JField* fskew = jget(in, "skew");
    if (!kh || !fttl || fttl->type != 'n' || !fskew || fskew->type != 'n') {
        jo_str(out, "status", "bad_args");
        return;
    }
    unsigned char key[KEY_MAX];
    size_t klen;
    if (hex_decode(kh, key, sizeof(key), &klen) < 0) {
        jo_str(out, "status", "bad_hex");
        return;
    }
    static Auth a;
    auth_init(&a, key, klen, fttl->num, fskew->num);
    /* hand the context to later ops via a file-scope pointer */
    auth_ctx = &a;
    jo_str(out, "status", "ok");
}

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
        if (!op) {
            jo_str(&out, "status", "bad_args");
        } else if (strcmp(op, "init") == 0) {
            drv_init(&out, &in);
        } else if (strcmp(op, "rotate") == 0) {
            const char* kh = jstr(&in, "key_hex");
            unsigned char key[KEY_MAX];
            size_t klen;
            if (!kh || hex_decode(kh, key, sizeof(key), &klen) < 0) {
                jo_str(&out, "status", "bad_hex");
            } else if (!auth_ctx) {
                jo_str(&out, "status", "no_init");
            } else {
                auth_rotate(auth_ctx, key, klen);
                jo_str(&out, "status", "ok");
            }
        } else if (strcmp(op, "build") == 0) {
            const char* uid = jstr(&in, "uid");
            const JField* fnow = jget(&in, "now");
            const JField* fnonce = jget(&in, "nonce");
            if (!uid || !fnow || fnow->type != 'n' || !fnonce || fnonce->type != 'n' || !auth_ctx) {
                jo_str(&out, "status", "bad_args");
            } else {
                char tok[TOKEN_MAX];
                int built = build_token(auth_ctx, uid, fnow->num,
                                        (unsigned long long)fnonce->num, tok);
                if (!built) {
                    jo_str(&out, "status", "build_failed");
                } else {
                    jo_str(&out, "status", "ok");
                    jo_str(&out, "token", tok);
                }
            }
        } else if (strcmp(op, "verify") == 0) {
            const char* token = jstr(&in, "token");
            const JField* fnow = jget(&in, "now");
            if (!token || !fnow || fnow->type != 'n' || !auth_ctx) {
                jo_str(&out, "status", "bad_args");
            } else {
                unsigned long long nonce = 0;
                AuthErr e = verify(auth_ctx, token, fnow->num, &nonce);
                jo_str(&out, "status", auth_name(e));
                jo_ull(&out, "nonce", nonce);
            }
        } else if (strcmp(op, "flip_first_char") == 0) {
            const char* token = jstr(&in, "token");
            if (!token) {
                jo_str(&out, "status", "bad_args");
            } else {
                char tampered[TOKEN_MAX];
                snprintf(tampered, sizeof(tampered), "%s", token);
                for (size_t i = 0; tampered[i]; i++) {
                    if (tampered[i] != '.') {
                        tampered[i] = tampered[i] == 'a' ? 'b' : 'a';
                        break;
                    }
                }
                jo_str(&out, "status", "ok");
                jo_str(&out, "token", tampered);
            }
        } else {
            jo_str(&out, "status", "bad_op");
        }
        jo_end(&out);
    }
    return 0;
}
