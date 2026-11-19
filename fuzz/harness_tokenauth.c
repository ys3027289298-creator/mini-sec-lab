/*
 * harness_tokenauth.c — fuzzing entry point for tokenauth token
 * verification. A fresh Auth context is created per worker process via
 * fuzz_init(); the fuzzer feeds attacker-controlled byte strings into
 * verify(), exactly the untrusted-input boundary the component guards.
 */
#include "engine.h"

#include <string.h>

#define main tokenauth_demo_main
#include "../tokenauth/src/tokenauth.c"
#undef main

static const unsigned char FUZZ_KEY[32] = "0123456789abcdef0123456789abcdef";
static Auth g_auth;

void fuzz_init(void) {
    auth_init(&g_auth, FUZZ_KEY, sizeof(FUZZ_KEY) - 1, 300, 5);
    /* Also exercise the rotated (two-key) state in every worker. */
    static const unsigned char key2[32] = "ffffffffffffffffffffffffffffffff";
    auth_rotate(&g_auth, key2, sizeof(key2) - 1);
}

void fuzz_one(const uint8_t *data, size_t size) {
    if (size > TOKEN_MAX - 1) size = TOKEN_MAX - 1;

    char token[TOKEN_MAX];
    memcpy(token, data, size);
    token[size] = 0;

    unsigned long long nonce = 0;
    AuthErr e = verify(&g_auth, token, 1000, &nonce);
    if (auth_name(e) == NULL)
        abort();
}

int fuzz_seed(void) {
    Auth a;
    auth_init(&a, FUZZ_KEY, sizeof(FUZZ_KEY) - 1, 300, 5);

    char tok[TOKEN_MAX];
    static const char *uids[] = {"u1", "admin", "x"};
    static const unsigned long long nonces[] = {1, 42, 1024};
    for (size_t i = 0; i < sizeof(uids) / sizeof(uids[0]); i++) {
        if (!build_token(&a, uids[i], 1000, nonces[i], tok))
            return 1;
        engine_emit_seed((const uint8_t *)tok, strlen(tok));
    }
    /* Malformed-but-structured seeds give the mutator useful anchors. */
    static const char *bad[] = {
        "garbage",
        "u1.1300.42.0000000000000000000000000000000000000000000000000000000000000000",
        "...",
        "a.b.c",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        engine_emit_seed((const uint8_t *)bad[i], strlen(bad[i]));
    return 0;
}
