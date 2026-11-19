
/* tokenauth: HMAC-SHA256 bearer tokens with constant-time compare,
   expiry with clock skew, nonce replay cache and key rotation. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define TOKEN_MAX 256
#define NONCE_MAX 1024
#define KEY_MAX 32

typedef struct {
    unsigned char keys[2][KEY_MAX];
    size_t key_len[2];
    int key_count;
    long ttl;
    long skew;
    unsigned long long seen[NONCE_MAX];
    int seen_count;
    int seen_head;
} Auth;

typedef enum {
    AUTH_OK = 0,
    AUTH_MALFORMED,
    AUTH_BAD_SIG,
    AUTH_EXPIRED,
    AUTH_NOT_YET,
    AUTH_REPLAY
} AuthErr;

static const char* auth_name(AuthErr e) {
    switch (e) {
    case AUTH_OK: return "ok";
    case AUTH_MALFORMED: return "malformed";
    case AUTH_BAD_SIG: return "bad_sig";
    case AUTH_EXPIRED: return "expired";
    case AUTH_NOT_YET: return "not_yet";
    case AUTH_REPLAY: return "replay";
    }
    return "?";
}

static void auth_init(Auth* a, const unsigned char* key, size_t klen, long ttl, long skew) {
    memset(a, 0, sizeof(*a));
    memcpy(a->keys[0], key, klen);
    a->key_len[0] = klen;
    a->key_count = 1;
    a->ttl = ttl;
    a->skew = skew;
}

static void auth_rotate(Auth* a, const unsigned char* key, size_t klen) {
    memcpy(a->keys[1], a->keys[0], a->key_len[0]);
    a->key_len[1] = a->key_len[0];
    memcpy(a->keys[0], key, klen);
    a->key_len[0] = klen;
    a->key_count = 2;
}

static int ct_equal(const unsigned char* a, const unsigned char* b, size_t n) {
    unsigned char diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

static void hmac_hex(const unsigned char* key, size_t klen, const char* msg, char* out) {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen = 0;
    HMAC(EVP_sha256(), key, (int)klen, (const unsigned char*)msg, strlen(msg), mac, &maclen);
    for (unsigned int i = 0; i < maclen; i++) sprintf(out + i * 2, "%02x", mac[i]);
    out[maclen * 2] = 0;
}

static int build_token(const Auth* a, const char* uid, long now, unsigned long long nonce, char* out) {
    char body[TOKEN_MAX];
    snprintf(body, sizeof(body), "%s.%ld.%llu", uid, now + a->ttl, nonce);
    char sig[EVP_MAX_MD_SIZE * 2 + 1];
    hmac_hex(a->keys[0], a->key_len[0], body, sig);
    int n = snprintf(out, TOKEN_MAX, "%s.%s", body, sig);
    return n > 0 && n < TOKEN_MAX;
}

static AuthErr verify(Auth* a, const char* token, long now, unsigned long long* nonce_out) {
    char buf[TOKEN_MAX];
    if (strlen(token) >= sizeof(buf)) return AUTH_MALFORMED;
    strcpy(buf, token);

    char* dot = strrchr(buf, '.');
    if (!dot) return AUTH_MALFORMED;
    *dot = 0;
    const char* sig = dot + 1;
    if (strlen(sig) != 64) return AUTH_MALFORMED;

    char exp_s[32], nonce_s[32];
    char* last = strrchr(buf, '.');
    if (!last) return AUTH_MALFORMED;
    *last = 0;
    char* mid = strrchr(buf, '.');
    if (!mid) return AUTH_MALFORMED;
    *mid = 0;
    const char* uid = buf;
    strncpy(exp_s, mid + 1, sizeof(exp_s) - 1);
    exp_s[sizeof(exp_s) - 1] = 0;
    strncpy(nonce_s, last + 1, sizeof(nonce_s) - 1);
    nonce_s[sizeof(nonce_s) - 1] = 0;

    char body[TOKEN_MAX];
    snprintf(body, sizeof(body), "%s.%s.%s", uid, exp_s, nonce_s);

    char want[EVP_MAX_MD_SIZE * 2 + 1];
    int ok = 0;
    for (int k = 0; k < a->key_count; k++) {
        hmac_hex(a->keys[k], a->key_len[k], body, want);
        if (ct_equal((const unsigned char*)want, (const unsigned char*)sig, 64)) { ok = 1; break; }
    }
    if (!ok) return AUTH_BAD_SIG;

    long exp = strtol(exp_s, NULL, 10);
    unsigned long long nonce = strtoull(nonce_s, NULL, 10);
    if (now > exp + a->skew) return AUTH_EXPIRED;
    if (exp - a->ttl > now + a->skew) return AUTH_NOT_YET;

    for (int i = 0; i < a->seen_count; i++)
        if (a->seen[(a->seen_head + NONCE_MAX - 1 - i) % NONCE_MAX] == nonce) return AUTH_REPLAY;

    a->seen[a->seen_head] = nonce;
    a->seen_head = (a->seen_head + 1) % NONCE_MAX;
    if (a->seen_count < NONCE_MAX) a->seen_count++;
    if (nonce_out) *nonce_out = nonce;
    return AUTH_OK;
}

#ifdef SELF_TEST
static int failures = 0;
static void check(const char* name, int ok) {
    printf("%s=%d\n", name, ok ? 1 : 0);
    if (!ok) failures++;
}

int main(void) {
    Auth a;
    const unsigned char key[] = "0123456789abcdef0123456789abcdef";
    auth_init(&a, key, 32, 300, 5);

    char tok[TOKEN_MAX];
    long now = 1000;
    check("build_ok", build_token(&a, "u1", now, 42, tok));
    check("verify_ok", verify(&a, tok, now, NULL) == AUTH_OK);
    check("replay_rejected", verify(&a, tok, now, NULL) == AUTH_REPLAY);

    char tok2[TOKEN_MAX];
    build_token(&a, "u1", now, 43, tok2);
    check("distinct_nonce_ok", verify(&a, tok2, now, NULL) == AUTH_OK);

    char bad[TOKEN_MAX];
    strcpy(bad, tok2);
    bad[0] = bad[0] == 'a' ? 'b' : 'a';
    check("tampered_sig", verify(&a, bad, now, NULL) == AUTH_BAD_SIG);

    check("expired", verify(&a, tok2, now + 400, NULL) == AUTH_EXPIRED);

    char tok_old[TOKEN_MAX];
    build_token(&a, "u3", now, 45, tok_old);

    const unsigned char key2[] = "ffffffffffffffffffffffffffffffff";
    auth_rotate(&a, key2, 32);
    char tok3[TOKEN_MAX];
    build_token(&a, "u2", now, 44, tok3);
    check("rotated_new_key_ok", verify(&a, tok3, now, NULL) == AUTH_OK);
    check("old_token_still_ok", verify(&a, tok_old, now, NULL) == AUTH_OK);

    check("malformed", verify(&a, "garbage", now, NULL) == AUTH_MALFORMED);

    printf("all_ok=%d\n", failures == 0);
    return failures == 0 ? 0 : 1;
}
#endif /* SELF_TEST */
