
/* tokenauth: HMAC-SHA256 bearer tokens with constant-time compare,
   expiry with clock skew, nonce replay cache, key rotation and a
   bounded revocation list (per-user and per-token, auto-expiring). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define TOKEN_MAX 256
#define NONCE_MAX 1024
#define KEY_MAX 32
#define UID_MAX 64
#define REVOKE_MAX 256

typedef struct {
    unsigned char keys[2][KEY_MAX];
    size_t key_len[2];
    int key_count;
    long ttl;
    long skew;
    unsigned long long seen[NONCE_MAX];
    int seen_count;
    int seen_head;
    /* revocation list: empty slots have uid[0] == 0 */
    struct {
        char uid[UID_MAX];
        unsigned long long nonce; /* 0 means "revoke whole user" */
        long expire;              /* wall-clock expiry; LONG_MAX = permanent */
    } rev[REVOKE_MAX];
    int rev_count;
} Auth;

typedef enum {
    AUTH_OK = 0,
    AUTH_MALFORMED,
    AUTH_BAD_SIG,
    AUTH_EXPIRED,
    AUTH_NOT_YET,
    AUTH_REPLAY,
    AUTH_REVOKED
} AuthErr;

static const char* auth_name(AuthErr e) {
    switch (e) {
    case AUTH_OK: return "ok";
    case AUTH_MALFORMED: return "malformed";
    case AUTH_BAD_SIG: return "bad_sig";
    case AUTH_EXPIRED: return "expired";
    case AUTH_NOT_YET: return "not_yet";
    case AUTH_REPLAY: return "replay";
    case AUTH_REVOKED: return "revoked";
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

/* split "uid.exp.nonce.sig" into its parts; body keeps the exact
   "uid.exp.nonce" substring so the signature is checked verbatim. */
static int parse_token(const char* token, char* uid, unsigned long long* nonce,
                       char* body, char* sig) {
    char buf[TOKEN_MAX];
    if (strlen(token) >= sizeof(buf)) return 0;
    strcpy(buf, token);

    char* dot = strrchr(buf, '.');
    if (!dot) return 0;
    *dot = 0;
    if (strlen(dot + 1) != 64) return 0;
    strcpy(sig, dot + 1);

    char* last = strrchr(buf, '.');
    if (!last) return 0;
    *last = 0;
    char* mid = strrchr(buf, '.');
    if (!mid) return 0;
    *mid = 0;
    if (strlen(buf) == 0 || strlen(buf) >= UID_MAX) return 0;

    strcpy(uid, buf);
    *nonce = strtoull(last + 1, NULL, 10);
    /* reconstruct the body exactly as signed */
    if (snprintf(body, TOKEN_MAX, "%s.%s.%s", buf, mid + 1, last + 1) >= TOKEN_MAX)
        return 0;
    return 1;
}

static int build_token(const Auth* a, const char* uid, long now, unsigned long long nonce, char* out) {
    char body[TOKEN_MAX];
    snprintf(body, sizeof(body), "%s.%ld.%llu", uid, now + a->ttl, nonce);
    char sig[EVP_MAX_MD_SIZE * 2 + 1];
    hmac_hex(a->keys[0], a->key_len[0], body, sig);
    int n = snprintf(out, TOKEN_MAX, "%s.%s", body, sig);
    return n > 0 && n < TOKEN_MAX;
}

/* drop every expired revocation entry; entries with non-zero ttl carry
   their own expiry, so cleanup never touches entries still in force. */
static void revoke_purge(Auth* a, long now) {
    for (int i = 0; i < a->rev_count;) {
        if (a->rev[i].expire <= now) {
            a->rev[i] = a->rev[a->rev_count - 1];
            memset(&a->rev[a->rev_count - 1], 0, sizeof(a->rev[0]));
            a->rev_count--;
        } else {
            i++;
        }
    }
}

/* ttl <= 0 means "revoke until the token itself expires" (permanent here). */
static int revoke_put(Auth* a, const char* uid, unsigned long long nonce, long now, long ttl) {
    if (strlen(uid) == 0 || strlen(uid) >= UID_MAX) return 0;

    revoke_purge(a, now);

    long expire = LONG_MAX;
    if (ttl > 0) {
        if (ttl > LONG_MAX - now) return 0;
        expire = now + ttl;
    }

    /* same identity already listed: extend/replace its expiry */
    for (int i = 0; i < a->rev_count; i++) {
        if (a->rev[i].nonce == nonce && strcmp(a->rev[i].uid, uid) == 0) {
            a->rev[i].expire = expire;
            return 1;
        }
    }

    /* hard upper bound on table size. A finite entry only evicts a
       longer-lived one (strictly), so a flood of same-ttl revokes cannot
       churn the table; a permanent entry (LONG_MAX) always takes a finite
       slot but can never itself be evicted. */
    if (a->rev_count >= REVOKE_MAX) {
        int victim = 0;
        for (int i = 1; i < a->rev_count; i++)
            if (a->rev[i].expire < a->rev[victim].expire) victim = i;
        int can_evict = expire == LONG_MAX
                            ? a->rev[victim].expire < LONG_MAX
                            : expire < a->rev[victim].expire;
        if (!can_evict) return 0;
        a->rev[victim].nonce = nonce;
        strcpy(a->rev[victim].uid, uid);
        a->rev[victim].expire = expire;
        return 1;
    }

    int i = a->rev_count++;
    strcpy(a->rev[i].uid, uid);
    a->rev[i].nonce = nonce;
    a->rev[i].expire = expire;
    return 1;
}

static int revoke_user(Auth* a, const char* uid, long now, long ttl) {
    return revoke_put(a, uid, 0, now, ttl);
}

static int revoke_token(Auth* a, const char* token, long now, long ttl) {
    char uid[UID_MAX], body[TOKEN_MAX], sig[65];
    unsigned long long nonce;
    if (!parse_token(token, uid, &nonce, body, sig)) return 0;
    return revoke_put(a, uid, nonce, now, ttl);
}

/* a token is revoked when its exact (uid, nonce) is listed or when the
   whole user is listed (nonce == 0). */
static int is_revoked(Auth* a, const char* uid, unsigned long long nonce, long now) {
    for (int i = 0; i < a->rev_count; i++) {
        if (a->rev[i].expire <= now) continue;
        if (strcmp(a->rev[i].uid, uid) != 0) continue;
        if (a->rev[i].nonce == 0 || a->rev[i].nonce == nonce) return 1;
    }
    return 0;
}

static AuthErr verify(Auth* a, const char* token, long now, unsigned long long* nonce_out) {
    char uid[UID_MAX], body[TOKEN_MAX], sig[65];
    unsigned long long nonce;
    if (!parse_token(token, uid, &nonce, body, sig)) return AUTH_MALFORMED;

    char want[EVP_MAX_MD_SIZE * 2 + 1];
    int ok = 0;
    for (int k = 0; k < a->key_count; k++) {
        hmac_hex(a->keys[k], a->key_len[k], body, want);
        if (ct_equal((const unsigned char*)want, (const unsigned char*)sig, 64)) { ok = 1; break; }
    }
    if (!ok) return AUTH_BAD_SIG;

    /* lazy cleanup on read, then the immediate-effect check: a revoked
       token fails before expiry/replay bookkeeping can touch it. */
    revoke_purge(a, now);
    if (is_revoked(a, uid, nonce, now)) return AUTH_REVOKED;

    char* mid = strchr(body, '.');
    long exp = strtol(mid + 1, NULL, 10);
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

    /* ---- revocation list ---- */
    char t101[TOKEN_MAX], t102[TOKEN_MAX], t201[TOKEN_MAX], t202[TOKEN_MAX];
    build_token(&a, "uA", now, 101, t101);
    build_token(&a, "uA", now, 102, t102);
    build_token(&a, "uB", now, 201, t201);
    build_token(&a, "uB", now, 101, t202); /* same nonce, different user */

    check("revoke_user_ok", revoke_user(&a, "uA", now, 100));
    check("user_revoke_immediate", verify(&a, t101, now, NULL) == AUTH_REVOKED);
    check("user_revoke_all_tokens", verify(&a, t102, now, NULL) == AUTH_REVOKED);
    check("other_user_unaffected", verify(&a, t201, now, NULL) == AUTH_OK);

    check("revoke_token_ok", revoke_token(&a, t201, now, 100));
    check("token_revoke_immediate", verify(&a, t201, now, NULL) == AUTH_REVOKED);
    check("token_revoke_scoped", verify(&a, t202, now, NULL) == AUTH_OK);
    check("revoked_not_recorded_as_replay", verify(&a, t201, now, NULL) == AUTH_REVOKED);

    /* expiry + auto cleanup: expired entries vanish, live entries stay */
    char t301[TOKEN_MAX];
    build_token(&a, "uC", now, 301, t301);
    check("short_revoke_ok", revoke_user(&a, "uC", now, 10));
    check("short_revoke_active", verify(&a, t301, now, NULL) == AUTH_REVOKED);
    revoke_purge(&a, now + 11);
    check("purge_drops_expired", a.rev_count == 2); /* uA(100s), uB/201(100s) remain */
    check("purge_keeps_live", verify(&a, t101, now + 11, NULL) == AUTH_REVOKED);
    check("purge_frees_token", verify(&a, t301, now + 11, NULL) == AUTH_OK);

    /* lazy cleanup inside verify works without an explicit purge call */
    char t302[TOKEN_MAX];
    build_token(&a, "uD", now, 302, t302);
    revoke_user(&a, "uD", now, 5);
    check("lazy_purge_on_verify", verify(&a, t302, now + 6, NULL) == AUTH_OK);

    /* re-listing an identity before expiry extends it in place */
    check("rerevoke_same_user", revoke_user(&a, "uA", now + 50, 100));
    revoke_purge(&a, now + 105); /* original 100s entry would have died at 1100 */
    check("rerevoke_extends", is_revoked(&a, "uA", 0, now + 105));

    /* coexistence with key rotation: revocation is key-independent */
    char t401[TOKEN_MAX], t402[TOKEN_MAX];
    build_token(&a, "uE", now, 401, t401);
    check("rotate_again_ok", build_token(&a, "uF", now, 402, t402));
    revoke_user(&a, "uE", now, 100);
    const unsigned char key3[] = "11111111111111111111111111111111";
    auth_rotate(&a, key3, 32);
    check("revoke_survives_rotation", verify(&a, t401, now, NULL) == AUTH_REVOKED);
    check("new_token_after_rotation_ok", verify(&a, t402, now, NULL) == AUTH_OK);
    char t403[TOKEN_MAX];
    build_token(&a, "uE", now, 403, t403);
    check("revoked_user_new_token_blocked", verify(&a, t403, now, NULL) == AUTH_REVOKED);

    /* hard upper bound: REVOKE_MAX entries, eviction keeps the table bounded */
    Auth b;
    auth_init(&b, key, 32, 300, 5);
    char name[UID_MAX];
    for (int i = 0; i < 300; i++) {
        snprintf(name, sizeof(name), "bulk%03d", i);
        revoke_user(&b, name, now, 100);
    }
    check("revoke_table_bounded", b.rev_count == REVOKE_MAX);
    check("bounded_keeps_long_lived", is_revoked(&b, "bulk100", 0, now));
    /* same-ttl revokes past the cap are rejected, nothing is evicted */
    check("bounded_samettl_rejected", !revoke_user(&b, "bulk_overflow", now, 100));
    check("bounded_overflow_kept_cap", b.rev_count == REVOKE_MAX);
    /* a strictly shorter-lived entry evicts the soonest-expiring slot */
    revoke_user(&b, "bulk_temp", now, 5);
    check("bounded_temp_capped", b.rev_count == REVOKE_MAX);
    check("bounded_temp_listed", is_revoked(&b, "bulk_temp", 0, now));
    revoke_purge(&b, now + 6);
    check("bounded_under_cap", b.rev_count == REVOKE_MAX - 1);
    check("bounded_shortlived_gone", !is_revoked(&b, "bulk_temp", 0, now + 6));
    revoke_user(&b, "bulk300", now, 100); /* freed slot is reusable */
    check("bounded_refills_to_cap", b.rev_count == REVOKE_MAX);
    /* permanent revocations can never be evicted */
    check("permanent_when_full", revoke_user(&b, "bulk_perm", now, 0));
    check("permanent_listed", is_revoked(&b, "bulk_perm", 0, now + 1000000));

    /* permanent revocation (ttl <= 0) outlives every purge */
    Auth c;
    auth_init(&c, key, 32, 300, 5);
    char t501[TOKEN_MAX];
    build_token(&c, "uP", now, 501, t501);
    check("permanent_revoke_ok", revoke_user(&c, "uP", now, 0));
    revoke_purge(&c, now + 1000000);
    check("permanent_revoke_kept", verify(&c, t501, now, NULL) == AUTH_REVOKED);

    check("revoke_malformed_token", !revoke_token(&c, "garbage", now, 100));
    char huge[TOKEN_MAX + 16];
    memset(huge, 'x', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = 0;
    check("revoke_oversized_user", !revoke_user(&c, huge, now, 100));

    printf("all_ok=%d\n", failures == 0);
    return failures == 0 ? 0 : 1;
}
