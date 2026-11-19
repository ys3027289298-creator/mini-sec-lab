
/* jwtguard: gateway-side verification of third-party RS256/ES256 JWTs.
 *
 * Security model:
 *  - asymmetric signatures only. alg "none" (any casing) is rejected and
 *    HMAC algs can never be pinned to an asymmetric key (alg confusion).
 *  - trust comes exclusively from the local keyring, a whitelist of
 *    (kid, alg, public key PEM) triples. A token's kid only selects an
 *    entry; the token cannot introduce keys (jwk/jku/x5u/x5c rejected)
 *    and cannot override the pinned alg.
 *  - RS256 = RSASSA-PKCS1-v1_5 with SHA-256; ES256 = ECDSA over P-256
 *    with SHA-256, JWT raw R||S signature converted to DER for OpenSSL.
 *  - exp/nbf are mandatory and checked against a configurable clock-skew
 *    leeway.
 *
 * Usage:
 *   jwtguard verify <keyring.conf> <token> [leeway [now_epoch]]
 *   jwtguard batch  <keyring.conf> <cases.tsv>
 *       cases.tsv lines: id<TAB>leeway<TAB>now_epoch<TAB>token
 *       output lines:     id<TAB>ok|reject<TAB>reason
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define TOKEN_MAX 16384
#define DECODE_MAX 12288
#define ARENA_SIZE (128u * 1024u)
#define MAX_DEPTH 16
#define KID_MAX 64
#define ALG_MAX 16
#define KEYRING_MAX 16

/* ---- result reasons (kept identical to the Python reference harness) ---- */
typedef enum {
    R_OK = 0,
    R_MALFORMED,
    R_ALG_NONE,
    R_ALG_CONFUSION,
    R_MISSING_KID,
    R_UNKNOWN_KID,
    R_UNTRUSTED_HEADER,
    R_MISSING_CLAIM,
    R_BAD_SIG,
    R_EXPIRED,
    R_NOT_YET
} Reason;

static const char *reason_str(Reason r) {
    switch (r) {
    case R_OK:               return "ok";
    case R_MALFORMED:        return "malformed";
    case R_ALG_NONE:         return "alg_none";
    case R_ALG_CONFUSION:    return "alg_confusion";
    case R_MISSING_KID:      return "missing_kid";
    case R_UNKNOWN_KID:      return "unknown_kid";
    case R_UNTRUSTED_HEADER: return "untrusted_header";
    case R_MISSING_CLAIM:    return "missing_claim";
    case R_BAD_SIG:          return "bad_sig";
    case R_EXPIRED:          return "expired";
    case R_NOT_YET:          return "not_yet";
    }
    return "?";
}

/* ----------------------------- bump arena -------------------------------- */
typedef struct {
    unsigned char *buf;
    size_t used;
    int failed;
} Arena;

static void arena_init(Arena *a) {
    a->buf = (unsigned char *)malloc(ARENA_SIZE);
    a->used = 0;
    a->failed = a->buf == NULL;
}

static void *arena_alloc(Arena *a, size_t n) {
    n = (n + 7u) & ~(size_t)7u;
    if (a->failed || a->used + n > ARENA_SIZE) { a->failed = 1; return NULL; }
    void *p = a->buf + a->used;
    a->used += n;
    return p;
}

/* --------------------------- minimal JSON parser ------------------------- */
enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ };

typedef struct JVal JVal;
struct JVal {
    int type;
    int boolean;
    double num;
    char *str;
    JVal **items;
    size_t nitems;
    struct { char *key; JVal *val; } *mem;
    size_t nmem;
};

typedef struct {
    const char *p;
    const char *end;
    Arena *ar;
    int err;
    int depth;
} JParser;

static void j_fail(JParser *ps) { ps->err = 1; }

static void j_ws(JParser *ps) {
    while (ps->p < ps->end &&
           (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r'))
        ps->p++;
}

static JVal *j_new(JParser *ps, int type) {
    JVal *v = (JVal *)arena_alloc(ps->ar, sizeof(JVal));
    if (!v) { j_fail(ps); return NULL; }
    memset(v, 0, sizeof(*v));
    v->type = type;
    return v;
}

static void j_utf8(JParser *ps, unsigned long cp, char **out, size_t *n) {
    unsigned char tmp[4];
    size_t len;
    if (cp <= 0x7F) { tmp[0] = (unsigned char)cp; len = 1; }
    else if (cp <= 0x7FF) {
        tmp[0] = (unsigned char)(0xC0 | (cp >> 6));
        tmp[1] = (unsigned char)(0x80 | (cp & 0x3F));
        len = 2;
    } else if (cp <= 0xFFFF) {
        tmp[0] = (unsigned char)(0xE0 | (cp >> 12));
        tmp[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        tmp[2] = (unsigned char)(0x80 | (cp & 0x3F));
        len = 3;
    } else {
        tmp[0] = (unsigned char)(0xF0 | (cp >> 18));
        tmp[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
        tmp[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        tmp[3] = (unsigned char)(0x80 | (cp & 0x3F));
        len = 4;
    }
    if (*n + len + 1 > 4096) { j_fail(ps); return; }
    memcpy(*out + *n, tmp, len);
    *n += len;
    (*out)[*n] = 0;
}

static int j_hex4(JParser *ps, unsigned long *out) {
    if (ps->end - ps->p < 4) { j_fail(ps); return 0; }
    unsigned long v = 0;
    for (int i = 0; i < 4; i++) {
        char c = *ps->p++;
        v <<= 4;
        if (c >= '0' && c <= '9') v += (unsigned long)(c - '0');
        else if (c >= 'a' && c <= 'f') v += (unsigned long)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v += (unsigned long)(c - 'A' + 10);
        else { j_fail(ps); return 0; }
    }
    *out = v;
    return 1;
}

static char *j_string(JParser *ps) {
    if (ps->p >= ps->end || *ps->p != '"') { j_fail(ps); return NULL; }
    ps->p++;
    char *out = (char *)arena_alloc(ps->ar, 4096);
    if (!out) { j_fail(ps); return NULL; }
    size_t n = 0;
    while (ps->p < ps->end) {
        char c = *ps->p++;
        if (c == '"') { out[n] = 0; return out; }
        if ((unsigned char)c < 0x20) { j_fail(ps); return NULL; }
        if (c != '\\') {
            if (n + 2 > 4095) { j_fail(ps); return NULL; }
            out[n++] = c;
            continue;
        }
        if (ps->p >= ps->end) break;
        char e = *ps->p++;
        switch (e) {
        case '"': case '\\': case '/': out[n++] = e; break;
        case 'b': out[n++] = '\b'; break;
        case 'f': out[n++] = '\f'; break;
        case 'n': out[n++] = '\n'; break;
        case 'r': out[n++] = '\r'; break;
        case 't': out[n++] = '\t'; break;
        case 'u': {
            unsigned long cp;
            if (!j_hex4(ps, &cp)) return NULL;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                if (ps->end - ps->p >= 2 && ps->p[0] == '\\' && ps->p[1] == 'u') {
                    ps->p += 2;
                    unsigned long lo;
                    if (!j_hex4(ps, &lo)) return NULL;
                    if (lo >= 0xDC00 && lo <= 0xDFFF)
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    else { j_fail(ps); return NULL; }
                } else { j_fail(ps); return NULL; }
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                j_fail(ps);
                return NULL;
            }
            j_utf8(ps, cp, &out, &n);
            if (ps->err) return NULL;
            break;
        }
        default: j_fail(ps); return NULL;
        }
    }
    j_fail(ps);
    return NULL;
}

static int j_digits(JParser *ps) {
    const char *start = ps->p;
    while (ps->p < ps->end && isdigit((unsigned char)*ps->p)) ps->p++;
    return ps->p > start;
}

static JVal *j_number(JParser *ps) {
    const char *start = ps->p;
    if (ps->p < ps->end && *ps->p == '-') ps->p++;
    if (ps->p >= ps->end) { j_fail(ps); return NULL; }
    if (*ps->p == '0') ps->p++;
    else {
        if (!isdigit((unsigned char)*ps->p) || !j_digits(ps)) { j_fail(ps); return NULL; }
    }
    if (ps->p < ps->end && *ps->p == '.') {
        ps->p++;
        if (!j_digits(ps)) { j_fail(ps); return NULL; }
    }
    if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
        ps->p++;
        if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-')) ps->p++;
        if (!j_digits(ps)) { j_fail(ps); return NULL; }
    }
    JVal *v = j_new(ps, J_NUM);
    if (!v) return NULL;
    char buf[64];
    size_t len = (size_t)(ps->p - start);
    if (len == 0 || len >= sizeof(buf)) { j_fail(ps); return NULL; }
    memcpy(buf, start, len);
    buf[len] = 0;
    v->num = strtod(buf, NULL);
    return v;
}

static JVal *j_value(JParser *ps);

static JVal *j_object(JParser *ps) {
    JVal *v = j_new(ps, J_OBJ);
    if (!v) return NULL;
    ps->p++; /* { */
    j_ws(ps);
    if (ps->p < ps->end && *ps->p == '}') { ps->p++; return v; }
    for (;;) {
        j_ws(ps);
        char *key = j_string(ps);
        if (ps->err) return NULL;
        j_ws(ps);
        if (ps->p >= ps->end || *ps->p != ':') { j_fail(ps); return NULL; }
        ps->p++;
        j_ws(ps);
        JVal *val = j_value(ps);
        if (ps->err) return NULL;
        /* RFC 8259: duplicate member names give unpredictable results;
           reject them instead of picking first- or last-wins (header
           splitting / alg-confusion hardening). */
        for (size_t k = 0; k < v->nmem; k++)
            if (strcmp(v->mem[k].key, key) == 0) { j_fail(ps); return NULL; }
        size_t cap = (v->nmem + 1) * sizeof(v->mem[0]);
        void *grown = arena_alloc(ps->ar, cap);
        if (!grown) { j_fail(ps); return NULL; }
        if (v->mem) memcpy(grown, v->mem, v->nmem * sizeof(v->mem[0]));
        v->mem = grown;
        v->mem[v->nmem].key = key;
        v->mem[v->nmem].val = val;
        v->nmem++;
        j_ws(ps);
        if (ps->p >= ps->end) { j_fail(ps); return NULL; }
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == '}') { ps->p++; return v; }
        j_fail(ps);
        return NULL;
    }
}

static JVal *j_array(JParser *ps) {
    JVal *v = j_new(ps, J_ARR);
    if (!v) return NULL;
    ps->p++; /* [ */
    j_ws(ps);
    if (ps->p < ps->end && *ps->p == ']') { ps->p++; return v; }
    for (;;) {
        j_ws(ps);
        JVal *val = j_value(ps);
        if (ps->err) return NULL;
        size_t cap = (v->nitems + 1) * sizeof(v->items[0]);
        void *grown = arena_alloc(ps->ar, cap);
        if (!grown) { j_fail(ps); return NULL; }
        if (v->items) memcpy(grown, v->items, v->nitems * sizeof(v->items[0]));
        v->items = grown;
        v->items[v->nitems++] = val;
        j_ws(ps);
        if (ps->p >= ps->end) { j_fail(ps); return NULL; }
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == ']') { ps->p++; return v; }
        j_fail(ps);
        return NULL;
    }
}

static JVal *j_value(JParser *ps) {
    if (++ps->depth > MAX_DEPTH) { j_fail(ps); return NULL; }
    j_ws(ps);
    if (ps->p >= ps->end) { j_fail(ps); return NULL; }
    JVal *v;
    switch (*ps->p) {
    case '{': v = j_object(ps); break;
    case '[': v = j_array(ps); break;
    case '"': v = j_new(ps, J_STR); if (v) { v->str = j_string(ps); if (ps->err) return NULL; } break;
    case 't':
        if (ps->end - ps->p >= 4 && memcmp(ps->p, "true", 4) == 0) {
            ps->p += 4; v = j_new(ps, J_BOOL); if (v) v->boolean = 1;
        } else { j_fail(ps); return NULL; }
        break;
    case 'f':
        if (ps->end - ps->p >= 5 && memcmp(ps->p, "false", 5) == 0) {
            ps->p += 5; v = j_new(ps, J_BOOL); if (v) v->boolean = 0;
        } else { j_fail(ps); return NULL; }
        break;
    case 'n':
        if (ps->end - ps->p >= 4 && memcmp(ps->p, "null", 4) == 0) {
            ps->p += 4; v = j_new(ps, J_NULL);
        } else { j_fail(ps); return NULL; }
        break;
    default:
        if (*ps->p == '-' || isdigit((unsigned char)*ps->p)) v = j_number(ps);
        else { j_fail(ps); return NULL; }
    }
    ps->depth--;
    return v;
}

static JVal *j_parse(const char *s, size_t len, Arena *ar) {
    JParser ps = { s, s + len, ar, 0, 0 };
    j_ws(&ps);
    JVal *v = j_value(&ps);
    if (ps.err) return NULL;
    j_ws(&ps);
    if (ps.p != ps.end) return NULL;
    return v;
}

static JVal *j_obj_get(const JVal *o, const char *key) {
    if (!o || o->type != J_OBJ) return NULL;
    for (size_t i = 0; i < o->nmem; i++)
        if (strcmp(o->mem[i].key, key) == 0) return o->mem[i].val;
    return NULL;
}

static const char *j_str_get(const JVal *o, const char *key) {
    JVal *v = j_obj_get(o, key);
    if (!v || v->type != J_STR || v->str[0] == 0) return NULL;
    return v->str;
}

/* ----------------------------- base64url --------------------------------- */
static int b64url_decode(const char *s, size_t n, unsigned char *out,
                         size_t cap, size_t *out_n) {
    static signed char tab[256];
    static int init = 0;
    if (!init) {
        memset(tab, -1, sizeof(tab));
        for (int c = 'A'; c <= 'Z'; c++) tab[c] = (signed char)(c - 'A');
        for (int c = 'a'; c <= 'z'; c++) tab[c] = (signed char)(c - 'a' + 26);
        for (int c = '0'; c <= '9'; c++) tab[c] = (signed char)(c - '0' + 52);
        tab[(unsigned char)'-'] = 62;
        tab[(unsigned char)'_'] = 63;
        init = 1;
    }
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        signed char val = tab[c];
        if (val < 0) return -1;          /* padding/whitespace also rejected */
        acc = (acc << 6) | (uint32_t)val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (unsigned char)((acc >> bits) & 0xFF);
        }
    }
    *out_n = o;
    return 0;
}

/* ------------------------------- keyring --------------------------------- */
typedef struct {
    char kid[KID_MAX];
    char alg[ALG_MAX];
    EVP_PKEY *pkey;
} KeyEntry;

typedef struct {
    KeyEntry items[KEYRING_MAX];
    int count;
} Keyring;

static void keyring_free(Keyring *kr) {
    for (int i = 0; i < kr->count; i++) EVP_PKEY_free(kr->items[i].pkey);
    kr->count = 0;
}

static int keyring_load(Keyring *kr, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "keyring: cannot open %s\n", path); return -1; }
    char line[1024];
    int rc = -1;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == 0) continue;
        char kid[KID_MAX], alg[ALG_MAX], pem[512];
        if (sscanf(p, "%63s %15s %511s", kid, alg, pem) != 3) {
            fprintf(stderr, "keyring: bad line: %s", line);
            goto out;
        }
        if (strcmp(alg, "RS256") != 0 && strcmp(alg, "ES256") != 0) {
            fprintf(stderr, "keyring: unsupported alg %s for %s\n", alg, kid);
            goto out;
        }
        for (int i = 0; i < kr->count; i++) {
            if (strcmp(kr->items[i].kid, kid) == 0) {
                fprintf(stderr, "keyring: duplicate kid %s\n", kid);
                goto out;
            }
        }
        if (kr->count >= KEYRING_MAX) { fprintf(stderr, "keyring: full\n"); goto out; }
        FILE *kf = fopen(pem, "r");
        if (!kf) { fprintf(stderr, "keyring: cannot open key %s\n", pem); goto out; }
        EVP_PKEY *pkey = PEM_read_PUBKEY(kf, NULL, NULL, NULL);
        fclose(kf);
        if (!pkey) { fprintf(stderr, "keyring: bad PEM %s\n", pem); goto out; }
        int base = EVP_PKEY_base_id(pkey);
        if (strcmp(alg, "RS256") == 0) {
            if (base != EVP_PKEY_RSA || EVP_PKEY_get_bits(pkey) < 2048) {
                fprintf(stderr, "keyring: %s is not an RSA key >= 2048 bits\n", kid);
                EVP_PKEY_free(pkey);
                goto out;
            }
        } else {
            char gname[64] = {0};
            if (base != EVP_PKEY_EC ||
                EVP_PKEY_get_group_name(pkey, gname, sizeof(gname), NULL) == 0 ||
                strcmp(gname, "prime256v1") != 0) {
                fprintf(stderr, "keyring: %s is not a P-256 EC key\n", kid);
                EVP_PKEY_free(pkey);
                goto out;
            }
        }
        KeyEntry *e = &kr->items[kr->count++];
        snprintf(e->kid, sizeof(e->kid), "%s", kid);
        snprintf(e->alg, sizeof(e->alg), "%s", alg);
        e->pkey = pkey;
    }
    rc = 0;
out:
    fclose(f);
    return rc;
}

static const KeyEntry *keyring_find(const Keyring *kr, const char *kid) {
    for (int i = 0; i < kr->count; i++)
        if (strcmp(kr->items[i].kid, kid) == 0) return &kr->items[i];
    return NULL;
}

/* --------------------------- signature primitives ------------------------ */
/* ES256 JWT signatures are raw R||S (64 bytes); OpenSSL wants DER. */
static int es256_raw_to_der(const unsigned char *raw, size_t rawlen,
                            unsigned char *der, size_t dercap, size_t *derlen) {
    if (rawlen != 64) return -1;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(raw, 32, NULL);
    BIGNUM *s = BN_bin2bn(raw + 32, 32, NULL);
    if (!sig || !r || !s) {
        BN_free(r); BN_free(s); ECDSA_SIG_free(sig);
        return -1;
    }
    ECDSA_SIG_set0(sig, r, s); /* ownership transferred */
    int len = i2d_ECDSA_SIG(sig, NULL);
    if (len <= 0 || (size_t)len > dercap) { ECDSA_SIG_free(sig); return -1; }
    unsigned char *p = der;
    i2d_ECDSA_SIG(sig, &p);
    *derlen = (size_t)len;
    ECDSA_SIG_free(sig);
    return 0;
}

static int digest_verify(EVP_PKEY *pkey, const char *alg,
                         const unsigned char *tbs, size_t tbslen,
                         const unsigned char *sig, size_t siglen) {
    unsigned char der[128];
    size_t derlen = 0;
    const unsigned char *sigbuf = sig;
    size_t sigbuflen = siglen;
    if (strcmp(alg, "ES256") == 0) {
        if (es256_raw_to_der(sig, siglen, der, sizeof(der), &derlen) != 0)
            return 0;
        sigbuf = der;
        sigbuflen = derlen;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;
    if (ctx &&
        EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestUpdate(ctx, tbs, tbslen) == 1) {
        int rc = EVP_DigestVerifyFinal(ctx, sigbuf, sigbuflen);
        ok = (rc == 1); /* 0 = bad signature, <0 = malformed/error: both fail */
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* ------------------------------ verification ----------------------------- */
static int ascii_ieq(const char *a, const char *b) {
    while (*a && *b) {
        int ca = tolower((unsigned char)*a++);
        int cb = tolower((unsigned char)*b++);
        if (ca != cb) return 0;
    }
    return *a == 0 && *b == 0;
}

static int time_claim(const JVal *obj, const char *key, long long *out) {
    JVal *v = j_obj_get(obj, key);
    if (!v || v->type != J_NUM) return -1;
    double d = v->num;
    if (!(d > -1.0e18 && d < 1.0e18)) return -1;
    *out = (long long)d;
    return 0;
}

static Reason verify_token(const Keyring *kr, const char *token,
                           long long now, long long leeway,
                           const KeyEntry **used_out) {
    size_t tlen = strlen(token);
    if (tlen == 0 || tlen >= TOKEN_MAX) return R_MALFORMED;
    for (size_t i = 0; i < tlen; i++)
        if ((unsigned char)token[i] < 0x21 || (unsigned char)token[i] > 0x7E)
            return R_MALFORMED;

    /* exactly two separators, three segments; empty signature tolerated
       here so that alg=none tokens are classified as alg_none, not malformed */
    const char *dot1 = strchr(token, '.');
    if (!dot1) return R_MALFORMED;
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2 || strchr(dot2 + 1, '.') != NULL) return R_MALFORMED;
    const char *h_b64 = token, *p_b64 = dot1 + 1, *s_b64 = dot2 + 1;
    size_t h_len = (size_t)(dot1 - token);
    size_t p_len = (size_t)(dot2 - dot1 - 1);
    size_t s_len = strlen(s_b64);
    if (h_len == 0 || p_len == 0) return R_MALFORMED;

    Reason rc = R_MALFORMED;
    unsigned char *h_raw = (unsigned char *)malloc(DECODE_MAX);
    unsigned char *p_raw = (unsigned char *)malloc(DECODE_MAX);
    unsigned char *s_raw = (unsigned char *)malloc(DECODE_MAX);
    Arena ar = { NULL, 0, 0 };
    if (!h_raw || !p_raw || !s_raw) { rc = R_MALFORMED; goto done; }
    size_t h_n = 0, p_n = 0, s_n = 0;
    if (b64url_decode(h_b64, h_len, h_raw, DECODE_MAX, &h_n) != 0 ||
        b64url_decode(p_b64, p_len, p_raw, DECODE_MAX, &p_n) != 0 ||
        b64url_decode(s_b64, s_len, s_raw, DECODE_MAX, &s_n) != 0)
        goto done;

    arena_init(&ar);
    if (ar.failed) goto done;
    JVal *hdr = j_parse((char *)h_raw, h_n, &ar);
    JVal *pay = j_parse((char *)p_raw, p_n, &ar);
    if (!hdr || hdr->type != J_OBJ || !pay || pay->type != J_OBJ) goto done;

    const char *alg = j_str_get(hdr, "alg");
    if (!alg) goto done;
    if (ascii_ieq(alg, "none")) { rc = R_ALG_NONE; goto done; }
    if (strcmp(alg, "RS256") != 0 && strcmp(alg, "ES256") != 0) {
        rc = R_ALG_CONFUSION;
        goto done;
    }
    /* token-supplied key material is never consulted */
    if (j_obj_get(hdr, "jwk") || j_obj_get(hdr, "jku") ||
        j_obj_get(hdr, "x5u") || j_obj_get(hdr, "x5c")) {
        rc = R_UNTRUSTED_HEADER;
        goto done;
    }
    const char *kid = j_str_get(hdr, "kid");
    if (!kid) { rc = R_MISSING_KID; goto done; }
    if (strlen(kid) >= KID_MAX) { rc = R_UNKNOWN_KID; goto done; }

    const KeyEntry *entry = keyring_find(kr, kid);
    if (!entry) { rc = R_UNKNOWN_KID; goto done; }
    /* the keyring pins the alg: header alg must match, no downgrade/swaps */
    if (strcmp(entry->alg, alg) != 0) { rc = R_ALG_CONFUSION; goto done; }

    if (!digest_verify(entry->pkey, alg, (const unsigned char *)token,
                       (size_t)(dot2 - token), s_raw, s_n)) {
        rc = R_BAD_SIG;
        goto done;
    }

    long long exp, nbf;
    if (time_claim(pay, "exp", &exp) != 0 || time_claim(pay, "nbf", &nbf) != 0) {
        rc = R_MISSING_CLAIM;
        goto done;
    }
    if (now > exp + leeway) { rc = R_EXPIRED; goto done; }
    if (now + leeway < nbf) { rc = R_NOT_YET; goto done; }

    rc = R_OK;
    if (used_out) *used_out = entry;
done:
    free(ar.buf);
    free(h_raw);
    free(p_raw);
    free(s_raw);
    return rc;
}

/* --------------------------------- CLI ----------------------------------- */
static int cmd_verify(int argc, char **argv) {
    if (argc < 4 || argc > 6) {
        fprintf(stderr, "usage: jwtguard verify <keyring.conf> <token> [leeway [now]]\n");
        return 2;
    }
    Keyring kr;
    memset(&kr, 0, sizeof(kr));
    if (keyring_load(&kr, argv[2]) != 0) { keyring_free(&kr); return 2; }
    long long leeway = argc > 4 ? strtoll(argv[4], NULL, 10) : 0;
    long long now = argc > 5 ? strtoll(argv[5], NULL, 10) : (long long)time(NULL);
    const KeyEntry *used = NULL;
    Reason r = verify_token(&kr, argv[3], now, leeway, &used);
    if (r == R_OK)
        printf("verdict=ok reason=ok kid=%s alg=%s\n", used->kid, used->alg);
    else
        printf("verdict=reject reason=%s\n", reason_str(r));
    keyring_free(&kr);
    return r == R_OK ? 0 : 1;
}

static int cmd_batch(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: jwtguard batch <keyring.conf> <cases.tsv>\n");
        return 2;
    }
    Keyring kr;
    memset(&kr, 0, sizeof(kr));
    if (keyring_load(&kr, argv[2]) != 0) { keyring_free(&kr); return 2; }
    FILE *f = fopen(argv[3], "r");
    if (!f) { fprintf(stderr, "batch: cannot open %s\n", argv[3]); keyring_free(&kr); return 2; }
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, f) != -1) {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = 0;
        if (len == 0) continue;
        char *id = strtok(line, "\t");
        char *leeway_s = strtok(NULL, "\t");
        char *now_s = strtok(NULL, "\t");
        char *token = strtok(NULL, "\t");
        if (!id || !leeway_s || !now_s || !token || strtok(NULL, "\t")) {
            printf("%s\treject\tmalformed\n", id ? id : "?");
            continue;
        }
        long long leeway = strtoll(leeway_s, NULL, 10);
        long long now = strtoll(now_s, NULL, 10);
        Reason r = verify_token(&kr, token, now, leeway, NULL);
        printf("%s\t%s\t%s\n", id, r == R_OK ? "ok" : "reject", reason_str(r));
    }
    free(line);
    fclose(f);
    keyring_free(&kr);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "verify") == 0)
        return cmd_verify(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "batch") == 0)
        return cmd_batch(argc, argv);
    fprintf(stderr, "usage: jwtguard verify|batch ...\n");
    return 2;
}
