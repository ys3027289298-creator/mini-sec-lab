/* drv_json.h: tiny header-only JSON line protocol shared by every component
   driver. The checker speaks one protocol to all components:

     stdin  : one flat JSON object per line, e.g. {"op":"parse","request":"..."}
     stdout : one flat JSON object per line, in request order

   Only flat objects (string / number / bool / null values) are needed by the
   case manifests, so this is deliberately not a general JSON parser. */
#ifndef DRV_JSON_H
#define DRV_JSON_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#if defined(__GNUC__) || defined(__clang__)
#define DRV_MAYBE_UNUSED __attribute__((unused))
#else
#define DRV_MAYBE_UNUSED
#endif

#define JF_MAX 16
#define JS_MAX 8192
#define JLINE_MAX 16384

typedef struct {
    char key[64];
    int type; /* 's' string, 'n' number, 'b' bool, 'l' null */
    char s[JS_MAX];
    long num;
    int boolean;
} JField;

typedef struct {
    JField f[JF_MAX];
    int n;
} JObj;

static const char* j_skip_ws(const char* p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

static int j_utf8(char* out, size_t cap, size_t* oi, unsigned cp) {
    int n = cp < 0x80 ? 1 : cp < 0x800 ? 2 : 3;
    if (*oi + (size_t)n >= cap) return -1;
    if (n == 1) {
        out[(*oi)++] = (char)cp;
    } else if (n == 2) {
        out[(*oi)++] = (char)(0xC0 | (cp >> 6));
        out[(*oi)++] = (char)(0x80 | (cp & 0x3F));
    } else {
        out[(*oi)++] = (char)(0xE0 | (cp >> 12));
        out[(*oi)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[(*oi)++] = (char)(0x80 | (cp & 0x3F));
    }
    return 0;
}

/* parses a JSON string starting at *pp ('"'); advances past the closing quote */
static int j_parse_string(const char** pp, char* out, size_t cap) {
    const char* p = *pp;
    if (*p != '"') return -1;
    p++;
    size_t o = 0;
    while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\') {
            char e = *p++;
            switch (e) {
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            case '/': c = '/'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u': {
                if (!isxdigit((unsigned char)p[0]) || !isxdigit((unsigned char)p[1]) ||
                    !isxdigit((unsigned char)p[2]) || !isxdigit((unsigned char)p[3]))
                    return -1;
                unsigned cp = 0;
                for (int i = 0; i < 4; i++) {
                    char h = *p++;
                    int v = h <= '9' ? h - '0' : (tolower((unsigned char)h) - 'a' + 10);
                    cp = (cp << 4) | (unsigned)v;
                }
                if (j_utf8(out, cap, &o, cp) < 0) return -1;
                continue;
            }
            default: return -1;
            }
        }
        if (o + 1 >= cap) return -1;
        out[o++] = c;
    }
    if (*p != '"') return -1;
    out[o] = 0;
    *pp = p + 1;
    return 0;
}

/* parse one flat JSON object; returns 0 on success, -1 on malformed input */
static int jparse(const char* line, JObj* o) {
    o->n = 0;
    const char* p = j_skip_ws(line);
    if (*p++ != '{') return -1;
    p = j_skip_ws(p);
    if (*p == '}') return 0;
    while (o->n < JF_MAX) {
        p = j_skip_ws(p);
        JField* f = &o->f[o->n];
        if (j_parse_string(&p, f->key, sizeof(f->key)) < 0) return -1;
        p = j_skip_ws(p);
        if (*p++ != ':') return -1;
        p = j_skip_ws(p);
        if (*p == '"') {
            f->type = 's';
            if (j_parse_string(&p, f->s, sizeof(f->s)) < 0) return -1;
        } else if (*p == 't' || *p == 'f') {
            f->type = 'b';
            f->boolean = (*p == 't');
            p += f->boolean ? 4 : 5;
        } else if (*p == 'n') {
            f->type = 'l';
            p += 4;
        } else if (*p == '-' || isdigit((unsigned char)*p)) {
            f->type = 'n';
            char* end = NULL;
            f->num = strtol(p, &end, 10);
            if (end == p) return -1;
            p = end;
        } else {
            return -1;
        }
        o->n++;
        p = j_skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == '}') return 0;
        return -1;
    }
    return -1;
}

static const JField* jget(const JObj* o, const char* key) {
    for (int i = 0; i < o->n; i++)
        if (strcmp(o->f[i].key, key) == 0) return &o->f[i];
    return NULL;
}

static const char* jstr(const JObj* o, const char* key) {
    const JField* f = jget(o, key);
    return (f && f->type == 's') ? f->s : NULL;
}

/* ---- JSON reply writer --------------------------------------------------- */

typedef struct {
    char buf[JLINE_MAX];
    size_t len;
    int n;
} JOut;

static void jo_put(JOut* o, const char* s) {
    size_t add = strlen(s);
    if (o->len + add + 2 >= sizeof(o->buf)) return;
    memcpy(o->buf + o->len, s, add);
    o->len += add;
}

static void jo_putc(JOut* o, char c) {
    if (o->len + 2 >= sizeof(o->buf)) return;
    o->buf[o->len++] = c;
}

static void jo_escape(JOut* o, const char* v) {
    jo_putc(o, '"');
    for (const char* p = v; *p; p++) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
        case '"': jo_put(o, "\\\""); break;
        case '\\': jo_put(o, "\\\\"); break;
        case '\n': jo_put(o, "\\n"); break;
        case '\r': jo_put(o, "\\r"); break;
        case '\t': jo_put(o, "\\t"); break;
        default:
            if (c < 0x20) {
                char tmp[8];
                snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                jo_put(o, tmp);
            } else {
                jo_putc(o, (char)c);
            }
        }
    }
    jo_putc(o, '"');
}

static void jo_begin(JOut* o) {
    o->len = 0;
    o->n = 0;
    jo_putc(o, '{');
}

static void jo_sep(JOut* o, const char* key) {
    if (o->n) jo_putc(o, ',');
    o->n++;
    jo_escape(o, key);
    jo_putc(o, ':');
}

static void jo_str(JOut* o, const char* key, const char* val) {
    jo_sep(o, key);
    jo_escape(o, val ? val : "");
}

static DRV_MAYBE_UNUSED void jo_long(JOut* o, const char* key, long v) {
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%ld", v);
    jo_sep(o, key);
    jo_put(o, tmp);
}

static DRV_MAYBE_UNUSED void jo_ull(JOut* o, const char* key, unsigned long long v) {
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%llu", v);
    jo_sep(o, key);
    jo_put(o, tmp);
}

static DRV_MAYBE_UNUSED void jo_bool(JOut* o, const char* key, int v) {
    jo_sep(o, key);
    jo_put(o, v ? "true" : "false");
}

static DRV_MAYBE_UNUSED void jo_null(JOut* o, const char* key) {
    jo_sep(o, key);
    jo_put(o, "null");
}

static void jo_end(JOut* o) {
    jo_putc(o, '}');
    o->buf[o->len] = 0;
    fputs(o->buf, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

/* ---- helpers -------------------------------------------------------------- */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* decode hex string into bytes; returns 0 on success, -1 on bad input */
static DRV_MAYBE_UNUSED int hex_decode(const char* hex, unsigned char* out, size_t cap, size_t* out_len) {
    size_t n = strlen(hex);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hex_nibble(hex[i]), lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return 0;
}

#endif /* DRV_JSON_H */
