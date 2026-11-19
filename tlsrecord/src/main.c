
/* tlsrecord test driver.
   ./tlsrecord                 built-in self-tests (key=value, all_ok=1)
   ./tlsrecord dump <file> [s] parse a vector and dump a normalized,
                               field-by-field trace for reference parity
   ./tlsrecord bench           timing + fixed memory upper bound report */
#define _POSIX_C_SOURCE 199309L
#include "tlsrecord.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---------- wire builders (shared by self-tests and the trace) ---------- */

static size_t put_record(uint8_t* out, uint8_t type, uint16_t ver,
                         const uint8_t* body, uint16_t len) {
    out[0] = type;
    out[1] = (uint8_t)(ver >> 8);
    out[2] = (uint8_t)(ver & 0xff);
    out[3] = (uint8_t)(len >> 8);
    out[4] = (uint8_t)(len & 0xff);
    if (len) memcpy(out + 5, body, len);
    return 5 + len;
}

static size_t put_hs_frag(uint8_t* out, uint8_t htype, uint32_t hlen,
                          uint16_t mseq, uint32_t foff,
                          const uint8_t* frag, uint32_t flen) {
    out[0] = htype;
    out[1] = (uint8_t)(hlen >> 16);
    out[2] = (uint8_t)(hlen >> 8);
    out[3] = (uint8_t)(hlen & 0xff);
    out[4] = (uint8_t)(mseq >> 8);
    out[5] = (uint8_t)(mseq & 0xff);
    out[6] = (uint8_t)(foff >> 16);
    out[7] = (uint8_t)(foff >> 8);
    out[8] = (uint8_t)(foff & 0xff);
    out[9]  = (uint8_t)(flen >> 16);
    out[10] = (uint8_t)(flen >> 8);
    out[11] = (uint8_t)(flen & 0xff);
    if (flen) memcpy(out + 12, frag, flen);
    return 12 + flen;
}

static const char* tname(uint8_t type) {
    switch (type) {
    case 20: return "change_cipher_spec";
    case 21: return "alert";
    case 22: return "handshake";
    case 23: return "application_data";
    default: return "unknown";
    }
}

/* ---------- dump mode: normalized trace for reference-parser parity ---------- */

static uint32_t get_u24(const uint8_t* p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static uint16_t get_u16(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static int dump_trace(const char* path, int est, int ccs_after) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror(path); return 2; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 4 * 1024 * 1024) { fprintf(stderr, "bad size\n"); return 2; }
    uint8_t* buf = (uint8_t*)malloc((size_t)sz);
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { fprintf(stderr, "short read\n"); return 2; }
    fclose(f);

    TlsRecordLayer* ctx = (TlsRecordLayer*)calloc(1, sizeof(TlsRecordLayer));
    trl_init(ctx, ccs_after);
    if (est) trl_mark_established(ctx);

    uint64_t stream_pos = 0;
    size_t off = 0;
    int rc = TRL_OK;
    while (off < (size_t)sz) {
        if (off + 5 > (size_t)sz) {
            rc = trl_feed(ctx, buf + off, sz - off);
            if (rc == TRL_OK) rc = trl_finish(ctx);
            break;
        }
        uint8_t type = buf[off];
        uint16_t ver = get_u16(buf + off + 1);
        uint16_t len = get_u16(buf + off + 3);
        printf("record type=%s(%u) ver=0x%04x len=%u offset=%llu\n",
               tname(type), type, ver, len, (unsigned long long)stream_pos);
        if (len > TRL_MAX_RECORD_PLAINTEXT) {
            rc = trl_feed(ctx, buf + off, 5);
            break;
        }
        size_t total = 5 + len;
        if (off + total > (size_t)sz) {
            rc = trl_feed(ctx, buf + off, sz - off);
            if (rc == TRL_OK) rc = trl_finish(ctx);
            break;
        }
        if (type == 22 && !ctx->established) {
            size_t p = off + 5;
            size_t end = off + 5 + len;
            while (p < end) {
                if (end - p < 12) {
                    printf("  fragment truncated=1 remain=%u\n",
                           (unsigned)(end - p));
                    break;
                }
                uint8_t ht = buf[p];
                uint32_t hl = get_u24(buf + p + 1);
                uint16_t ms = get_u16(buf + p + 4);
                uint32_t fo = get_u24(buf + p + 6);
                uint32_t fl = get_u24(buf + p + 9);
                printf("  fragment hs_type=%u hs_len=%u seq=%u frag_off=%u frag_len=%u\n",
                       ht, hl, ms, fo, fl);
                if (p + 12 + fl > end) {
                    printf("  fragment truncated=1 remain=%u\n",
                           (unsigned)(end - p - 12));
                    break;
                }
                p += 12 + fl;
            }
        } else if (type == 21 && len == 2) {
            printf("  alert level=%u desc=%u\n", buf[off + 5], buf[off + 6]);
        }
        rc = trl_feed(ctx, buf + off, total);
        if (rc != TRL_OK) break;
        off += total;
        stream_pos += total;
    }
    if (rc == TRL_OK) rc = trl_finish(ctx);

    printf("result=%s", trl_err_name(rc));
    if (rc != TRL_OK) printf(" code=%d detail=%u", rc, ctx->last_detail);
    printf("\n");
    printf("stats records=%llu hs_messages=%llu fragments=%llu reordered=%llu duplicates=%llu dup_bytes=%llu alerts=%llu app_bytes=%zu\n",
           (unsigned long long)ctx->n_records,
           (unsigned long long)ctx->n_hs_messages,
           (unsigned long long)ctx->n_frags,
           (unsigned long long)ctx->n_reordered,
           (unsigned long long)ctx->n_duplicates,
           (unsigned long long)ctx->dup_bytes,
           (unsigned long long)ctx->n_alerts,
           ctx->app_len);
    const char* http = trl_http_ingest(ctx);
    printf("http=%s\n", http ? http : "none");

    int fail = rc;
    free(buf);
    free(ctx);
    return fail ? 1 : 0;
}

/* ---------- built-in self-tests ---------- */

static int failures = 0;
static void check(const char* name, int ok) {
    printf("%s=%d\n", name, ok ? 1 : 0);
    if (!ok) failures++;
}

static void feed_bytewise(TlsRecordLayer* ctx, const uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        int rc = trl_feed(ctx, buf + i, 1);
        if (rc != TRL_OK) { check("feed_no_error", 0); return; }
    }
}

static void self_test(void) {
    TlsRecordLayer c;
    uint8_t wire[2048];
    uint8_t msg[64];
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)(i + 1);

    /* simple application_data, whole and bytewise */
    trl_init(&c, 0);
    size_t n = put_record(wire, 23, 0x0303, (const uint8_t*)"PING", 4);
    check("app_ok", trl_feed(&c, wire, n) == TRL_OK && c.app_len == 4);

    trl_init(&c, 0);
    feed_bytewise(&c, wire, n);
    check("app_bytewise_ok", c.rec_have == 0 && c.app_len == 4);

    /* split record header across feeds */
    trl_init(&c, 0);
    check("split_hdr_1", trl_feed(&c, wire, 2) == TRL_OK);
    check("split_hdr_2", trl_feed(&c, wire + 2, 3) == TRL_OK);
    check("split_hdr_3", trl_feed(&c, wire + 5, 4) == TRL_OK && c.app_len == 4);

    /* type whitelist: 24 is not a TLS content type */
    trl_init(&c, 0);
    uint8_t badtype[] = {24, 0x03, 0x03, 0x00, 0x01, 0x01};
    check("bad_type", trl_feed(&c, badtype, sizeof(badtype)) == TRL_BAD_TYPE);
    trl_init(&c, 0);
    trl_allow_type(&c, 24);
    check("type_whitelist_extended", trl_feed(&c, badtype, sizeof(badtype)) == TRL_OK);

    /* length consistency: oversized, zero-length, bad CCS / alert sizes */
    trl_init(&c, 0);
    uint8_t over[] = {23, 0x03, 0x03, 0x40, 0x01}; /* 16385 */
    check("record_too_large", trl_feed(&c, over, sizeof(over)) == TRL_RECORD_TOO_LARGE);

    trl_init(&c, 0);
    uint8_t zero[] = {23, 0x03, 0x03, 0x00, 0x00};
    check("zero_len", trl_feed(&c, zero, sizeof(zero)) == TRL_LEN_MISMATCH);    trl_init(&c, 0);
    uint8_t ccs2[] = {20, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02};
    check("ccs_bad_len", trl_feed(&c, ccs2, sizeof(ccs2)) == TRL_LEN_MISMATCH);

    trl_init(&c, 0);
    uint8_t alert3[] = {21, 0x03, 0x03, 0x00, 0x03, 0x02, 0x28, 0x00};
    check("alert_bad_len", trl_feed(&c, alert3, sizeof(alert3)) == TRL_LEN_MISMATCH);

    /* versions */
    trl_init(&c, 0);
    uint8_t ssl30[] = {23, 0x03, 0x00, 0x00, 0x01, 0x41};
    check("bad_version", trl_feed(&c, ssl30, sizeof(ssl30)) == TRL_BAD_VERSION);
    trl_init(&c, 0);
    uint8_t tls10[] = {23, 0x03, 0x01, 0x00, 0x01, 0x41};
    check("tls10_ok", trl_feed(&c, tls10, sizeof(tls10)) == TRL_OK);

    /* handshake fragments: in-order split then reassembled */
    trl_init(&c, 0);
    uint8_t hsbuf[256];
    size_t hp = 0;
    hp += put_hs_frag(hsbuf + hp, 22, 40, 0, 0, msg, 20);
    hp += put_hs_frag(hsbuf + hp, 22, 40, 0, 20, msg + 20, 20);
    uint8_t hsrec[300];
    size_t hn = put_record(hsrec, 22, 0x0303, hsbuf, (uint16_t)hp);
    check("hs_reassemble_ok", trl_feed(&c, hsrec, hn) == TRL_OK &&
          c.n_hs_messages == 1 && memcmp(c.hs, msg, 40) == 0);

    /* gap => reorder detected */
    trl_init(&c, 0);
    hp = 0;
    hp += put_hs_frag(hsbuf + hp, 22, 40, 0, 0, msg, 20);
    hp += put_hs_frag(hsbuf + hp, 22, 40, 0, 25, msg + 25, 15);
    hn = put_record(hsrec, 22, 0x0303, hsbuf, (uint16_t)hp);
    check("hs_reorder_detected", trl_feed(&c, hsrec, hn) == TRL_HS_REORDER);

    /* overlapping fragment with a changed byte => overlap */
    trl_init(&c, 0);
    hp = 0;
    uint8_t tampered[20];
    memcpy(tampered, msg + 10, 20);
    tampered[0] ^= 0xff;
    hp += put_hs_frag(hsbuf + hp, 22, 40, 0, 0, msg, 20);
    hp += put_hs_frag(hsbuf + hp, 22, 40, 0, 10, tampered, 20);
    hn = put_record(hsrec, 22, 0x0303, hsbuf, (uint16_t)hp);
    check("hs_overlap_detected", trl_feed(&c, hsrec, hn) == TRL_HS_OVERLAP);

    /* identical retransmit of an already-covered range: accepted */
    trl_init(&c, 0);
    hp = 0;
    hp += put_hs_frag(hsbuf + hp, 22, 40, 0, 0, msg, 20);
    hp += put_hs_frag(hsbuf + hp, 22, 40, 0, 0, msg, 20);
    hp += put_hs_frag(hsbuf + hp, 22, 40, 0, 20, msg + 20, 20);
    hn = put_record(hsrec, 22, 0x0303, hsbuf, (uint16_t)hp);
    check("hs_dup_retransmit_ok", trl_feed(&c, hsrec, hn) == TRL_OK &&
          c.n_duplicates == 1 && c.dup_bytes == 20 && c.n_hs_messages == 1);

    /* fragment claiming more than the message's total length */
    trl_init(&c, 0);
    hp = put_hs_frag(hsbuf, 22, 20, 0, 0, msg, 21);
    hn = put_record(hsrec, 22, 0x0303, hsbuf, (uint16_t)hp);
    check("hs_len_conflict", trl_feed(&c, hsrec, hn) == TRL_HS_LEN_CONFLICT);

    /* fragment header whose bytes run past the record => truncated */
    trl_init(&c, 0);
    uint8_t trunc_rec[] = {22, 0x03, 0x03, 0x00, 0x08,
                           22, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00};
    check("hs_truncated", trl_feed(&c, trunc_rec, sizeof(trunc_rec)) == TRL_HS_TRUNCATED);

    /* half record at end of stream */
    trl_init(&c, 0);
    trl_feed(&c, wire, 3);
    check("truncated_stream", trl_finish(&c) == TRL_TRUNCATED_STREAM);

    /* renegotiation: handshake after establishment */
    trl_init(&c, 0);
    trl_mark_established(&c);
    hn = put_record(hsrec, 22, 0x0303, hsbuf,
                    (uint16_t)put_hs_frag(hsbuf, 0, 0, 0, 0, NULL, 0));
    check("renegotiation", trl_feed(&c, hsrec, hn) == TRL_RENEGOTIATION);

    /* CCS policy after establishment */
    trl_init(&c, 0);
    trl_mark_established(&c);
    uint8_t ccs[] = {20, 0x03, 0x03, 0x00, 0x01, 0x01};
    check("ccs_after_est_rejected", trl_feed(&c, ccs, sizeof(ccs)) == TRL_CCS_AFTER_ESTABLISHED);
    trl_init(&c, 1);
    trl_mark_established(&c);
    check("ccs_after_est_allowed", trl_feed(&c, ccs, sizeof(ccs)) == TRL_OK);

    /* alerts recorded */
    trl_init(&c, 0);
    uint8_t alert[] = {21, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
    check("alert_ok", trl_feed(&c, alert, sizeof(alert)) == TRL_OK &&
          c.n_alerts == 1 && c.last_alert_desc == 0x28);

    /* reqguard entry point: valid request and CL+TE smuggling */
    trl_init(&c, 0);
    const char* good = "GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
    n = put_record(wire, 23, 0x0303, (const uint8_t*)good, (uint16_t)strlen(good));
    trl_feed(&c, wire, n);
    check("http_ingest_ok", strcmp(trl_http_ingest(&c), "ok") == 0);

    trl_init(&c, 0);
    const char* smug = "POST /a HTTP/1.1\r\nContent-Length: 5\r\n"
                       "Transfer-Encoding: chunked\r\n\r\n";
    n = put_record(wire, 23, 0x0303, (const uint8_t*)smug, (uint16_t)strlen(smug));
    trl_feed(&c, wire, n);
    check("http_smuggling_caught", strcmp(trl_http_ingest(&c), "cl_te_conflict") == 0);

    /* multiple records inside one feed */
    trl_init(&c, 0);
    uint8_t multi[64];
    size_t mp = 0;
    mp += put_record(multi + mp, 23, 0x0303, (const uint8_t*)"AB", 2);
    mp += put_record(multi + mp, 23, 0x0303, (const uint8_t*)"CD", 2);
    check("multi_record_feed", trl_feed(&c, multi, mp) == TRL_OK &&
          c.n_records == 2 && c.app_len == 4);

    /* application_data buffer ceiling: fill 16384, then one more record */
    trl_init(&c, 0);
    static uint8_t fill[TRL_MAX_RECORD_PLAINTEXT];
    static uint8_t bigwire[5 + TRL_MAX_RECORD_PLAINTEXT];
    memset(fill, 0x42, sizeof(fill));
    n = put_record(bigwire, 23, 0x0303, fill, TRL_MAX_RECORD_PLAINTEXT);
    check("app_fill_to_bound", trl_feed(&c, bigwire, n) == TRL_OK &&
          c.app_len == TRL_MAX_RECORD_PLAINTEXT);
    n = put_record(wire, 23, 0x0303, (const uint8_t*)"X", 1);
    check("app_overflow", trl_feed(&c, wire, n) == TRL_APP_OVERFLOW);
}

/* ---------- benchmark: timing and fixed memory bound ---------- */

static void bench(void) {
    const size_t total = 64u << 20; /* 64 MiB of plaintext stream */
    uint8_t rec[5 + TRL_MAX_RECORD_PLAINTEXT];
    uint8_t body[TRL_MAX_RECORD_PLAINTEXT];
    memset(body, 0x41, sizeof(body));
    size_t rn = put_record(rec, 23, 0x0303, body, TRL_MAX_RECORD_PLAINTEXT);

    TlsRecordLayer* ctx = (TlsRecordLayer*)calloc(1, sizeof(TlsRecordLayer));
    trl_init(ctx, 0);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    size_t fed = 0;
    while (fed < total) {
        size_t chunk = rn;
        if (fed + chunk > total) chunk = total - fed;
        int rc = trl_feed(ctx, rec, chunk);
        if (rc != TRL_OK) { printf("bench error %s\n", trl_err_name(rc)); return; }
        fed += chunk;
        if (ctx->app_len + TRL_MAX_RECORD_PLAINTEXT > sizeof(ctx->app))
            ctx->app_len = 0; /* drain like the HTTP entry point would */
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                (t1.tv_nsec - t0.tv_nsec) / 1.0e6;
    double mbps = (double)fed / (1024.0 * 1024.0) / (ms / 1000.0);
    double ns_per_record = (ms * 1.0e6) / (double)ctx->n_records;

    printf("bench_bytes=%zu\n", fed);
    printf("bench_records=%llu\n", (unsigned long long)ctx->n_records);
    printf("bench_elapsed_ms=%.3f\n", ms);
    printf("bench_throughput_mib_s=%.1f\n", mbps);
    printf("bench_ns_per_record=%.1f\n", ns_per_record);
    printf("mem_context_bytes=%zu\n", sizeof(TlsRecordLayer));
    printf("mem_bound_bytes=%d\n", TRL_MEM_BOUND_BYTES);
    printf("mem_within_bound=%d\n", (int)sizeof(TlsRecordLayer) <= TRL_MEM_BOUND_BYTES);
    free(ctx);
}

int main(int argc, char** argv) {
    if (argc >= 2 && strcmp(argv[1], "dump") == 0) {
        if (argc < 3) { fprintf(stderr, "usage: tlsrecord dump <file> [sidecar]\n"); return 2; }
        int est = 0, ccs_after = 0;
        if (argc >= 4) {
            FILE* s = fopen(argv[3], "r");
            if (s) {
                char line[64];
                while (fgets(line, sizeof(line), s)) {
                    if (!strncmp(line, "established=1", 13)) est = 1;
                    if (!strncmp(line, "allow_ccs_after=1", 17)) ccs_after = 1;
                }
                fclose(s);
            }
        }
        return dump_trace(argv[2], est, ccs_after);
    }
    if (argc >= 2 && strcmp(argv[1], "bench") == 0) {
        bench();
        return failures;
    }
    self_test();
    printf("all_ok=%d\n", failures == 0);
    return failures == 0 ? 0 : 1;
}
