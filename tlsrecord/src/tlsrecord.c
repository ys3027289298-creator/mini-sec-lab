
/* tlsrecord core: record-stream reassembly and validation.
   See tlsrecord.h for the contract. The core is allocation-free. */
#include "tlsrecord.h"
#include <stdio.h>
#include <string.h>

/* The allocation-free core promises a fixed context ceiling. */
typedef char trl_mem_bound_check[(sizeof(TlsRecordLayer) <= TRL_MEM_BOUND_BYTES) ? 1 : -1];

#define TRL_DENY 0
#define TRL_ALLOW 1

const char* trl_err_name(int code) {
    switch (code) {
    case TRL_OK: return "ok";
    case TRL_RECORD_TOO_LARGE: return "record_too_large";
    case TRL_BAD_VERSION: return "bad_version";
    case TRL_BAD_TYPE: return "bad_type";
    case TRL_LEN_MISMATCH: return "length_mismatch";
    case TRL_HS_TRUNCATED: return "handshake_truncated";
    case TRL_HS_TOO_LARGE: return "handshake_too_large";
    case TRL_HS_OVERLAP: return "handshake_overlap";
    case TRL_HS_REORDER: return "handshake_reorder";
    case TRL_HS_LEN_CONFLICT: return "handshake_length_conflict";
    case TRL_RENEGOTIATION: return "renegotiation_rejected";
    case TRL_CCS_AFTER_ESTABLISHED: return "ccs_after_established";
    case TRL_APP_OVERFLOW: return "app_overflow";
    case TRL_TRUNCATED_STREAM: return "truncated_stream";
    }
    return "?";
}

static int trl_fail(TlsRecordLayer* ctx, int code, uint32_t detail) {
    ctx->last_err = code;
    ctx->last_detail = detail;
    return code;
}

void trl_init(TlsRecordLayer* ctx, int allow_ccs_after) {
    memset(ctx, 0, sizeof(*ctx));
    /* RFC 5246 whitelist: the only legal record-layer content types. */
    ctx->type_allow[TRL_TYPE_CHANGE_CIPHER_SPEC] = TRL_ALLOW;
    ctx->type_allow[TRL_TYPE_ALERT] = TRL_ALLOW;
    ctx->type_allow[TRL_TYPE_HANDSHAKE] = TRL_ALLOW;
    ctx->type_allow[TRL_TYPE_APPLICATION_DATA] = TRL_ALLOW;
    ctx->allow_ccs_after = allow_ccs_after ? 1 : 0;
    ctx->rec_need = 5;
}

void trl_allow_type(TlsRecordLayer* ctx, uint8_t type) {
    ctx->type_allow[type] = TRL_ALLOW;
}

void trl_mark_established(TlsRecordLayer* ctx) {
    ctx->established = 1;
}

static int read_u16(const uint8_t* p) {
    return ((int)p[0] << 8) | p[1];
}

static uint32_t read_u24(const uint8_t* p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

/* Per-type length rules. Zero-length records are always inconsistent;
   CCS has an exact fixed size. */
static int type_length_ok(uint8_t type, uint16_t len) {
    if (len == 0) return 0;
    if (type == TRL_TYPE_CHANGE_CIPHER_SPEC && len != 1) return 0;
    if (type == TRL_TYPE_ALERT && len != 2) return 0;
    return 1;
}

/* Reassemble one handshake record's worth of handshake fragments.
   A record may carry several whole fragments; a fragment must never
   span the record that contains its header (RFC 5246 6.2.1). */
static int trl_dispatch_handshake(TlsRecordLayer* ctx, const uint8_t* body, uint16_t len) {
    size_t pos = 0;
    while (pos < len) {
        if (len - pos < 12)
            return trl_fail(ctx, TRL_HS_TRUNCATED, (uint32_t)(len - pos));

        uint8_t  htype = body[pos];
        uint32_t hlen  = read_u24(body + pos + 1);
        uint16_t mseq  = (uint16_t)read_u16(body + pos + 4);
        uint32_t foff  = read_u24(body + pos + 6);
        uint32_t flen  = read_u24(body + pos + 9);
        ctx->n_frags++;

        if (hlen > TRL_MAX_HANDSHAKE_MSG)
            return trl_fail(ctx, TRL_HS_TOO_LARGE, hlen);
        if (pos + 12 + flen > len)
            return trl_fail(ctx, TRL_HS_TRUNCATED, flen);
        if ((uint64_t)foff + flen > (uint64_t)hlen)
            return trl_fail(ctx, TRL_HS_LEN_CONFLICT, foff + flen);

        if (!ctx->hs_active) {
            if (foff != 0) {
                ctx->n_reordered++;
                return trl_fail(ctx, TRL_HS_REORDER, foff);
            }
            ctx->hs_active = 1;
            ctx->hs_type = htype;
            ctx->hs_total = hlen;
            ctx->hs_seq = mseq;
            ctx->hs_got = 0;
        } else {
            if (htype != ctx->hs_type || hlen != ctx->hs_total)
                return trl_fail(ctx, TRL_HS_LEN_CONFLICT, hlen);
        }
        if (mseq != ctx->hs_seq) {
            ctx->n_reordered++;
            return trl_fail(ctx, TRL_HS_REORDER, mseq);
        }

        uint32_t end = foff + flen;
        if (flen > 0 && foff < ctx->hs_got) {
            if (end <= ctx->hs_got) {
                /* fully inside the already-received prefix: an exact
                   retransmit is accepted, any byte difference is overlap. */
                if (memcmp(ctx->hs + foff, body + pos + 12, flen) != 0)
                    return trl_fail(ctx, TRL_HS_OVERLAP, foff);
                ctx->n_duplicates++;
                ctx->dup_bytes += flen;
            } else {
                return trl_fail(ctx, TRL_HS_OVERLAP, foff);
            }
        } else if (flen > 0 && foff > ctx->hs_got) {
            ctx->n_reordered++;
            return trl_fail(ctx, TRL_HS_REORDER, foff);
        } else if (flen > 0) {
            memcpy(ctx->hs + foff, body + pos + 12, flen);
            if (end > ctx->hs_got) ctx->hs_got = end;
        }

        if (ctx->hs_got == ctx->hs_total) {
            ctx->n_hs_messages++;
            ctx->hs_active = 0;
            ctx->hs_got = 0;
        }
        pos += 12 + (size_t)flen;
    }
    /* the loop invariant guarantees pos == len on exit */
    return TRL_OK;
}

static int trl_dispatch_record(TlsRecordLayer* ctx) {
    uint8_t type = ctx->cur_type;
    uint16_t ver = ctx->cur_ver;
    uint16_t len = ctx->cur_len;
    const uint8_t* body = ctx->rec + 5;
    ctx->n_records++;

    if (!ctx->type_allow[type])
        return trl_fail(ctx, TRL_BAD_TYPE, type);
    if (ver != 0x0301 && ver != 0x0303)
        return trl_fail(ctx, TRL_BAD_VERSION, ver);
    if (!type_length_ok(type, len))
        return trl_fail(ctx, TRL_LEN_MISMATCH, len);

    switch (type) {
    case TRL_TYPE_APPLICATION_DATA:
        if (ctx->app_len + len > sizeof(ctx->app))
            return trl_fail(ctx, TRL_APP_OVERFLOW, (uint32_t)(ctx->app_len + len));
        memcpy(ctx->app + ctx->app_len, body, len);
        ctx->app_len += len;
        break;

    case TRL_TYPE_HANDSHAKE:
        if (ctx->established)
            return trl_fail(ctx, TRL_RENEGOTIATION, type);
        {
            int rc = trl_dispatch_handshake(ctx, body, len);
            if (rc != TRL_OK) return rc;
        }
        break;

    case TRL_TYPE_CHANGE_CIPHER_SPEC:
        if (ctx->established && !ctx->allow_ccs_after)
            return trl_fail(ctx, TRL_CCS_AFTER_ESTABLISHED, body[0]);
        break;

    case TRL_TYPE_ALERT:
        ctx->n_alerts++;
        ctx->last_alert_level = body[0];
        ctx->last_alert_desc = body[1];
        break;

    default:
        /* a non-standard type reaches here only when the caller has
           explicitly whitelisted it via trl_allow_type. */
        break;
    }
    return TRL_OK;
}

int trl_feed(TlsRecordLayer* ctx, const uint8_t* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        if (!ctx->have_header) {
            /* phase 1: accumulate the 5-byte record header. */
            size_t room = 5 - ctx->rec_have;
            size_t take = len - off;
            if (take > room) take = room;
            memcpy(ctx->rec + ctx->rec_have, data + off, take);
            ctx->rec_have += take;
            off += take;
            if (ctx->rec_have < 5)
                break;

            ctx->cur_type = ctx->rec[0];
            ctx->cur_ver = (uint16_t)read_u16(ctx->rec + 1);
            ctx->cur_len = (uint16_t)read_u16(ctx->rec + 3);
            if (ctx->cur_len > TRL_MAX_RECORD_PLAINTEXT)
                return trl_fail(ctx, TRL_RECORD_TOO_LARGE, ctx->cur_len);
            ctx->have_header = 1;
            /* fall through: a zero-length record has no body phase. */
        }

        if (ctx->have_header && ctx->cur_len > 0) {
            /* phase 2: accumulate the declared body. rec_have counts
               header + body bytes, so the target is 5 + cur_len. */
            size_t target = (size_t)5 + ctx->cur_len;
            size_t room = target - ctx->rec_have;
            size_t take = len - off;
            if (take > room) take = room;
            if (take > 0) {
                memcpy(ctx->rec + ctx->rec_have, data + off, take);
                ctx->rec_have += take;
                off += take;
            }
            if (ctx->rec_have < target)
                break;
        }

        /* whole record available (or zero-length): validate and dispatch. */
        int rc = trl_dispatch_record(ctx);
        if (rc != TRL_OK) return rc;
        ctx->rec_have = 0;
        ctx->have_header = 0;
    }
    ctx->stream_pos += len;
    return TRL_OK;
}

int trl_finish(TlsRecordLayer* ctx) {
    if (ctx->rec_have != 0)
        return trl_fail(ctx, TRL_TRUNCATED_STREAM, (uint32_t)ctx->rec_have);
    return TRL_OK;
}
