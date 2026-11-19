
/* tlsrecord: TLS record layer for decrypted plaintext records.
   Stream reassembly across fragmented feeds, content-type whitelist,
   record/fragment length consistency, handshake fragment reassembly
   with reorder/overlap detection, renegotiation rejection, and an
   entry point that hands application plaintext to reqguard.

   The library core performs no dynamic allocation: a caller-owned
   TlsRecordLayer context has a fixed, documented size. */
#ifndef TLSRECORD_H
#define TLSRECORD_H

#include <stddef.h>
#include <stdint.h>

/* RFC 5246 6.2.1: maximum plaintext fragment length. */
#define TRL_MAX_RECORD_PLAINTEXT 16384
/* Largest reassembled handshake message this layer accepts. */
#define TRL_MAX_HANDSHAKE_MSG    65536
/* Decrypted application_data buffered for the HTTP entry point. */
#define TRL_MAX_APP_PLAINTEXT    16384
/* Guaranteed upper bound on sizeof(TlsRecordLayer), checked at compile time. */
#define TRL_MEM_BOUND_BYTES      100000

/* TLS content types (RFC 5246 6.2.1). */
#define TRL_TYPE_CHANGE_CIPHER_SPEC 20
#define TRL_TYPE_ALERT              21
#define TRL_TYPE_HANDSHAKE          22
#define TRL_TYPE_APPLICATION_DATA   23

typedef enum {
    TRL_OK = 0,
    TRL_RECORD_TOO_LARGE,       /* record length field > 16384 */
    TRL_BAD_VERSION,            /* version not 0x0301 / 0x0303 */
    TRL_BAD_TYPE,               /* content type not on whitelist */
    TRL_LEN_MISMATCH,           /* per-type record length violation */
    TRL_HS_TRUNCATED,           /* handshake fragment runs past its record */
    TRL_HS_TOO_LARGE,           /* reassembled message > TRL_MAX_HANDSHAKE_MSG */
    TRL_HS_OVERLAP,             /* overlapping, non-identical fragment */
    TRL_HS_REORDER,             /* gap / out-of-order fragment */
    TRL_HS_LEN_CONFLICT,        /* type/length change or fragment beyond total */
    TRL_RENEGOTIATION,          /* handshake after the session is established */
    TRL_CCS_AFTER_ESTABLISHED,  /* ChangeCipherSpec after establishment */
    TRL_APP_OVERFLOW,           /* app plaintext buffer exhausted */
    TRL_TRUNCATED_STREAM        /* feed ended in the middle of a record */
} TrlErr;

typedef struct {
    /* whitelist of acceptable content types */
    uint8_t  type_allow[256];
    int      allow_ccs_after;
    int      established;

    /* current record being assembled from the byte stream */
    uint8_t  rec[TRL_MAX_RECORD_PLAINTEXT + 5];
    size_t   rec_have;
    size_t   rec_need;
    int      have_header;
    uint8_t  cur_type;
    uint16_t cur_ver;
    uint16_t cur_len;
    uint64_t stream_pos;        /* total bytes consumed */

    /* DTLS-style handshake fragment reassembly state */
    uint8_t  hs[TRL_MAX_HANDSHAKE_MSG];
    int      hs_active;
    uint8_t  hs_type;
    uint32_t hs_total;
    uint32_t hs_got;           /* contiguous prefix length */
    uint16_t hs_seq;

    /* decrypted application_data waiting for the HTTP entry point */
    uint8_t  app[TRL_MAX_APP_PLAINTEXT];
    size_t   app_len;

    /* counters */
    uint64_t n_records;
    uint64_t n_hs_messages;
    uint64_t n_frags;
    uint64_t n_reordered;
    uint64_t n_duplicates;
    uint64_t dup_bytes;
    uint64_t n_alerts;
    uint8_t  last_alert_level;
    uint8_t  last_alert_desc;

    int      last_err;
    uint32_t last_detail;
} TlsRecordLayer;

void trl_init(TlsRecordLayer* ctx, int allow_ccs_after);
void trl_allow_type(TlsRecordLayer* ctx, uint8_t type);
void trl_mark_established(TlsRecordLayer* ctx);

/* Feed arbitrary-sized chunks of the decrypted record stream.
   Returns TRL_OK while whole records keep dispatching; the first error
   poisons the context (no further feeding is defined afterwards). */
int trl_feed(TlsRecordLayer* ctx, const uint8_t* data, size_t len);

/* Call once at end of stream: catches a half-record left pending. */
int trl_finish(TlsRecordLayer* ctx);

/* Run the buffered application plaintext through reqguard.
   Returns reqguard's error name ("ok", "cl_te_conflict", ...) or NULL
   when no application data has been buffered. */
const char* trl_http_ingest(const TlsRecordLayer* ctx);

const char* trl_err_name(int code);

#endif
