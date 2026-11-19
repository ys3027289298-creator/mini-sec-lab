/* hpack: RFC 7541 header compression decoder for HTTP/2.

   The decoder is a caller-owned context with a fixed memory footprint:
   a static table, a dynamic table with RFC 7541 eviction, an arena for
   entry bytes and scratch buffers for the field being decoded. No
   allocation happens while decoding.

   The peer-visible limit is the SETTINGS_HEADER_TABLE_SIZE this side
   advertised (allowed_max). A dynamic table size update above that
   limit is a decoding error (RFC 7541 section 6.3), and after the limit
   is lowered the next field block must begin with updates that reach the
   smallest advertised maximum (RFC 7541 section 4.2; RFC 9113 section
   4.3.1). */
#ifndef REQGUARD_HPACK_H
#define REQGUARD_HPACK_H

#include <stddef.h>
#include <stdint.h>

#define HPACK_STATIC_COUNT      61
#define HPACK_DEFAULT_TABLE_SIZE 4096u
#define HPACK_MAX_TABLE_SIZE    65536u
/* 65536 / 32: the most entries a maximum-size table can hold. */
#define HPACK_MAX_ENTRIES       2048
/* Implementation limit on one decoded name or value. */
#define HPACK_MAX_FIELD_LEN     65536u
/* Default cap on the inflated field section: sum of 32 + name + value. */
#define HPACK_MAX_HEADER_LIST   65536u

typedef enum {
    HPACK_OK = 0,
    HPACK_ERR_TRUNCATED,           /* block ends mid-representation */
    HPACK_ERR_INTEGER_OVERFLOW,    /* integer too large or too long */
    HPACK_ERR_INDEX_ZERO,          /* indexed field with index 0 */
    HPACK_ERR_INDEX_RANGE,         /* index past static + dynamic table */
    HPACK_ERR_HUFFMAN,             /* EOS, bad padding or over-long code */
    HPACK_ERR_FIELD_TOO_LARGE,     /* decoded name/value beyond our limit */
    HPACK_ERR_HEADER_LIST_TOO_LARGE,
    HPACK_ERR_TABLE_SIZE_UPDATE,   /* update above the advertised maximum */
    HPACK_ERR_SIZE_UPDATE_POSITION,/* update after a header field */
    HPACK_ERR_SIZE_UPDATE_MISSING, /* lowered limit not acknowledged */
    HPACK_ERR_TABLE_SIZE_LIMIT,    /* local limit beyond our implementation */
    HPACK_ERR_CALLBACK             /* caller's field callback rejected it */
} HpackErr;

typedef struct {
    uint32_t name_off;
    uint32_t value_off;
    uint32_t name_len;
    uint32_t value_len;
} HpackSlot;

typedef struct {
    uint32_t allowed_max;   /* SETTINGS_HEADER_TABLE_SIZE we advertised */
    uint32_t max_size;      /* size chosen by the most recent update */
    uint32_t size;          /* sum of live entry sizes (32 + name + value) */
    uint32_t head;          /* slot index of the newest entry */
    uint32_t count;         /* live slots */
    uint32_t arena_used;
    uint32_t header_list_max;
    int needs_shrink_update; /* advertised max was lowered, ack pending */
    uint32_t shrink_target;  /* smallest advertised max since last block */
    HpackSlot slot[HPACK_MAX_ENTRIES];
    uint8_t arena[HPACK_MAX_TABLE_SIZE];
    uint8_t name[HPACK_MAX_FIELD_LEN];
    uint8_t value[HPACK_MAX_FIELD_LEN];
} HpackDecoder;

/* Receives one decoded field. Pointers are valid only for the duration
   of the call. Return non-zero to abort decoding with HPACK_ERR_CALLBACK. */
typedef int (*HpackFieldFn)(void *user, const char *name, size_t name_len,
                            const char *value, size_t value_len);

/* Fresh connection state: dynamic table starts at 4096 bytes, which is
   also the initial value of SETTINGS_HEADER_TABLE_SIZE. */
void hpack_decoder_init(HpackDecoder *d);

/* Announce a new SETTINGS_HEADER_TABLE_SIZE value. Values above
   HPACK_MAX_TABLE_SIZE are refused with HPACK_ERR_TABLE_SIZE_LIMIT.
   The new maximum is enforced from the next decoded block on; after a
   reduction, the peer must open its following field block with updates
   that reach the smallest advertised maximum (RFC 7541 4.2, RFC 9113
   4.3.1), or decoding reports HPACK_ERR_SIZE_UPDATE_MISSING. */
int hpack_decoder_set_allowed_table_size(HpackDecoder *d, uint32_t size);

/* Decode one complete header block. Returns HPACK_OK when every field
   was decoded and the table state is within the advertised limit.
   Table changes made before an error remain in effect, as HPACK state
   belongs to the connection. */
int hpack_decode(HpackDecoder *d, const uint8_t *block, size_t len,
                 HpackFieldFn fn, void *user);

uint32_t hpack_dynamic_size(const HpackDecoder *d);
uint32_t hpack_dynamic_count(const HpackDecoder *d);

/* Dynamic table entry `i`, 0 = most recently inserted. Returns 0 on
   success, -1 when `i` is out of range. Pointers alias the arena. */
int hpack_dynamic_get(const HpackDecoder *d, uint32_t i,
                      const char **name, size_t *name_len,
                      const char **value, size_t *value_len);

/* Huffman code and length per symbol (256 = EOS), for encoders. */
extern const uint32_t hpack_huff_code[257];
extern const uint8_t hpack_huff_len[257];

#endif /* REQGUARD_HPACK_H */
