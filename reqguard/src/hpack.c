/* HPACK decoder. See hpack.h for the contract and RFC references. */
#include "hpack.h"
#include "hpack_tables.h"

#include <string.h>

/* RFC 7541 section 4.2: one update may follow a reduction to signal the
   smallest size seen in the interval, plus the final size. */
#define HPACK_MAX_UPDATES 2

static void dec_reset(HpackDecoder *d) {
    d->max_size = HPACK_DEFAULT_TABLE_SIZE;
    d->size = 0;
    d->head = 0;
    d->count = 0;
    d->arena_used = 0;
}

void hpack_decoder_init(HpackDecoder *d) {
    memset(d, 0, sizeof(*d));
    d->allowed_max = HPACK_DEFAULT_TABLE_SIZE;
    d->shrink_target = UINT32_MAX;
    d->header_list_max = HPACK_MAX_HEADER_LIST;
    dec_reset(d);
}

int hpack_decoder_set_allowed_table_size(HpackDecoder *d, uint32_t size) {
    if (size > HPACK_MAX_TABLE_SIZE) return HPACK_ERR_TABLE_SIZE_LIMIT;
    if (size < d->allowed_max) {
        d->needs_shrink_update = 1;
        if (size < d->shrink_target) d->shrink_target = size;
    }
    d->allowed_max = size;
    return HPACK_OK;
}

uint32_t hpack_dynamic_size(const HpackDecoder *d) { return d->size; }
uint32_t hpack_dynamic_count(const HpackDecoder *d) { return d->count; }

/* Dynamic table entry `i`, 0 = most recently inserted. The ring keeps
   the newest slot at `head` and walks backwards from it. */
int hpack_dynamic_get(const HpackDecoder *d, uint32_t i,
                      const char **name, size_t *name_len,
                      const char **value, size_t *value_len) {
    if (i >= d->count) return -1;
    uint32_t idx = (d->head + HPACK_MAX_ENTRIES - i) % HPACK_MAX_ENTRIES;
    const HpackSlot *s = &d->slot[idx];
    *name = (const char *)d->arena + s->name_off;
    *name_len = s->name_len;
    *value = (const char *)d->arena + s->value_off;
    *value_len = s->value_len;
    return 0;
}


/* RFC 7541 section 5.1. `prefix` is 1..8, and the bits above it in
   data[0] are representation flags the caller already handled. */
static int dec_int(const uint8_t *data, size_t len, size_t *pos, int prefix,
                   uint32_t *out) {
    if (*pos >= len) return HPACK_ERR_TRUNCATED;
    uint32_t mask = (1u << prefix) - 1u;
    uint32_t value = data[(*pos)++] & mask;
    if (value < mask) {
        *out = value;
        return HPACK_OK;
    }
    unsigned shift = 0;
    for (;;) {
        if (*pos >= len) return HPACK_ERR_TRUNCATED;
        uint8_t b = data[(*pos)++];
        /* 32-bit values may use at most five continuation octets, and
           the last one must fit without wrapping (section 5.1 allows
           implementations to reject anything longer). */
        if (shift > 28) return HPACK_ERR_INTEGER_OVERFLOW;
        if (shift == 28 && (b & 0x7fu) > 0x0fu) return HPACK_ERR_INTEGER_OVERFLOW;
        value += (uint32_t)(b & 0x7fu) << shift;
        if ((b & 0x80u) == 0) {
            *out = value;
            return HPACK_OK;
        }
        shift += 7;
    }
}

/* RFC 7541 section 5.2 and Appendix B. Decodes into `out`, which must
   hold `cap` bytes. Returns the decoded length, or the negated HpackErr
   so a length can never be mistaken for an error code.

   Walking the code trie bit by bit means a partial code at the end of
   the input is a path that never reached a leaf. That is only valid as
   padding when it is shorter than 8 bits AND every bit is a 1, i.e. a
   proper prefix of EOS (section 5.2). An EOS symbol inside the payload
   is always an error. */
static int dec_huffman(const uint8_t *in, size_t len, uint8_t *out, size_t cap) {
    int node = 0;
    unsigned pad_bits = 0;
    int pad_all_ones = 1;
    size_t written = 0;

    for (size_t i = 0; i < len; i++) {
        for (int shift = 7; shift >= 0; shift--) {
            int bit = (in[i] >> shift) & 1;
            node = (bit ? huff_child1 : huff_child0)[node];
            /* Every code is a prefix of some longer one, so a missing
               child can never be valid padding; it is a bad code. */
            if (node < 0) return -HPACK_ERR_HUFFMAN;
            pad_bits++;
            if (bit == 0) pad_all_ones = 0;
            int sym = huff_sym[node];
            if (sym < 0) continue;
            if (sym == 256) return -HPACK_ERR_HUFFMAN; /* EOS in payload */
            if (written >= cap) return -HPACK_ERR_FIELD_TOO_LARGE;
            out[written++] = (uint8_t)sym;
            node = 0;
            pad_bits = 0;
            pad_all_ones = 1;
        }
    }
    if (pad_bits > 7) return -HPACK_ERR_HUFFMAN;
    if (pad_bits > 0 && !pad_all_ones) return -HPACK_ERR_HUFFMAN;
    return (int)written;
}

static int table_entry_get(const HpackDecoder *d, uint32_t index,
                           const char **name, size_t *name_len,
                           const char **value, size_t *value_len) {
    if (index == 0) return HPACK_ERR_INDEX_ZERO;
    if (index <= HPACK_STATIC_COUNT) {
        const HpackStaticEntry *e = &hpack_static[index];
        *name = e->name;
        *name_len = e->name_len;
        *value = e->value;
        *value_len = e->value_len;
        return HPACK_OK;
    }
    return hpack_dynamic_get(d, index - HPACK_STATIC_COUNT - 1,
                             name, name_len, value, value_len) == 0
               ? HPACK_OK
               : HPACK_ERR_INDEX_RANGE;
}

/* Drop the oldest entry, which sits immediately before `head`. */
static void table_drop_oldest(HpackDecoder *d) {
    uint32_t idx = (d->head + HPACK_MAX_ENTRIES - d->count + 1) % HPACK_MAX_ENTRIES;
    HpackSlot *s = &d->slot[idx];
    d->size -= 32 + s->name_len + s->value_len;
    d->count--;
    if (d->count == 0) {
        d->head = 0;
        d->arena_used = 0;
    }
}

/* RFC 7541 section 4.3/4.4: evict from the oldest end until the table
   is at or below `limit` bytes. */
static void table_evict_to(HpackDecoder *d, uint32_t limit) {
    while (d->size > limit && d->count > 0) table_drop_oldest(d);
}

static void table_resize(HpackDecoder *d, uint32_t new_max) {
    d->max_size = new_max;
    table_evict_to(d, new_max);
}

/* Compact the arena so live entry bytes start at offset 0. Called when
   appending would run past the arena end; with evictions ahead of it,
   the space reclaimed is at least the entry being inserted. */
static void arena_compact(HpackDecoder *d) {
    uint32_t out = 0;
    for (uint32_t i = 0; i < d->count; i++) {
        HpackSlot *s = &d->slot[(d->head + HPACK_MAX_ENTRIES - i) % HPACK_MAX_ENTRIES];
        if (s->name_off != out) {
            memmove(d->arena + out, d->arena + s->name_off, s->name_len);
            s->name_off = out;
        }
        out += s->name_len;
        if (s->value_off != out) {
            memmove(d->arena + out, d->arena + s->value_off, s->value_len);
            s->value_off = out;
        }
        out += s->value_len;
    }
    d->arena_used = out;
}

/* Insert a new entry at the front of the dynamic table (RFC 7541
   sections 3.2, 4.1 and 4.4). An entry that alone exceeds the table
   size empties the table and is not inserted. */
static void table_add(HpackDecoder *d, const uint8_t *name, size_t name_len,
                      const uint8_t *value, size_t value_len) {
    uint32_t entry = (uint32_t)(32 + name_len + value_len);

    table_evict_to(d, entry > d->max_size ? 0 : d->max_size - entry);

    /* An entry that cannot fit is simply not added; eviction above has
       already emptied the table as section 4.4 requires. */
    if (entry > d->max_size) return;

    /* The entry's bytes alone are smaller than the table it fits in,
       which is capped at HPACK_MAX_TABLE_SIZE, so after compaction the
       append always has room. */
    if (d->arena_used + name_len + value_len > HPACK_MAX_TABLE_SIZE)
        arena_compact(d);

    uint32_t new_head = (d->head + 1) % HPACK_MAX_ENTRIES;
    HpackSlot *s = &d->slot[new_head];
    s->name_off = d->arena_used;
    s->name_len = (uint32_t)name_len;
    memcpy(d->arena + d->arena_used, name, name_len);
    d->arena_used += (uint32_t)name_len;
    s->value_off = d->arena_used;
    s->value_len = (uint32_t)value_len;
    memcpy(d->arena + d->arena_used, value, value_len);
    d->arena_used += (uint32_t)value_len;

    d->head = new_head;
    d->count++;
    d->size += entry;
}

/* A string literal (RFC 7541 section 5.2): 7-bit length, H flag on the
   length octet, optional Huffman payload. */
static int dec_string(const uint8_t *data, size_t len, size_t *pos,
                      uint8_t *out, size_t cap, size_t *out_len) {
    if (*pos >= len) return HPACK_ERR_TRUNCATED;
    int huffman = (data[*pos] & 0x80) != 0;
    uint32_t slen;
    int rc = dec_int(data, len, pos, 7, &slen);
    if (rc != HPACK_OK) return rc;
    if (slen > len - *pos) return HPACK_ERR_TRUNCATED;
    if (!huffman) {
        if (slen > cap) return HPACK_ERR_FIELD_TOO_LARGE;
        memcpy(out, data + *pos, slen);
        *out_len = slen;
    } else {
        int n = dec_huffman(data + *pos, slen, out, cap);
        if (n < 0) return -n;
        *out_len = (size_t)n;
    }
    *pos += slen;
    return HPACK_OK;
}

typedef struct {
    const uint8_t *name;
    size_t name_len;
    const uint8_t *value;
    size_t value_len;
} FieldView;

/* Decode the field name part of a literal representation. `pos` still
   points at the representation's first octet: its low `prefix` bits are
   the name index (0 means a string literal follows), and dec_int masks
   off the representation flags above them. */
static int dec_field_name(HpackDecoder *d, const uint8_t *data, size_t len,
                          size_t *pos, int prefix, FieldView *f) {
    uint32_t index;
    int rc = dec_int(data, len, pos, prefix, &index);
    if (rc != HPACK_OK) return rc;
    if (index == 0) {
        rc = dec_string(data, len, pos, d->name, sizeof(d->name), &f->name_len);
        if (rc != HPACK_OK) return rc;
        f->name = d->name;
        return HPACK_OK;
    }
    const char *name, *ignored_value;
    size_t name_len, ignored_len;
    rc = table_entry_get(d, index, &name, &name_len, &ignored_value, &ignored_len);
    if (rc != HPACK_OK) return rc;
    f->name = (const uint8_t *)name;
    f->name_len = name_len;
    return HPACK_OK;
}

static int emit(HpackDecoder *d, const FieldView *f,
                HpackFieldFn fn, void *user, uint32_t *inflated) {
    uint64_t add = 32ull + f->name_len + f->value_len;
    if (*inflated + add > d->header_list_max)
        return HPACK_ERR_HEADER_LIST_TOO_LARGE;
    *inflated += (uint32_t)add;
    if (fn && fn(user, (const char *)f->name, f->name_len,
                 (const char *)f->value, f->value_len))
        return HPACK_ERR_CALLBACK;
    return HPACK_OK;
}

/* A hostname / scanned name is stored inline when the name index is 0,
   and the value is always a string literal. This helper handles the
   "literal field" spine shared by the three literal representations:
   the only difference is the name index width (4 vs 6 bits) and whether
   the field is added to the dynamic table. */
static int dec_literal(HpackDecoder *d, const uint8_t *data, size_t len,
                       size_t *pos, int name_prefix, FieldView *f) {
    int rc = dec_field_name(d, data, len, pos, name_prefix, f);
    if (rc != HPACK_OK) return rc;
    rc = dec_string(data, len, pos, d->value, sizeof(d->value), &f->value_len);
    if (rc != HPACK_OK) return rc;
    f->value = d->value;
    return HPACK_OK;
}

int hpack_decode(HpackDecoder *d, const uint8_t *block, size_t len,
                 HpackFieldFn fn, void *user) {
    size_t pos = 0;
    uint32_t inflated = 0;
    int size_updates = 0;
    int fields_seen = 0;
    uint32_t smallest_update = UINT32_MAX;

    if (d->allowed_max > HPACK_MAX_TABLE_SIZE) return HPACK_ERR_TABLE_SIZE_LIMIT;

    while (pos < len) {
        uint8_t b = block[pos];
        int rc;

        if (b & 0x80) {                         /* 6.1 indexed field */
            uint32_t index;
            rc = dec_int(block, len, &pos, 7, &index);
            if (rc != HPACK_OK) return rc;
            const char *name, *value;
            size_t name_len, value_len;
            rc = table_entry_get(d, index, &name, &name_len, &value, &value_len);
            if (rc != HPACK_OK) return rc;
            FieldView f = { (const uint8_t *)name, name_len,
                            (const uint8_t *)value, value_len };
            rc = emit(d, &f, fn, user, &inflated);
            if (rc != HPACK_OK) return rc;
            fields_seen = 1;
        } else if (b & 0x40) {                  /* 6.2.1 literal, indexed */
            FieldView f = { 0, 0, 0, 0 };
            rc = dec_literal(d, block, len, &pos, 6, &f);
            if (rc != HPACK_OK) return rc;
            table_add(d, f.name, f.name_len, f.value, f.value_len);
            rc = emit(d, &f, fn, user, &inflated);
            if (rc != HPACK_OK) return rc;
            fields_seen = 1;
        } else if (b & 0x20) {                  /* 6.3 dynamic table size update */
            /* RFC 7541 4.2: updates come first in the block, at most a
               reduction-to-smallest plus the final value. */
            if (fields_seen || size_updates >= HPACK_MAX_UPDATES)
                return HPACK_ERR_SIZE_UPDATE_POSITION;
            size_updates++;
            uint32_t new_max;
            rc = dec_int(block, len, &pos, 5, &new_max);
            if (rc != HPACK_OK) return rc;
            if (new_max > d->allowed_max) return HPACK_ERR_TABLE_SIZE_UPDATE;
            if (new_max < smallest_update) smallest_update = new_max;
            table_resize(d, new_max);
        } else {                                /* 6.2.2 / 6.2.3 literal */
            FieldView f = { 0, 0, 0, 0 };
            rc = dec_literal(d, block, len, &pos, 4, &f);
            if (rc != HPACK_OK) return rc;
            rc = emit(d, &f, fn, user, &inflated);
            if (rc != HPACK_OK) return rc;
            fields_seen = 1;
        }
    }

    /* RFC 9113 4.3.1: after SETTINGS_HEADER_TABLE_SIZE is lowered, the
       next field block must bring the table down to the new maximum. RFC
       7541 4.2 then requires the smallest size seen in the interval to be
       signalled, so an update sequence that never reaches the advertised
       maximum is also a miss even if the final size is back above it. */
    if (d->max_size > d->allowed_max) return HPACK_ERR_SIZE_UPDATE_MISSING;
    if (d->needs_shrink_update && smallest_update > d->shrink_target)
        return HPACK_ERR_SIZE_UPDATE_MISSING;
    d->needs_shrink_update = 0;
    d->shrink_target = UINT32_MAX;
    return HPACK_OK;
}
