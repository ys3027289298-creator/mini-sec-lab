/* pg_policy: lexical policy for untrusted relative names.
   The validator returns the exact byte string that the opener must use,
   so validation and open never disagree about which path is meant. */
#ifndef PG_POLICY_H
#define PG_POLICY_H

#include <stddef.h>

#define PG_MAX_COMP 64
#define PG_MAX_DEPTH 8
#define PG_MAX_PATH 512
#define PG_NAME_MAX 256

typedef enum {
    PG_OK = 0,
    PG_EMPTY,
    PG_ABSOLUTE,
    PG_TRAVERSAL,
    PG_CONTROL,
    PG_TOO_LONG,
    PG_TOO_DEEP,
    PG_ENCODED,
    PG_DOTFILE,
    PG_BACKSLASH,
    PG_OVERFLOW
} PgErr;

const char* pg_err_name(PgErr e);

/* Validate raw (possibly percent-encoded) request name.
   On PG_OK, decoded holds the NUL-terminated path to open and *decoded_len
   is its length.  On failure decoded must not be used. */
PgErr pg_check_name(const char* raw, char* decoded, size_t cap,
                    size_t* decoded_len);

#endif
