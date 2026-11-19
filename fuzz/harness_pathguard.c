/*
 * harness_pathguard.c — fuzzing entry point for the pathguard policy
 * checker. Inputs are treated as NUL-terminated untrusted relative
 * paths, mirroring how check_rel() is actually called.
 */
#include "engine.h"

#include <stdlib.h>
#include <string.h>

#define main pathguard_demo_main
#include "../pathguard/src/pathguard.c"
#undef main

void fuzz_one(const uint8_t *data, size_t size) {
    /* The component's decoded buffer is 512 bytes; stay within the
     * realistic input range it was designed for. */
    if (size > 511) size = 511;

    char path[512];
    memcpy(path, data, size);
    path[size] = 0;

    PgErr e = check_rel(path);
    if (pg_name(e) == NULL)
        abort();
}

static const char *seed_lines[] = {
    "a/b/c.txt",
    "file.txt",
    "dir/subdir/data.bin",
    "../escape",
    "%2e%2e%2fetc",
    "a\\b\\c",
    "a/./b/../c",
    "/etc/passwd",
    "a%2fb",
    "a%zz",
};

int fuzz_seed(void) {
    for (size_t i = 0; i < sizeof(seed_lines) / sizeof(seed_lines[0]); i++)
        engine_emit_seed((const uint8_t *)seed_lines[i],
                         strlen(seed_lines[i]));
    return 0;
}
