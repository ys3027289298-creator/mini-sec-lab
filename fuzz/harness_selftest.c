/*
 * harness_selftest.c — deliberately vulnerable target used to validate
 * the engine itself (crash / timeout / leak classification, recording
 * and minimization). It is NOT part of the three lab components.
 *
 *   input starting with "CRASH" -> stack buffer overflow (ASan abort)
 *   input starting with "HANG"  -> infinite loop (watchdog)
 *   input starting with "LEAK"  -> unreachable malloc (LSan report)
 *   anything else               -> clean
 */
#include "engine.h"

#include <stdlib.h>
#include <string.h>

void fuzz_one(const uint8_t *data, size_t size) {
    if (size >= 5 && memcmp(data, "CRASH", 5) == 0) {
        /* out-of-bounds stack write: ASan must abort the worker */
        char overflow[8];
        for (size_t i = 0; i < size && i < 64; i++)
            overflow[i] = (char)data[i];
        /* keep the writes observable so the compiler cannot elide them */
        if (overflow[0] == 0) abort();
    }
    if (size >= 4 && memcmp(data, "HANG", 4) == 0) {
        volatile unsigned long x = 0;
        for (;;) x++;
        (void)x;
    }
    if (size >= 4 && memcmp(data, "LEAK", 4) == 0) {
        void *p = malloc(64);
        memset(p, 0x41, 64);
        /* p intentionally lost: LSan must flag it at worker exit */
    }
}

static const char *seed_lines[] = {
    "CRASH-ME-PLEASE",
    "HANG-ON-WHILE",
    "LEAK-MEMORY-HERE",
    "benign input",
};

int fuzz_seed(void) {
    for (size_t i = 0; i < sizeof(seed_lines) / sizeof(seed_lines[0]); i++)
        engine_emit_seed((const uint8_t *)seed_lines[i],
                         strlen(seed_lines[i]));
    return 0;
}
