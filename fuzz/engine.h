/*
 * engine.h — interface between a fuzzing harness and the built-in
 * mutation fuzzing engine (engine.c). The engine needs only libc and
 * POSIX; no external fuzzer or extra library is required.
 */
#ifndef FUZZ_ENGINE_H
#define FUZZ_ENGINE_H

#include <stddef.h>
#include <stdint.h>

/* Called once per worker process before any fuzz_one() call.
 * Optional: engine.c ships a weak no-op definition. */
void fuzz_init(void);

/* Called by the "seed" subcommand to emit canonical seed inputs.
 * Emit each seed with engine_emit_seed(). Optional.
 * Return 0 on success. */
int fuzz_seed(void);

/* The target under test: exercise it on exactly the given bytes. */
void fuzz_one(const uint8_t *data, size_t size);

/* Frame a seed input (4-byte big-endian length + payload) on stdout,
 * for use inside fuzz_seed(). */
void engine_emit_seed(const uint8_t *data, size_t size);

/* Engine CLI entry point. target names the component and is used in
 * logs and output paths. Returns a process exit code: 0 = clean. */
int engine_run(const char *target, int argc, char **argv);

#endif /* FUZZ_ENGINE_H */
