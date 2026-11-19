/*
 * engine.c — dependency-free mutation fuzzing engine.
 *
 * What it does:
 *   - loads a seed corpus, mutates seed-derived byte buffers with a
 *     deterministic xorshift64 PRNG (flip / insert / delete / replace /
 *     duplicate / block-move / arithmetic / length-set);
 *   - runs every input inside a forked worker so a crash in the target
 *     cannot take the campaign down;
 *   - classifies every abnormal outcome: sanitizer/process crash,
 *     timeout (watchdog), or memory leak (LeakSanitizer at worker exit);
 *   - records every failing input plus a JSON manifest, and minimizes
 *     each failure with a ddmin-style chunk removal pass followed by a
 *     per-byte substitution pass;
 *   - determinism: a given --rng-seed reproduces the exact same run,
 *     and every saved input re-triggers the same failure via "oneshot".
 *
 * Requirements: libc + POSIX only. Built with -fsanitize=address,undefined
 * by the Makefile; the engine itself adds no dependency.
 */
#define _POSIX_C_SOURCE 200809L

#include "engine.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_INPUT        4096    /* largest buffer ever handed to a target */
#define DEFAULT_ITERS    100000
#define DEFAULT_BATCH    200     /* inputs per forked worker */
#define INPUT_TIMEOUT_MS 1000    /* per-input watchdog budget */
#define MAX_FINDINGS     16      /* stop recording after this many */
#define MIN_TRIALS       20000   /* minimization trial budget */

typedef enum {
    V_OK = 0,      /* clean exit, no sanitizer report */
    V_CRASH,       /* killed by signal (incl. sanitizer abort) */
    V_TIMEOUT,     /* watchdog killed the worker */
    V_LEAK,        /* LeakSanitizer reported leaks at exit */
    V_ERROR        /* harness/engine failure, not a target finding */
} VerdictKind;

typedef struct {
    VerdictKind kind;
    int code;              /* signal number or exit status */
} Verdict;

/* ---------------------------------------------------------------- PRNG */

static uint64_t rng_state;

static void rng_seed(uint64_t s) {
    rng_state = s ? s : 0x9e3779b97f4a7c15ULL;
}

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static size_t rng_below(size_t n) {
    return n ? (size_t)(rng_next() % n) : 0;
}

/* ------------------------------------------------------------- helpers */

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "fuzz: ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0)
        return S_ISDIR(st.st_mode) ? 0 : -1;

    /* create missing parents first */
    char tmp[1024];
    size_t n = strlen(path);
    if (n >= sizeof(tmp)) return -1;
    memcpy(tmp, path, n + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(path, 0755) == 0)
        return 0;
    return errno == EEXIST ? 0 : -1;
}

static int read_file(const char *path, uint8_t *buf, size_t cap, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t n = 0;
    while (n < cap) {
        ssize_t r = read(fd, buf + n, cap - n);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) break;
        n += (size_t)r;
    }
    close(fd);
    *out_len = n;
    return 0;
}

static int write_file(const char *path, const uint8_t *data, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        off += (size_t)w;
    }
    close(fd);
    return 0;
}

static const char *verdict_name(VerdictKind k) {
    switch (k) {
    case V_OK:      return "ok";
    case V_CRASH:   return "crash";
    case V_TIMEOUT: return "timeout";
    case V_LEAK:    return "leak";
    case V_ERROR:   return "error";
    }
    return "?";
}

/* --------------------------------------------------------- sanitizers */

/* ASan reads ASAN_OPTIONS once, at process startup, so the log path is
 * supplied by the invoking shell (run_fuzz.sh) before the engine starts
 * and inherited by every forked worker. The engine parses it back to
 * know which directory to scan for leak reports. */
static char g_log_dir[256];

static void sanitizer_env(void) {
    const char *ap = getenv("ASAN_OPTIONS");
    if (ap && (ap = strstr(ap, "log_path=")) != NULL) {
        ap += 9;
        const char *end = strchr(ap, ':');
        size_t n = end ? (size_t)(end - ap) : strlen(ap);
        if (n >= sizeof(g_log_dir)) n = sizeof(g_log_dir) - 1;
        memcpy(g_log_dir, ap, n);
        g_log_dir[n] = 0;
        char *slash = strrchr(g_log_dir, '/');
        if (slash) *slash = 0;   /* keep directory, drop file prefix */
    }
    setenv("UBSAN_OPTIONS",
           "abort_on_error=1:halt_on_error=1:print_stacktrace=1", 0);
}

/* Scan the sanitizer log directory for a leak report. ASan names logs
 * <log_path>.<pid>; the directory is small and per-campaign. */
static int log_says_leak(pid_t pid) {
    if (!g_log_dir[0]) return 0;
    char pattern[512];
    snprintf(pattern, sizeof(pattern),
             "grep -l -E 'LeakSanitizer|detected memory leaks' '%s'/asan.%d 2>/dev/null",
             g_log_dir, (int)pid);
    FILE *p = popen(pattern, "r");
    if (!p) return 0;
    int found = (fgetc(p) != EOF);
    pclose(p);
    return found;
}

/* ----------------------------------------------------------- mutation */

static uint8_t interesting_byte(void) {
    static const uint8_t vals[] = {
        0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff, '\r', '\n', ' ', ':', '.', '/', '%'
    };
    return vals[rng_below(sizeof(vals))];
}

/* Mutate buf in place; *len tracks the current size. Inputs start from
 * corpus seeds, so empty buffers only appear if every byte was deleted. */
static void mutate(uint8_t *buf, size_t *len) {
    size_t n = *len;
    int op = (int)rng_below(8);
    switch (op) {
    case 0: /* bit/byte flip */
        if (n > 0) {
            size_t p = rng_below(n);
            if (rng_next() & 1)
                buf[p] ^= (uint8_t)(1u << rng_below(8));
            else
                buf[p] = interesting_byte();
        }
        break;
    case 1: { /* insert */
        if (n < MAX_INPUT) {
            size_t p = rng_below(n + 1);
            memmove(buf + p + 1, buf + p, n - p);
            buf[p] = interesting_byte();
            (*len)++;
        }
        break;
    }
    case 2: /* delete */
        if (n > 0) {
            size_t p = rng_below(n);
            memmove(buf + p, buf + p + 1, n - p - 1);
            (*len)--;
        }
        break;
    case 3: /* replace byte (keeps length; distinct from flip) */
        if (n > 0)
            buf[rng_below(n)] = (uint8_t)(rng_next() >> 24);
        break;
    case 4: { /* duplicate a block */
        if (n > 0 && n < MAX_INPUT) {
            size_t p = rng_below(n);
            size_t max_b = n - p;
            size_t b = 1 + rng_below(max_b < 16 ? max_b : 16);
            if (b > MAX_INPUT - n) b = MAX_INPUT - n;
            memmove(buf + p + b, buf + p, n - p);
            *len += b;
        }
        break;
    }
    case 5: { /* move a block */
        if (n > 1) {
            size_t p = rng_below(n);
            size_t b = 1 + rng_below((n - p < 32 ? n - p : 32));
            uint8_t tmp[64];
            if (b > sizeof(tmp)) b = sizeof(tmp);
            memcpy(tmp, buf + p, b);
            memmove(buf + p, buf + p + b, n - p - b);
            memcpy(buf + n - b, tmp, b);
        }
        break;
    }
    case 6: /* arithmetic on a 1/2/4-byte window */
        if (n > 0) {
            size_t p = rng_below(n);
            int delta = (rng_next() & 1) ? 1 : -1;
            buf[p] = (uint8_t)((int)buf[p] + delta);
        }
        break;
    case 7: /* truncate / extend to a random length */
        if (rng_next() & 1) {
            *len = rng_below(n + 1);
        } else if (n < MAX_INPUT) {
            size_t want = n + 1 + rng_below(MAX_INPUT - n < 64 ? MAX_INPUT - n : 64);
            while (*len < want)
                buf[(*len)++] = (uint8_t)(rng_next() >> 24);
        }
        break;
    }
}

/* Number of mutations applied to a seed each round. Occasionally stack
 * several mutations to reach deeper structural changes. */
static size_t mutation_count(void) {
    if (rng_below(100) < 80) return 1;
    return 2 + rng_below(3);
}

/* ------------------------------------------------------------- corpus */

typedef struct {
    uint8_t *data;
    size_t len;
} Seed;

static int load_corpus(const char *dir, Seed **out_seeds, size_t *out_n) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "find '%s' -maxdepth 1 -type f -print0 2>/dev/null", dir);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;

    Seed *seeds = NULL;
    size_t n = 0, cap = 0;
    char path[1024];
    size_t used = 0;
    int ch;
    while ((ch = fgetc(p)) != EOF) {
        if (ch != 0) {
            if (used + 1 < sizeof(path)) path[used++] = (char)ch;
            continue;
        }
        path[used] = 0;
        used = 0;
        uint8_t *buf = malloc(MAX_INPUT);
        if (!buf) { pclose(p); return -1; }
        size_t len = 0;
        if (read_file(path, buf, MAX_INPUT, &len) == 0) {
            if (n == cap) {
                cap = cap ? cap * 2 : 8;
                Seed *g = realloc(seeds, cap * sizeof(Seed));
                if (!g) { free(buf); pclose(p); return -1; }
                seeds = g;
            }
            seeds[n].data = buf;
            seeds[n].len = len;
            n++;
        } else {
            free(buf);
        }
    }
    pclose(p);
    *out_seeds = seeds;
    *out_n = n;
    return 0;
}

/* ------------------------------------------------------- worker verdict */

static Verdict classify(int status, pid_t pid) {
    Verdict v;
    if (WIFSIGNALED(status)) {
        /* LSan aborts after reporting a leak; the log tells them apart. */
        if (log_says_leak(pid)) {
            v.kind = V_LEAK;
            v.code = WTERMSIG(status);
        } else {
            v.kind = V_CRASH;
            v.code = WTERMSIG(status);
        }
    } else if (WIFEXITED(status)) {
        int e = WEXITSTATUS(status);
        if (e == 23 || log_says_leak(pid)) {
            v.kind = V_LEAK;
            v.code = e;
        } else if (e == 0) {
            v.kind = V_OK;
            v.code = 0;
        } else {
            v.kind = V_CRASH;     /* non-zero exit, e.g. sanitizer exit */
            v.code = e;
        }
    } else {
        v.kind = V_ERROR;
        v.code = status;
    }
    return v;
}

static int verdict_bad(VerdictKind k) {
    return k == V_CRASH || k == V_TIMEOUT || k == V_LEAK;
}

/* ----------------------------------------------------- single execution */

/* Run one input in a forked child with a watchdog. The child initializes
 * the target once per process and then calls fuzz_one(). */
static Verdict run_one(const uint8_t *data, size_t len, int timeout_ms) {
    pid_t pid = fork();
    if (pid < 0)
        return (Verdict){V_ERROR, errno};

    if (pid == 0) {
        fuzz_init();
        fuzz_one(data, len);
        /* exit(), not _exit(): atexit gives LSan its leak scan. */
        exit(0);
    }

    long deadline = now_ms() + timeout_ms;
    for (;;) {
        int status;
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid)
            return classify(status, pid);
        if (r < 0)
            return (Verdict){V_ERROR, errno};
        long remain = deadline - now_ms();
        if (remain <= 0) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            return (Verdict){V_TIMEOUT, SIGKILL};
        }
        struct timespec ts = { .tv_sec = 0,
                               .tv_nsec = (remain > 10 ? 10 : remain) * 1000000L };
        nanosleep(&ts, NULL);
    }
}

/* ------------------------------------------------------------- findings */

typedef struct {
    VerdictKind kind;
    int code;
    uint64_t iter;
    uint8_t *data;
    size_t len;
    char raw_path[256];
    char min_path[256];
} Finding;

static const char *finding_prefix(VerdictKind k) {
    switch (k) {
    case V_CRASH:   return "crash";
    case V_TIMEOUT: return "timeout";
    case V_LEAK:    return "leak";
    default:        return "finding";
    }
}

/* -------------------------------------------------------- minimization */

/* Try a candidate; only keep the verdict class we are minimizing for. */
static int trial_keeps(const uint8_t *data, size_t len, VerdictKind want,
                       int timeout_ms) {
    Verdict v = run_one(data, len, timeout_ms);
    return v.kind == want;
}

/* ddmin-style chunk removal followed by a per-byte simplification pass.
 * Returns a new malloc'd buffer and stores its length. */
static uint8_t *minimize(const uint8_t *in, size_t in_len, VerdictKind want,
                         int timeout_ms, size_t *out_len) {
    uint8_t *cur = malloc(in_len ? in_len : 1);
    memcpy(cur, in, in_len);
    size_t cur_len = in_len;
    long budget = MIN_TRIALS;

    /* Pass 1: remove chunks (classic ddmin granularity shrinking). */
    size_t granularity = cur_len < 2 ? 1 : cur_len / 2;
    while (granularity > 0 && budget > 0) {
        int reduced = 0;
        size_t start = 0;
        while (start < cur_len && budget > 0) {
            size_t end = start + granularity;
            if (end > cur_len) end = cur_len;
            size_t trial_len = cur_len - (end - start);
            uint8_t *trial = malloc(trial_len ? trial_len : 1);
            memcpy(trial, cur, start);
            memcpy(trial + start, cur + end, cur_len - end);
            budget--;
            if (trial_keeps(trial, trial_len, want, timeout_ms)) {
                free(cur);
                cur = trial;
                cur_len = trial_len;
                reduced = 1;
                /* stay at the same offset; content shifted left */
            } else {
                free(trial);
                start = end;
            }
        }
        if (!reduced) {
            if (granularity == 1) break;
            granularity = granularity / 2;
            if (granularity == 0) granularity = 1;
        } else if (granularity > 1 && granularity > cur_len / 4) {
            granularity = cur_len < 2 ? 1 : cur_len / 2;
        }
    }

    /* Pass 2: per-byte substitution toward minimal/printable values. */
    for (size_t i = 0; i < cur_len && budget > 0; i++) {
        uint8_t orig = cur[i];
        static const uint8_t attempts[] = {0, '\n', '\r', ' ', 'A', '0'};
        for (size_t j = 0; j < sizeof(attempts) && budget > 0; j++) {
            if (attempts[j] == orig) continue;
            cur[i] = attempts[j];
            budget--;
            if (!trial_keeps(cur, cur_len, want, timeout_ms))
                cur[i] = orig;
        }
    }

    *out_len = cur_len;
    return cur;
}

/* --------------------------------------------------------------- batch */

/* Read one 4-byte-length-framed input from the pipe. Returns 0 on a
 * frame, 1 on clean EOF, -1 on protocol error. */
static int recv_frame(int fd, uint8_t *buf, size_t *out_len) {
    size_t need = 4;
    uint8_t hdr[4];
    size_t got = 0;
    while (got < need) {
        ssize_t r = read(fd, hdr + got, need - got);
        if (r == 0) return got == 0 ? 1 : -1;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
    }
    size_t len = ((size_t)hdr[0] << 24) | ((size_t)hdr[1] << 16) |
                 ((size_t)hdr[2] << 8) | (size_t)hdr[3];
    if (len > MAX_INPUT) return -1;
    got = 0;
    while (got < len) {
        ssize_t r = read(fd, buf + got, len - got);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
    }
    *out_len = len;
    return 0;
}

static void send_frame(int fd, const uint8_t *data, size_t len) {
    uint8_t hdr[4] = {
        (uint8_t)(len >> 24), (uint8_t)(len >> 16),
        (uint8_t)(len >> 8), (uint8_t)len
    };
    size_t off = 0;
    while (off < 4) {
        ssize_t w = write(fd, hdr + off, 4 - off);
        if (w < 0) { if (errno == EINTR) continue; return; }
        off += (size_t)w;
    }
    off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; return; }
        off += (size_t)w;
    }
}

/* ----------------------------------------------------------- campaign */

typedef struct {
    const char *target;
    const char *outdir;
    const char *corpus;
    size_t iters;
    size_t batch;
    uint64_t rng_seed;
    int timeout_ms;
} Campaign;

static void save_manifest(const Campaign *c, const Finding *f, size_t nf,
                          int clean) {
    char path[512];
    snprintf(path, sizeof(path), "%s/manifest.json", c->outdir);
    FILE *m = fopen(path, "w");
    if (!m) return;
    fprintf(m, "{\n");
    fprintf(m, "  \"target\": \"%s\",\n", c->target);
    fprintf(m, "  \"iterations\": %zu,\n", c->iters);
    fprintf(m, "  \"rng_seed\": %llu,\n", (unsigned long long)c->rng_seed);
    fprintf(m, "  \"batch_size\": %zu,\n", c->batch);
    fprintf(m, "  \"input_timeout_ms\": %d,\n", c->timeout_ms);
    fprintf(m, "  \"clean\": %s,\n", clean ? "true" : "false");
    fprintf(m, "  \"findings\": [\n");
    for (size_t i = 0; i < nf; i++) {
        fprintf(m,
            "    {\"id\": %zu, \"kind\": \"%s\", \"code\": %d, \"iteration\": %llu,"
            " \"size\": %zu, \"raw\": \"%s\", \"minimized\": \"%s\"}%s\n",
            i, verdict_name(f[i].kind), f[i].code,
            (unsigned long long)f[i].iter, f[i].len,
            f[i].raw_path, f[i].min_path, i + 1 < nf ? "," : "");
    }
    fprintf(m, "  ]\n}\n");
    fclose(m);
}

/* Locate the exact failing input in a bad batch by re-running each
 * input in its own watched process. Returns index, or -1 if none of the
 * inputs individually reproduces (a cross-input worker issue). */
static ssize_t pinpoint(const uint8_t *batch, const size_t *lens, size_t n,
                        VerdictKind *out_kind, int *out_code, int timeout_ms) {
    size_t off = 0;
    for (size_t i = 0; i < n; i++) {
        Verdict v = run_one(batch + off, lens[i], timeout_ms);
        if (verdict_bad(v.kind)) {
            *out_kind = v.kind;
            *out_code = v.code;
            return (ssize_t)i;
        }
        off += lens[i];
    }
    return -1;
}

static int run_campaign(const Campaign *c) {
    if (ensure_dir(c->outdir) != 0)
        die("cannot create output dir %s: %s", c->outdir, strerror(errno));

    /* Sanitizer logs land in <outdir>/logs; run_fuzz.sh exports the
     * matching log_path in ASAN_OPTIONS at process startup. */
    snprintf(g_log_dir, sizeof(g_log_dir), "%s/logs", c->outdir);
    ensure_dir(g_log_dir);

    Seed *seeds = NULL;
    size_t nseeds = 0;
    if (load_corpus(c->corpus, &seeds, &nseeds) != 0 || nseeds == 0)
        die("no seed corpus found in %s", c->corpus);

    rng_seed(c->rng_seed);

    Finding findings[MAX_FINDINGS];
    size_t nf = 0;

    /* Smoke pass: every seed verbatim, before any mutation. A crash on
     * a canonical seed is the most direct possible failure. */
    for (size_t i = 0; i < nseeds && nf < MAX_FINDINGS; i++) {
        Verdict v = run_one(seeds[i].data, seeds[i].len, c->timeout_ms);
        if (!verdict_bad(v.kind)) continue;
        Finding *f = &findings[nf];
        f->kind = v.kind;
        f->code = v.code;
        f->iter = 0;
        f->data = malloc(seeds[i].len ? seeds[i].len : 1);
        memcpy(f->data, seeds[i].data, seeds[i].len);
        f->len = seeds[i].len;
        snprintf(f->raw_path, sizeof(f->raw_path),
                 "%s/%s-%02zu.raw", c->outdir, finding_prefix(v.kind), nf);
        snprintf(f->min_path, sizeof(f->min_path),
                 "%s/%s-%02zu.min", c->outdir, finding_prefix(v.kind), nf);
        write_file(f->raw_path, f->data, f->len);
        size_t mlen = 0;
        uint8_t *mini = minimize(f->data, f->len, v.kind, c->timeout_ms, &mlen);
        write_file(f->min_path, mini, mlen);
        fprintf(stderr,
                "fuzz: #%zu seed %s (code %d), %zu -> %zu bytes: %s\n",
                nf, verdict_name(v.kind), v.code, f->len, mlen, f->min_path);
        free(mini);
        nf++;
    }

    long start = now_ms();
    size_t done = 0;
    uint64_t next_report = 1000;

    while (done < c->iters) {
        size_t b = c->iters - done;
        if (b > c->batch) b = c->batch;

        uint8_t *payload = malloc((size_t)b * MAX_INPUT);
        size_t *lens = calloc(b, sizeof(size_t));
        if (!payload || !lens) die("out of memory");

        size_t total = 0;
        for (size_t i = 0; i < b; i++) {
            Seed *s = &seeds[rng_below(nseeds)];
            uint8_t *slot = payload + total;
            memcpy(slot, s->data, s->len);
            size_t len = s->len;
            size_t nmut = mutation_count();
            for (size_t m = 0; m < nmut; m++)
                mutate(slot, &len);
            lens[i] = len;
            total += len;
        }

        int fds[2];
        if (pipe(fds) != 0) die("pipe: %s", strerror(errno));

        pid_t pid = fork();
        if (pid < 0) die("fork: %s", strerror(errno));

        if (pid == 0) {
            close(fds[0]);
            fuzz_init();
            uint8_t in[MAX_INPUT];
            size_t in_len;
            while (recv_frame(fds[1], in, &in_len) == 0)
                fuzz_one(in, in_len);
            exit(0); /* LSan leak scan happens here */
        }
        close(fds[1]);

        /* Stream frames, then close the pipe so the worker reaches EOF. */
        size_t off = 0;
        for (size_t i = 0; i < b; i++) {
            send_frame(fds[0], payload + off, lens[i]);
            off += lens[i];
        }
        close(fds[0]);

        long deadline = now_ms() + (long)c->timeout_ms * (long)b;
        int status;
        for (;;) {
            pid_t r = waitpid(pid, &status, WNOHANG);
            if (r == pid) break;
            if (r < 0) die("waitpid: %s", strerror(errno));
            if (now_ms() > deadline) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                status = -1; /* marker: batch-level timeout */
                break;
            }
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 5 * 1000000L };
            nanosleep(&ts, NULL);
        }

        Verdict batch_v = (status == -1)
            ? (Verdict){V_TIMEOUT, SIGKILL}
            : classify(status, pid);

        if (verdict_bad(batch_v.kind)) {
            VerdictKind want = batch_v.kind;
            int code = batch_v.code;
            ssize_t idx = pinpoint(payload, lens, b, &want, &code,
                                   c->timeout_ms);
            if (idx >= 0 && nf < MAX_FINDINGS) {
                Finding *f = &findings[nf];
                size_t p = 0;
                for (ssize_t i = 0; i < idx; i++) p += lens[i];

                f->kind = want;
                f->code = code;
                f->iter = done + (uint64_t)idx + 1;
                f->data = malloc(lens[idx]);
                memcpy(f->data, payload + p, lens[idx]);
                f->len = lens[idx];
                snprintf(f->raw_path, sizeof(f->raw_path),
                         "%s/%s-%02zu.raw", c->outdir,
                         finding_prefix(want), nf);
                snprintf(f->min_path, sizeof(f->min_path),
                         "%s/%s-%02zu.min", c->outdir,
                         finding_prefix(want), nf);
                write_file(f->raw_path, f->data, f->len);

                size_t mlen = 0;
                uint8_t *mini = minimize(f->data, f->len, want,
                                         c->timeout_ms, &mlen);
                write_file(f->min_path, mini, mlen);
                fprintf(stderr,
                        "fuzz: #%zu %s (code %d) at iter %llu, "
                        "%zu -> %zu bytes: %s\n",
                        nf, verdict_name(want), code,
                        (unsigned long long)f->iter, f->len, mlen,
                        f->min_path);
                free(mini);
                nf++;
            } else if (idx < 0) {
                fprintf(stderr,
                        "fuzz: batch verdict %s but no single input "
                        "reproduced at iter %zu\n", verdict_name(want), done);
            }
        }

        free(payload);
        free(lens);
        done += b;

        if (done >= next_report || done == c->iters) {
            fprintf(stderr, "fuzz: %s %zu/%zu iterations, %zu finding(s), "
                    "%ld ms\n", c->target, done, c->iters, nf,
                    now_ms() - start);
            next_report += 10000;
        }
    }

    int clean = (nf == 0);
    save_manifest(c, findings, nf, clean);
    for (size_t i = 0; i < nf; i++) free(findings[i].data);
    for (size_t i = 0; i < nseeds; i++) free(seeds[i].data);
    free(seeds);

    fprintf(stderr, "fuzz: %s finished: %zu iters, %zu finding(s), %s\n",
            c->target, c->iters, nf, clean ? "CLEAN" : "FAILURES PRESENT");
    return clean ? 0 : 1;
}

/* ------------------------------------------------------------- oneshot */

static int run_oneshot(const char *path, int timeout_ms) {
    /* Shell sets ASAN_OPTIONS log_path to this same directory. */
    const char *d = getenv("FUZZ_LOG_DIR");
    if (d && *d)
        snprintf(g_log_dir, sizeof(g_log_dir), "%s", d);
    else
        snprintf(g_log_dir, sizeof(g_log_dir),
                 "/tmp/fuzz-oneshot-%d", (int)getpid());
    ensure_dir(g_log_dir);

    uint8_t *buf = malloc(MAX_INPUT);
    if (!buf) die("out of memory");
    size_t len = 0;
    if (read_file(path, buf, MAX_INPUT, &len) != 0)
        die("cannot read %s: %s", path, strerror(errno));

    Verdict v = run_one(buf, len, timeout_ms);
    fprintf(stderr, "fuzz: oneshot %s: %s (code %d), %zu bytes\n",
            path, verdict_name(v.kind), v.code, len);
    free(buf);
    if (v.kind == V_OK) return 0;
    return v.kind == V_TIMEOUT ? 76 : (v.kind == V_LEAK ? 23 : 70);
}

/* ------------------------------------------------------------- minimize */

static int run_minimize_cmd(const char *in_path, const char *out_path,
                            const char *kind_s, int timeout_ms) {
    const char *d = getenv("FUZZ_LOG_DIR");
    if (d && *d) {
        snprintf(g_log_dir, sizeof(g_log_dir), "%s", d);
        ensure_dir(g_log_dir);
    }

    VerdictKind want;
    if (!strcmp(kind_s, "crash"))        want = V_CRASH;
    else if (!strcmp(kind_s, "timeout")) want = V_TIMEOUT;
    else if (!strcmp(kind_s, "leak"))    want = V_LEAK;
    else die("kind must be crash|timeout|leak");

    uint8_t *buf = malloc(MAX_INPUT);
    if (!buf) die("out of memory");
    size_t len = 0;
    if (read_file(in_path, buf, MAX_INPUT, &len) != 0)
        die("cannot read %s: %s", in_path, strerror(errno));

    if (!trial_keeps(buf, len, want, timeout_ms))
        die("input %s does not reproduce a %s", in_path, kind_s);

    size_t mlen = 0;
    uint8_t *mini = minimize(buf, len, want, timeout_ms, &mlen);
    if (write_file(out_path, mini, mlen) != 0)
        die("cannot write %s: %s", out_path, strerror(errno));
    fprintf(stderr, "fuzz: minimized %zu -> %zu bytes -> %s\n",
            len, mlen, out_path);

    Verdict v = run_one(mini, mlen, timeout_ms);
    fprintf(stderr, "fuzz: verify minimized sample: %s (code %d)\n",
            verdict_name(v.kind), v.code);
    free(mini);
    free(buf);
    return v.kind == want ? 0 : 1;
}

/* ---------------------------------------------------------------- seed */

void engine_emit_seed(const uint8_t *data, size_t size) {
    if (size > MAX_INPUT) return;
    uint8_t hdr[4] = {
        (uint8_t)(size >> 24), (uint8_t)(size >> 16),
        (uint8_t)(size >> 8), (uint8_t)size
    };
    fwrite(hdr, 1, 4, stdout);
    fwrite(data, 1, size, stdout);
}

__attribute__((weak)) void fuzz_init(void) { /* optional */ }
__attribute__((weak)) int fuzz_seed(void) { return 0; }

/* ------------------------------------------------------------- unseed */

/* Read framed seeds from stdin and write each one as seed-NNNN in dir. */
static int run_unseed(const char *dir) {
    if (ensure_dir(dir) != 0)
        die("cannot create corpus dir %s: %s", dir, strerror(errno));
    uint8_t buf[MAX_INPUT];
    size_t n = 0;
    for (;;) {
        size_t len = 0;
        int r = recv_frame(STDIN_FILENO, buf, &len);
        if (r == 1) break;
        if (r < 0) die("corrupt seed stream");
        char path[1024];
        snprintf(path, sizeof(path), "%s/seed-%04zu", dir, n);
        if (write_file(path, buf, len) != 0)
            die("cannot write %s: %s", path, strerror(errno));
        n++;
    }
    fprintf(stderr, "fuzz: wrote %zu seed file(s) to %s\n", n, dir);
    return 0;
}

/* ----------------------------------------------------------------- CLI */

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s <campaign|oneshot|minimize|seed|unseed> [opts]\n"
        "  campaign --corpus DIR --out DIR [--iters N] [--batch N]\n"
        "           [--rng-seed N] [--timeout-ms N]\n"
        "  oneshot  --input FILE [--timeout-ms N]\n"
        "  minimize --input FILE --output FILE --kind crash|timeout|leak\n"
        "           [--timeout-ms N]\n"
        "  seed     (framed seeds on stdout)\n"
        "  unseed   --out DIR (framed seeds on stdin -> seed-NNNN files)\n",
        prog);
}

int engine_run(const char *target, int argc, char **argv) {
    sanitizer_env();

    if (argc < 2) { usage(argv[0]); return 2; }
    const char *cmd = argv[1];

    if (!strcmp(cmd, "seed"))
        return fuzz_seed();
    if (!strcmp(cmd, "unseed")) {
        const char *out = NULL;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--out") && i + 1 < argc)
                out = argv[++i];
        }
        if (!out) { usage(argv[0]); return 2; }
        return run_unseed(out);
    }

    const char *corpus = NULL, *out = NULL, *input = NULL, *output = NULL;
    const char *kind_s = "crash";
    size_t iters = DEFAULT_ITERS, batch = DEFAULT_BATCH;
    uint64_t seed = 1;
    int timeout_ms = INPUT_TIMEOUT_MS;

    for (int i = 2; i < argc; i++) {
        const char *o = argv[i];
        const char *v = (i + 1 < argc) ? argv[++i] : NULL;
        if (!v) { usage(argv[0]); return 2; }
        if (!strcmp(o, "--corpus"))        corpus = v;
        else if (!strcmp(o, "--out"))      out = v;
        else if (!strcmp(o, "--input"))    input = v;
        else if (!strcmp(o, "--output"))   output = v;
        else if (!strcmp(o, "--kind"))     kind_s = v;
        else if (!strcmp(o, "--iters"))    iters = (size_t)strtoull(v, NULL, 10);
        else if (!strcmp(o, "--batch"))    batch = (size_t)strtoull(v, NULL, 10);
        else if (!strcmp(o, "--rng-seed")) seed = strtoull(v, NULL, 0);
        else if (!strcmp(o, "--timeout-ms")) timeout_ms = atoi(v);
        else { usage(argv[0]); return 2; }
    }

    if (!strcmp(cmd, "campaign")) {
        if (!corpus || !out) { usage(argv[0]); return 2; }
        Campaign c = {
            .target = target, .outdir = out, .corpus = corpus,
            .iters = iters, .batch = batch, .rng_seed = seed,
            .timeout_ms = timeout_ms
        };
        return run_campaign(&c);
    }
    if (!strcmp(cmd, "oneshot")) {
        if (!input) { usage(argv[0]); return 2; }
        return run_oneshot(input, timeout_ms);
    }
    if (!strcmp(cmd, "minimize")) {
        if (!input || !output) { usage(argv[0]); return 2; }
        return run_minimize_cmd(input, output, kind_s, timeout_ms);
    }

    usage(argv[0]);
    return 2;
}

/* Each harness links exactly one engine translation unit; derive the
 * target name from the executable (argv[0] basename, "fuzz-" stripped). */
int main(int argc, char **argv) {
    const char *slash = strrchr(argv[0], '/');
    const char *base = slash ? slash + 1 : argv[0];
    const char *target = base;
    if (!strncmp(base, "fuzz-", 5))
        target = base + 5;
    return engine_run(target, argc, argv);
}
