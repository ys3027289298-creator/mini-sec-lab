#define _GNU_SOURCE
#include "pg_worker.h"

#include "pg_cases.h"
#include "pg_open.h"
#include "pg_policy.h"
#include "pg_sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>

static int outfd = -1;

#define OUTBUF 8192
static char outbuf[OUTBUF];
static size_t outlen;

static void out_flush(void) {
    size_t off = 0;
    while (off < outlen) {
        ssize_t w = write(outfd, outbuf + off, outlen - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    outlen = 0;
}

/* vsnprintf only formats; the single write(2) in out_flush is the only
   syscall here, and it is on the allowlist. */
static void out_fmt(const char* fmt, ...) {
    char tmp[320];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    size_t n = strlen(tmp);
    if (n >= OUTBUF) {
        out_flush();
        size_t off = 0;
        while (off < n) {
            ssize_t w = write(outfd, tmp + off, n - off);
            if (w <= 0) return;
            off += (size_t)w;
        }
        return;
    }
    if (outlen + n > OUTBUF) out_flush();
    memcpy(outbuf + outlen, tmp, n);
    outlen += n;
}

static int read_all(int fd, char* buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = read(fd, buf + n, cap - 1 - n);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        n += (size_t)r;
    }
    buf[n] = 0;
    return (int)n;
}

static int has_secret(const char* b, int n) {
    static const char secret[] = "outside-secret";
    if (n < (int)sizeof(secret) - 1) return 0;
    for (int i = 0; i + (int)sizeof secret - 2 < n; i++)
        if (!memcmp(b + i, secret, sizeof secret - 1)) return 1;
    return 0;
}

/* The opener the audit finding describes: resolve the name, then open.
   With use_resolve=0 it keeps no resolve flags, so only Landlock (if any)
   can stop an escape. */
static long plain_open(int rootfd, const char* name, int use_resolve) {
    return use_resolve ? pg_openat2(rootfd, name, O_RDONLY | O_CLOEXEC)
                       : pg_openat2_raw(rootfd, name, O_RDONLY | O_CLOEXEC, 0);
}

static void one_open(int rootfd, const char* name, int use_resolve,
                     const char* tag, const char* expect_body) {
    long fd = plain_open(rootfd, name, use_resolve);
    if (fd < 0) {
        out_fmt("%s %s open=deny errno=%d\n", tag, name, errno);
        return;
    }
    char buf[128];
    int n = read_all((int)fd, buf, sizeof buf);
    close((int)fd);
    if (n < 0) n = 0;
    int body_ok = expect_body && n == (int)strlen(expect_body) &&
                  memcmp(buf, expect_body, (size_t)n) == 0;
    out_fmt("%s %s open=ok bytes=%d secret=%d body=%s\n", tag, name, n,
            has_secret(buf, n),
            expect_body ? (body_ok ? "match" : "differs") : "-");
}

static void run_scenarios(int rootfd, int use_resolve, int validate) {
    char dec[PG_MAX_PATH];

    for (int i = 0; i < PG_VALID_COUNT; i++) {
        const char* name = PG_VALID_NAMES[i];
        const char* path = name;
        if (validate) {
            size_t len = 0;
            PgErr e = pg_check_name(name, dec, sizeof dec, &len);
            if (e != PG_OK) {
                out_fmt("valid %s lex=%s\n", name, pg_err_name(e));
                continue;
            }
            path = dec;
        }
        one_open(rootfd, path, use_resolve, "valid", PG_VALID_BODY[i]);
    }

    for (int i = 0; i < PG_ESCAPE_COUNT; i++) {
        const char* name = PG_ESCAPE_NAMES[i];
        const char* path = name;
        if (validate) {
            size_t len = 0;
            PgErr e = pg_check_name(name, dec, sizeof dec, &len);
            if (e != PG_OK) {
                out_fmt("escape %s lex=%s\n", name, pg_err_name(e));
                continue;
            }
            path = dec;
        }
        one_open(rootfd, path, use_resolve, "escape", NULL);
    }
}

static void run_writes(int rootfd) {
    long fd = pg_openat2_at(rootfd, PG_SCRATCH "/new.txt",
                            O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        out_fmt("write %s/new.txt open=deny errno=%d\n", PG_SCRATCH, errno);
    } else {
        ssize_t w = write((int)fd, "x", 1);
        close((int)fd);
        out_fmt("write %s/new.txt open=ok write=%s\n", PG_SCRATCH,
                w == 1 ? "ok" : "fail");
    }
    fd = pg_openat2_at(rootfd, "data/new.txt",
                       O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    out_fmt("write data/new.txt open=%s errno=%d\n", fd < 0 ? "deny" : "ok",
            fd < 0 ? errno : 0);
    if (fd >= 0) close((int)fd);
}

/* Each probe names the layer that must answer it, so the report shows
   EPERM from seccomp next to EACCES from Landlock. */
static void run_probes(int rootfd) {
    errno = 0;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    out_fmt("probe socket=%s errno=%d layer=seccomp\n", s < 0 ? "deny" : "ok",
            errno);
    if (s >= 0) close(s);

    errno = 0;
    int ch = chdir("/");
    out_fmt("probe chdir=%s errno=%d layer=seccomp\n", ch < 0 ? "deny" : "ok",
            errno);

    errno = 0;
    long p = syscall(SYS_ptrace, 0, 0, 0, 0);
    out_fmt("probe ptrace=%s errno=%d layer=seccomp\n", p < 0 ? "deny" : "ok",
            errno);

    errno = 0;
    long f = syscall(SYS_fork);
    out_fmt("probe fork=%s errno=%d layer=seccomp\n", f < 0 ? "deny" : "ok",
            errno);

    errno = 0;
    int e = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
    out_fmt("probe open_legacy=%s errno=%d layer=seccomp\n",
            e < 0 ? "deny" : "ok", errno);
    if (e >= 0) close(e);

    errno = 0;
    /* Absolute name, no resolve flags: only Landlock can refuse this, so
       the errno distinguishes the layer from the seccomp cases above. */
    long l = pg_openat2_raw(AT_FDCWD, "/etc/passwd", O_RDONLY | O_CLOEXEC, 0);
    out_fmt("probe open_outside=%s errno=%d layer=landlock\n",
            l < 0 ? "deny" : "ok", errno);
    if (l >= 0) close((int)l);

    /* Hitting the descriptor ceiling proves RLIMIT_NOFILE took effect and
       that the refusal is EMFILE, not a crash. */
    int held[128];
    int n = 0;
    for (; n < 128; n++) {
        held[n] = (int)pg_openat2(rootfd, PG_VALID_NAMES[0],
                                  O_RDONLY | O_CLOEXEC);
        if (held[n] < 0) break;
    }
    out_fmt("probe nofile=%s errno=%d held=%d layer=rlimit\n",
            n < 128 ? "deny" : "ok", errno, n);
    for (int i = 0; i < n; i++) close(held[i]);
}

/* Push past RLIMIT_FSIZE; the kernel's SIGXFSZ ends the process. */
static void run_fsize(int rootfd) {
    long fd = pg_openat2_at(rootfd, PG_SCRATCH "/big.bin",
                            O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        out_fmt("probe fsize=open_deny errno=%d\n", errno);
        return;
    }
    static char block[4096];
    memset(block, 'A', sizeof block);
    for (int i = 0; i < 512; i++) {
        ssize_t w = write((int)fd, block, sizeof block);
        if (w < 0) {
            out_fmt("probe fsize=deny errno=%d at_block=%d\n", errno, i);
            close((int)fd);
            return;
        }
    }
    out_fmt("probe fsize=miss\n");
    close((int)fd);
}

/* Deterministic check/use race.  The worker validates the name, hands
   control to the driver, and only opens after the driver has replaced
   data/sub with a symlink to outside/.  Nothing depends on timing luck,
   so the outcome is the same on every run. */
static void run_toctou(int rootfd, int syncfd, int use_resolve, int validate) {
    char dec[PG_MAX_PATH];
    const char* path = PG_TOCTOU_NAME;
    char tok = 'x';

    if (validate) {
        size_t len = 0;
        if (pg_check_name(PG_TOCTOU_NAME, dec, sizeof dec, &len) != PG_OK) {
            out_fmt("toctou result=0 reason=lex\n");
            return;
        }
        path = dec;
    }

    /* 1. driver swaps data/sub for a symlink and acknowledges. */
    if (write(syncfd, &tok, 1) != 1 || read(syncfd, &tok, 1) != 1) return;

    /* 2. the open the audit finding is about. */
    long fd = plain_open(rootfd, path, use_resolve);
    int leak = 0, denied = 0;
    if (fd < 0) {
        denied = 1;
    } else {
        char buf[128];
        int n = read_all((int)fd, buf, sizeof buf);
        close((int)fd);
        leak = n > 0 && has_secret(buf, n);
    }

    /* 3. driver restores the directory. */
    if (write(syncfd, &tok, 1) != 1 || read(syncfd, &tok, 1) != 1) return;

    out_fmt("toctou result=1 denied=%d leaks=%d\n", denied, leak);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* RAW: plain openat2, no validation and no resolve flags.
   GUARD: exactly the production path - validate + resolve flags.
   SB: the same production path with Landlock and seccomp installed, so
   the delta is the kernel's per-call LSM/BPF cost. */
static void bench_loop(int mode, int rootfd, int iters) {
    char dec[PG_MAX_PATH];
    size_t len = 0;
    int errors = 0;
    uint64_t t0 = now_ns();
    for (int i = 0; i < iters; i++) {
        const char* path = PG_VALID_NAMES[i % PG_VALID_COUNT];
        if (mode != WK_BENCH_RAW) {
            if (pg_check_name(path, dec, sizeof dec, &len) != PG_OK) {
                errors++;
                continue;
            }
            path = dec;
        }
        /* Resolve flags are part of the production opener in every mode
           except RAW, so the delta measured for SB is the sandbox, not a
           missing openat2 cost. */
        long fd = mode == WK_BENCH_RAW
                      ? pg_openat2_raw(rootfd, path, O_RDONLY | O_CLOEXEC, 0)
                      : pg_openat2(rootfd, path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            errors++;
            continue;
        }
        char c;
        ssize_t r = read((int)fd, &c, 1);
        close((int)fd);
        if (r < 0) errors++;
    }
    uint64_t t1 = now_ns();
    out_fmt("bench mode=%d iters=%d total_ns=%llu errors=%d\n", mode, iters,
            (unsigned long long)(t1 - t0), errors);
}

static void setup_timing(int rootfd) {
    PgSandboxState st;
    uint64_t t0 = now_ns();
    if (pg_sandbox_enter(&st) < 0) {
        out_fmt("fatal userns_map=deny\n");
        return;
    }
    uint64_t t1 = now_ns();
    PgLimits lim = PG_LIMITS_DEFAULT;
    if (pg_sandbox_lock(&st, rootfd, &lim, PG_SB_ALL, 1, PG_SCRATCH) < 0) {
        out_fmt("fatal sandbox=deny\n");
        return;
    }
    uint64_t t2 = now_ns();
    out_fmt("setup userns_caps_ns=%llu landlock_seccomp_rlimit_ns=%llu "
            "total_ns=%llu landlock_abi=%d seccomp=%d rlimit=%d nnp=%d "
            "caps=%d\n",
            (unsigned long long)(t1 - t0), (unsigned long long)(t2 - t1),
            (unsigned long long)(t2 - t0), st.landlock_abi, st.seccomp,
            st.rlimits, st.no_new_privs, st.cap_effective);
}

int pg_worker_main(int argc, char** argv) {
    if (argc < 5) {
        static const char bad[] = "fatal badargs\n";
        if (outfd >= 0) {
            ssize_t r = write(outfd, bad, sizeof bad - 1);
            (void)r;
        }
        return 2;
    }
    outfd = atoi(argv[3]);
    int iters = atoi(argv[4]);
    int syncfd = argc >= 6 ? atoi(argv[5]) : -1;

    int mode = WK_GUARD;
    if (!strcmp(argv[1], "naive")) mode = WK_NAIVE;
    else if (!strcmp(argv[1], "sb_naive")) mode = WK_SB_NAIVE;
    else if (!strcmp(argv[1], "sb_full")) mode = WK_SB_FULL;
    else if (!strcmp(argv[1], "probes")) mode = WK_PROBE;
    else if (!strcmp(argv[1], "fsize")) mode = WK_FSIZE;
    else if (!strcmp(argv[1], "toctou_naive")) mode = WK_TOCTOU_NAIVE;
    else if (!strcmp(argv[1], "toctou_sb")) mode = WK_TOCTOU_SB;
    else if (!strcmp(argv[1], "setup")) mode = WK_SETUP;
    else if (!strcmp(argv[1], "bench_raw")) mode = WK_BENCH_RAW;
    else if (!strcmp(argv[1], "bench_guard")) mode = WK_BENCH_GUARD;
    else if (!strcmp(argv[1], "bench_sb")) mode = WK_BENCH_SB;

    int rootfd = (int)pg_openat2_raw(AT_FDCWD, argv[2],
                                     O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
    if (rootfd < 0) {
        out_fmt("fatal root_open=deny errno=%d\n", errno);
        out_flush();
        return 3;
    }

    if (mode == WK_SETUP) {
        setup_timing(rootfd);
        out_flush();
        return 0;
    }

    int sandboxed = mode == WK_SB_NAIVE || mode == WK_SB_FULL ||
                    mode == WK_PROBE || mode == WK_FSIZE ||
                    mode == WK_TOCTOU_SB || mode == WK_BENCH_SB;

    if (sandboxed) {
        PgSandboxState st;
        if (pg_sandbox_enter(&st) < 0) {
            out_fmt("fatal userns_map=deny\n");
            out_flush();
            return 4;
        }
        /* TOCTOU and unhardened-opener modes stay naive on purpose: they
           prove Landlock alone holds when validation is bypassed.  The
           others get the full stack. */
        unsigned flags = (mode == WK_SB_NAIVE || mode == WK_TOCTOU_SB)
                             ? PG_SB_LANDLOCK
                             : PG_SB_ALL;
        PgLimits lim = PG_LIMITS_DEFAULT;
        if (pg_sandbox_lock(&st, rootfd, &lim, flags, 1, PG_SCRATCH) < 0) {
            out_fmt("fatal sandbox=deny\n");
            out_flush();
            return 5;
        }
        out_fmt("sandbox userns=%d caps=%d landlock_abi=%d seccomp=%d "
                "rlimit=%d nnp=%d\n",
                st.user_ns, st.cap_effective, st.landlock_abi,
                st.seccomp, st.rlimits, st.no_new_privs);
    }

    switch (mode) {
    case WK_GUARD: run_scenarios(rootfd, 1, 1); break;
    case WK_NAIVE: run_scenarios(rootfd, 0, 1); break;
    case WK_SB_NAIVE: run_scenarios(rootfd, 0, 0); break;
    case WK_SB_FULL:
        run_scenarios(rootfd, 1, 1);
        run_writes(rootfd);
        break;
    case WK_PROBE: run_probes(rootfd); break;
    case WK_FSIZE: run_fsize(rootfd); break;
    case WK_TOCTOU_NAIVE: run_toctou(rootfd, syncfd, 0, 0); break;
    case WK_TOCTOU_SB: run_toctou(rootfd, syncfd, 0, 1); break;
    case WK_BENCH_RAW:
    case WK_BENCH_GUARD:
    case WK_BENCH_SB: bench_loop(mode, rootfd, iters); break;
    default: break;
    }

    out_flush();
    return 0;
}
