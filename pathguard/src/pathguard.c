/* pathguard: driver and self-test.

   The driver builds a fixture tree, then forks one worker per scenario.
   Workers confine themselves (pg_sandbox) and only then validate and
   open, so the "check" and the "use" share a single sandboxed process.

   Usage:
     ./pathguard              run the self-test
     ./pathguard --bench [N]  run the performance comparison (default N
                              iterations per measurement, 5 repetitions)
*/
#define _GNU_SOURCE
#include "pg_cases.h"
#include "pg_open.h"
#include "pg_policy.h"
#include "pg_sandbox.h"
#include "pg_worker.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>

static int failures;

static void check(const char* name, int ok) {
    printf("check %s=%d\n", name, ok ? 1 : 0);
    if (!ok) failures++;
}

/* ---------- fixture ---------- */

/* The granted tree is <tmp>/jail; everything the attacks try to reach
   lives in <tmp>/outside, a sibling.  Keeping the secret outside the
   Landlock grant is what makes a leaked byte meaningful. */
static char base[256]; /* <tmp> */
static char root[256]; /* <tmp>/jail: what the worker is confined to */

static int mkfile(const char* rel, const char* body) {
    char p[512];
    snprintf(p, sizeof p, "%s/%s", base, rel);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    size_t n = strlen(body);
    ssize_t w = write(fd, body, n);
    close(fd);
    return w == (ssize_t)n ? 0 : -1;
}

static int mkdir_p(const char* rel) {
    char p[512];
    snprintf(p, sizeof p, "%s/%s", base, rel);
    return mkdir(p, 0700);
}

static int symlink_rel(const char* target, const char* rel) {
    char p[512];
    snprintf(p, sizeof p, "%s/%s", base, rel);
    return symlink(target, p);
}

static int build_fixture(void) {
    char tmpl[] = "/tmp/pathguard.XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) return -1;
    snprintf(base, sizeof base, "%s", dir);
    snprintf(root, sizeof root, "%s/jail", dir);

    if (mkdir_p("jail") || mkdir_p("jail/data") || mkdir_p("jail/data/sub") ||
        mkdir_p("jail/scratch") || mkdir_p("outside"))
        return -1;
    if (mkfile("jail/data/a.txt", PG_VALID_BODY[0]) ||
        mkfile("jail/data/b.txt", PG_VALID_BODY[1]) ||
        mkfile("jail/data/sub/c.txt", PG_VALID_BODY[2]) ||
        mkfile("jail/scratch/note.txt", PG_VALID_BODY[3]))
        return -1;
    if (mkfile("outside/secret.txt", PG_SECRET) ||
        mkfile("outside/c.txt", PG_SECRET))
        return -1;

    /* Escape fixtures.  Each name in PG_ESCAPE_NAMES must be refused. */
    if (symlink_rel("/etc/passwd", "jail/link_abs") ||
        symlink_rel("../outside/secret.txt", "jail/link_rel") ||
        symlink_rel("../outside", "jail/link_dir") ||
        symlink_rel("link_loop", "jail/link_loop") ||
        symlink_rel("link_rel", "jail/link_chain") ||
        symlink_rel("../../outside", "jail/data/sub.evil"))
        return -1;
    return 0;
}

static void scrub_fixture(void) {
    char cmd[512];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", base);
    if (system(cmd) != 0) { /* best effort */ }
}

/* ---------- worker plumbing ---------- */

static int run_worker_args(const char* mode, int iters, int syncfd, char* out,
                           size_t cap, int* status) {
    int p[2];
    if (pipe(p) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(p[0]);
        close(p[1]);
        return -1;
    }
    if (pid == 0) {
        close(p[0]);
        char ofd[16], it[16], sf[16];
        snprintf(ofd, sizeof ofd, "%d", p[1]);
        snprintf(it, sizeof it, "%d", iters);
        snprintf(sf, sizeof sf, "%d", syncfd >= 0 ? syncfd : p[1]);
        char* av[] = {"worker", (char*)mode, root, ofd, it, sf, NULL};
        _exit(pg_worker_main(syncfd >= 0 ? 6 : 5, av));
    }
    close(p[1]);
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = read(p[0], out + n, cap - 1 - n);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        n += (size_t)r;
    }
    out[n] = 0;
    close(p[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    *status = st;
    if (getenv("PG_TRACE")) {
        fprintf(stderr, "--- worker %s (status %d) ---\n%s", mode, st, out);
    }
    return 0;
}

static int run_worker(const char* mode, int iters, char* out, size_t cap,
                      int* status) {
    return run_worker_args(mode, iters, -1, out, cap, status);
}

static int move_path(const char* from, const char* to) {
    char a[512], b[512];
    snprintf(a, sizeof a, "%s/%s", root, from);
    snprintf(b, sizeof b, "%s/%s", root, to);
    return (int)syscall(SYS_renameat2, AT_FDCWD, a, AT_FDCWD, b, 0);
}

/* Handshake: wait for one token, swap data/sub for the outside symlink
   (or back), send one token.  The worker validates first and opens after,
   so this reproduces the audit finding without any timing luck. */
static int toctou_step(int fd, int to_symlink) {
    char c = 'x';
    if (read(fd, &c, 1) != 1) return -1;
    if (to_symlink) {
        if (move_path("data/sub", PG_TOCTOU_MOVED) < 0) return -1;
        if (move_path(PG_TOCTOU_EVIL, "data/sub") < 0) return -1;
    } else {
        if (move_path("data/sub", PG_TOCTOU_EVIL) < 0) return -1;
        if (move_path(PG_TOCTOU_MOVED, "data/sub") < 0) return -1;
    }
    return write(fd, &c, 1) == 1 ? 0 : -1;
}

static int run_toctou(const char* mode, char* out, size_t cap, int* status) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) return -1;
    int p[2];
    if (pipe(p) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        close(p[0]);
        close(sp[0]);
        char ofd[16], it[16], sf[16];
        snprintf(ofd, sizeof ofd, "%d", p[1]);
        snprintf(it, sizeof it, "%d", 0);
        snprintf(sf, sizeof sf, "%d", sp[1]);
        char* av[] = {"worker", (char*)mode, root, ofd, it, sf, NULL};
        _exit(pg_worker_main(6, av));
    }
    close(p[1]);
    close(sp[1]);

    int rc = toctou_step(sp[0], 1);   /* check done -> swap to symlink */
    if (rc == 0) rc = toctou_step(sp[0], 0); /* open done -> restore */
    close(sp[0]);

    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = read(p[0], out + n, cap - 1 - n);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        n += (size_t)r;
    }
    out[n] = 0;
    close(p[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    *status = st;
    if (getenv("PG_TRACE")) {
        fprintf(stderr, "--- toctou %s (status %d, step rc %d) ---\n%s", mode,
                st, rc, out);
    }
    return rc;
}

static int count_lines(const char* out, const char* needle) {
    int n = 0;
    const char* p = out;
    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += strlen(needle);
    }
    return n;
}

static int line_has(const char* out, const char* needle) {
    return strstr(out, needle) != NULL;
}

/* ---------- self-test ---------- */

static void test_policy(void) {
    char dec[PG_MAX_PATH];
    size_t len = 0;
    char label[64];

    for (int i = 0; i < PG_OK_COUNT; i++) {
        PgErr e = pg_check_name(PG_OK_NAMES[i], dec, sizeof dec, &len);
        snprintf(label, sizeof label, "policy_ok_%d", i);
        check(label, e == PG_OK);
    }
    for (int i = 0; i < PG_LEX_COUNT; i++) {
        PgErr e = pg_check_name(PG_LEX_CASES[i].name, dec, sizeof dec, &len);
        snprintf(label, sizeof label, "policy_%s", pg_err_name(PG_LEX_CASES[i].err));
        check(label, e == PG_LEX_CASES[i].err);
    }
    char longseg[80];
    memset(longseg, 'a', sizeof longseg);
    longseg[79] = 0;
    check("too_long_rejected",
          pg_check_name(longseg, dec, sizeof dec, &len) == PG_TOO_LONG);
    check("too_deep_rejected", pg_check_name("a/b/c/d/e/f/g/h/i", dec,
                                             sizeof dec, &len) == PG_TOO_DEEP);
}

static void test_scenarios(void) {
    static char out[65536];
    int st;

    /* Before: the reported implementation validates, then opens plainly. */
    run_worker("naive", 0, out, sizeof out, &st);
    check("naive_reproduces_leak",
          count_lines(out, "escape ") > 0 &&
              count_lines(out, "secret=1") > 0);

    /* Validation + openat2 resolve flags, no sandbox yet. */
    run_worker("guard", 0, out, sizeof out, &st);
    check("guard_no_leak", count_lines(out, "secret=1") == 0);
    check("guard_valid_readable",
          count_lines(out, "valid ") == PG_VALID_COUNT &&
              count_lines(out, "body=match") == PG_VALID_COUNT);

    /* Sandbox with the naive opener: Landlock alone must hold. */
    run_worker("sb_naive", 0, out, sizeof out, &st);
    check("landlock_blocks_bypass",
          line_has(out, "caps=0") && count_lines(out, "secret=1") == 0);
    check("landlock_denies_outside",
          count_lines(out, "errno=13") > 0);

    /* Full stack, validated opener, plus write policy. */
    run_worker("sb_full", 0, out, sizeof out, &st);
    check("full_sandbox_layers",
          line_has(out, "caps=0") && line_has(out, "seccomp=1 rlimit=1 nnp=1"));
    check("full_no_leak", count_lines(out, "secret=1") == 0);
    check("full_valid_readable",
          count_lines(out, "body=match") == PG_VALID_COUNT);
    check("full_write_in_scratch_ok",
          line_has(out, "write scratch/new.txt open=ok write=ok"));
    check("full_write_elsewhere_denied",
          line_has(out, "write data/new.txt open=deny"));
}

static void test_syscalls(void) {
    static char out[65536];
    int st;
    run_worker("probes", 0, out, sizeof out, &st);

    /* Whitelist misses return EPERM and the worker is still alive to
       report them: these lines could not exist if it had been killed. */
    check("seccomp_socket_eperm", line_has(out, "probe socket=deny errno=1 "));
    check("seccomp_chdir_eperm", line_has(out, "probe chdir=deny errno=1 "));
    check("seccomp_ptrace_eperm", line_has(out, "probe ptrace=deny errno=1 "));
    check("seccomp_fork_eperm", line_has(out, "probe fork=deny errno=1 "));
    check("seccomp_open_legacy_eperm",
          line_has(out, "probe open_legacy=deny errno=1 "));
    check("worker_alive_after_denials",
          line_has(out, "probe nofile=deny") && WIFEXITED(st) &&
              WEXITSTATUS(st) == 0);

    /* Landlock answers filesystem questions that seccomp allows. */
    check("landlock_outside_eacces",
          line_has(out, "probe open_outside=deny errno=13 "));
    /* RLIMIT_NOFILE: EMFILE, not a crash. */
    check("rlimit_nofile_emfile", line_has(out, "probe nofile=deny errno=24 "));
}

static void test_fsize(void) {
    static char out[65536];
    int st;
    run_worker("fsize", 0, out, sizeof out, &st);
    check("rlimit_fsize_sigxfsz",
          WIFSIGNALED(st) && WTERMSIG(st) == SIGXFSZ);
}

static void test_toctou(void) {
    static char out[65536];
    int st;

    run_toctou("toctou_naive", out, sizeof out, &st);
    check("toctou_naive_reproduces_leak",
          line_has(out, "toctou result=1") && line_has(out, "leaks=1"));
    check("toctou_naive_open_succeeded", line_has(out, "denied=0"));

    run_toctou("toctou_sb", out, sizeof out, &st);
    check("toctou_sandbox_no_leak",
          line_has(out, "toctou result=1") && line_has(out, "leaks=0"));
    check("toctou_sandbox_denied", line_has(out, "denied=1"));
}

/* ---------- benchmark ---------- */

static double measure(const char* mode, int iters, int reps) {
    static char out[65536];
    double best = 1e30;
    for (int r = 0; r < reps; r++) {
        int st;
        run_worker(mode, iters, out, sizeof out, &st);
        const char* p = strstr(out, "total_ns=");
        if (!p) return -1;
        unsigned long long ns = strtoull(p + 9, NULL, 10);
        double per = (double)ns / (double)iters;
        if (per < best) best = per;
    }
    return best;
}

static void bench(int iters) {
    char out[65536];
    int st;

    run_worker("setup", 0, out, sizeof out, &st);
    const char* s = strstr(out, "setup ");
    printf("setup %s", s ? s + 6 : "unavailable\n");

    int reps = 5;
    double raw = measure("bench_raw", iters, reps);
    double guard = measure("bench_guard", iters, reps);
    double sb = measure("bench_sb", iters, reps);

    printf("bench iters=%d reps=%d\n", iters, reps);
    printf("bench raw_ns_per_op=%.1f\n", raw);
    printf("bench guard_ns_per_op=%.1f\n", guard);
    printf("bench sandbox_ns_per_op=%.1f\n", sb);
    if (raw > 0) {
        printf("bench validate_overhead_pct=%.1f\n",
               100.0 * (guard - raw) / raw);
        printf("bench sandbox_overhead_pct=%.1f\n", 100.0 * (sb - guard) / guard);
        printf("bench total_overhead_pct=%.1f\n", 100.0 * (sb - raw) / raw);
    }
    printf("bench raw_ops_per_s=%.0f\n", raw > 0 ? 1e9 / raw : 0);
    printf("bench sandbox_ops_per_s=%.0f\n", sb > 0 ? 1e9 / sb : 0);
}

static void report_kernel(void) {
    struct utsname u;
    if (uname(&u) == 0)
        printf("kernel %s %s\n", u.sysname, u.release);
    printf("kernel landlock_abi=%d\n", pg_sandbox_landlock_abi());
#ifdef __x86_64__
    printf("kernel arch=x86_64\n");
#elif defined(__aarch64__)
    printf("kernel arch=aarch64\n");
#endif
}

int main(int argc, char** argv) {
    report_kernel();

    if (argc >= 2 && !strcmp(argv[1], "--bench")) {
        int iters = argc >= 3 ? atoi(argv[2]) : 20000;
        if (iters < 1000) iters = 1000;
        if (build_fixture() < 0) {
            printf("fatal fixture=deny\n");
            return 2;
        }
        bench(iters);
        scrub_fixture();
        return 0;
    }

    if (build_fixture() < 0) {
        printf("fatal fixture=deny\n");
        return 2;
    }

    test_policy();
    test_scenarios();
    test_syscalls();
    test_fsize();
    test_toctou();

    printf("all_ok=%d\n", failures == 0);
    scrub_fixture();
    return failures == 0 ? 0 : 1;
}
