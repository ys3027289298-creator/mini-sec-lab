/* pg_worker: the confined side of pathguard.

   The driver forks, and the child runs pg_worker_main().  The child
   confines itself first and only then validates, opens and reads.  It
   reports "key value..." lines through outfd with raw write(2), because
   the syscall allowlist blocks the futex and signal helpers stdio would
   reach for. */
#ifndef PG_WORKER_H
#define PG_WORKER_H

#define PG_SCRATCH "scratch"

enum {
    WK_GUARD = 0,   /* validate + openat2 resolve flags, no sandbox */
    WK_NAIVE,       /* decode + plain open, no sandbox: the reported bug */
    WK_SB_NAIVE,    /* sandbox, opener deliberately keeps no resolve flags */
    WK_SB_FULL,     /* sandbox + validated openat2 + writes */
    WK_PROBE,       /* sandboxed syscall and rlimit probes */
    WK_FSIZE,       /* push past RLIMIT_FSIZE (ends in SIGXFSZ) */
    WK_TOCTOU_NAIVE,/* deterministic check/use race, no sandbox */
    WK_TOCTOU_SB,   /* same race while sandboxed */
    WK_SETUP,       /* sandbox setup cost only, no I/O */
    WK_BENCH_RAW,   /* bench: plain openat2, no validation, no sandbox */
    WK_BENCH_GUARD, /* bench: validation + openat2, no sandbox */
    WK_BENCH_SB,    /* bench: full sandbox path */
    WK_MODE_COUNT
};

/* argv: <mode> <root-dir> <outfd> <iters> [syncfd].  syncfd, when given,
   is used by the TOCTOU modes to hand control to the driver between the
   check and the open.  Returns the process exit status; never returns for
   WK_FSIZE when the limit is hit. */
int pg_worker_main(int argc, char** argv);

#endif
