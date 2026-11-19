/* pg_sandbox: process containment applied after the name is validated.
   Layers, weakest first:
     1. user namespace   - no privilege over host-owned objects
     2. capability drop  - empty bounding/effective sets, locked securebits
     3. Landlock         - deny-by-default filesystem policy for the whole
                           process, so even an opener that skipped the
                           resolve flags stays inside the granted tree
     4. rlimits          - bounded descriptors, file size, CPU, processes
     5. seccomp          - syscall allowlist; anything else returns EPERM
                           and the process keeps running
   Layers 3 and 5 are enforced by the kernel.  A bug in the name check
   therefore degrades to "the sandbox still says no", not to an escape. */
#ifndef PG_SANDBOX_H
#define PG_SANDBOX_H

#define PG_SB_LANDLOCK 1u
#define PG_SB_RLIMIT 2u
#define PG_SB_SECCOMP 4u
#define PG_SB_ALL (PG_SB_LANDLOCK | PG_SB_RLIMIT | PG_SB_SECCOMP)

typedef struct {
    unsigned long max_open_files;
    unsigned long max_file_size;
    unsigned long max_cpu_seconds;
    unsigned long max_processes;
    unsigned long max_addr_space_mb;
} PgLimits;

#define PG_LIMITS_DEFAULT                                                 \
    (PgLimits) {                                                          \
        .max_open_files = 32, .max_file_size = 1UL << 20,                 \
        .max_cpu_seconds = 5, .max_processes = 1,                         \
        .max_addr_space_mb = 256                                          \
    }

typedef struct {
    int user_ns;       /* 1 if a user namespace was entered */
    int caps_dropped;  /* 1 if effective and permitted sets are empty */
    int cap_effective; /* effective capability count after the drop */
    int landlock_abi;  /* 0 if unavailable, else the probed ABI */
    int seccomp;       /* 1 if the syscall allowlist is installed */
    int rlimits;       /* 1 if all ceilings were applied */
    int no_new_privs;  /* 1 if PR_SET_NO_NEW_PRIVS succeeded */
} PgSandboxState;

/* Enter a user namespace and map the caller to uid/gid 0 inside it.
   Returns 0 if no namespace was needed/failed, and -1 only if the
   namespace was entered but could not be mapped (the uid would then be
   unmapped, so the caller must not continue). */
int pg_sandbox_userns(PgSandboxState* st);

/* Clear the capability bounding set, lock securebits and zero the
   permitted/effective/inheritable sets.  Safe to call after userns(). */
void pg_sandbox_drop_caps(PgSandboxState* st);

/* userns() followed by drop_caps(). */
int pg_sandbox_enter(PgSandboxState* st);

/* Remaining capabilities in the effective set, or -1 on error. */
int pg_sandbox_cap_count(void);

/* Highest supported Landlock ABI, or 0 if Landlock is unavailable. */
int pg_sandbox_landlock_abi(void);

/* Confine the process to root_fd.  flags selects PG_SB_* layers.
   want_write grants creation/truncation under writable_prefix only.
   Returns 0 when every requested layer that the kernel supports is
   active; -1 if a requested layer failed to install (fail closed). */
int pg_sandbox_lock(PgSandboxState* st, int root_fd, const PgLimits* lim,
                    unsigned flags, int want_write,
                    const char* writable_prefix);

int pg_sandbox_seccomp_active(void);

#endif
