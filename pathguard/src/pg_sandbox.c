#define _GNU_SOURCE
#include "pg_sandbox.h"

#include "pg_open.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <linux/securebits.h>

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (UINT64_C(1) << 15)
#endif

#if defined(__x86_64__)
#define PG_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define PG_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "pg_sandbox: seccomp allowlist is written for x86_64 or aarch64"
#endif

/* Syscalls the confined worker needs.  Glibc may add more (rt_sigprocmask
   inside printf, futex inside stdio locks); those return EPERM, so the
   worker must use raw write(2) for output. */
#define PG_ALLOWED_SYSCALLS(X)                                            \
    X(SYS_read);                                                          \
    X(SYS_write);                                                         \
    X(SYS_close);                                                         \
    X(SYS_lseek);                                                         \
    X(SYS_fstat);                                                         \
    X(SYS_openat2);                                                       \
    X(SYS_clock_gettime);                                                 \
    X(SYS_exit);                                                          \
    X(SYS_exit_group);                                                    \
    X(SYS_rt_sigreturn);

static int seccomp_active;

static int write_str(const char* path, const char* s) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t n = strlen(s);
    ssize_t w = write(fd, s, n);
    close(fd);
    return w == (ssize_t)n ? 0 : -1;
}

int pg_sandbox_cap_count(void) {
    struct __user_cap_header_struct h;
    struct __user_cap_data_struct d[2];
    memset(&h, 0, sizeof h);
    memset(d, 0, sizeof d);
    h.version = _LINUX_CAPABILITY_VERSION_3;
    h.pid = 0;
    if (syscall(SYS_capget, &h, d) < 0) return -1;
    int n = 0;
    for (int i = 0; i < 2; i++)
        for (int b = 0; b < 32; b++)
            if (d[i].effective & (uint32_t)(1u << b)) n++;
    return n;
}

int pg_sandbox_userns(PgSandboxState* st) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    char buf[64];

    if (unshare(CLONE_NEWUSER) < 0) return 0; /* not fatal; caps still go */
    st->user_ns = 1;

    /* Deny setgroups before writing gid_map (required for unprivileged
       gid mapping).  A fresh namespace may not expose the file on some
       kernels; only failure to *map* is fatal. */
    (void)write_str("/proc/self/setgroups", "deny");
    snprintf(buf, sizeof buf, "0 %u 1\n", (unsigned)uid);
    if (write_str("/proc/self/uid_map", buf) < 0) return -1;
    snprintf(buf, sizeof buf, "0 %u 1\n", (unsigned)gid);
    if (write_str("/proc/self/gid_map", buf) < 0) return -1;
    return 0;
}

void pg_sandbox_drop_caps(PgSandboxState* st) {
    /* Bounding set first: nothing regained by exec can survive it. */
    for (int c = CAP_LAST_CAP; c >= 0; c--)
        (void)prctl(PR_CAPBSET_DROP, c, 0, 0, 0);
    (void)prctl(PR_SET_SECUREBITS,
                SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP |
                    SECBIT_NO_SETUID_FIXUP_LOCKED |
                    SECBIT_NO_CAP_AMBIENT_RAISE |
                    SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED,
                0, 0, 0);

    struct __user_cap_header_struct h;
    struct __user_cap_data_struct d[2];
    memset(&h, 0, sizeof h);
    memset(d, 0, sizeof d);
    h.version = _LINUX_CAPABILITY_VERSION_3;
    h.pid = 0;
    (void)syscall(SYS_capset, &h, d);
    /* Query before seccomp goes in: capget is not on the worker's
       allowlist, so after this call the count is no longer observable
       from inside. */
    st->caps_dropped = pg_sandbox_cap_count() == 0;
    st->cap_effective = st->caps_dropped ? 0 : pg_sandbox_cap_count();
}

int pg_sandbox_enter(PgSandboxState* st) {
    memset(st, 0, sizeof *st);
    if (pg_sandbox_userns(st) < 0) return -1;
    pg_sandbox_drop_caps(st);
    return 0;
}

int pg_sandbox_landlock_abi(void) {
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
                       LANDLOCK_CREATE_RULESET_VERSION);
    return abi > 0 ? (int)abi : 0;
}

/* Only ask the kernel to handle rights it knows; unknown bits make
   create_ruleset fail with EINVAL instead of being ignored. */
static uint64_t landlock_fs_handled(int abi) {
    uint64_t m = (UINT64_C(1) << 13) - 1; /* ABI 1: EXECUTE .. MAKE_SYM */
    if (abi >= 2) m |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) m |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) m |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    return m;
}

static int landlock_restrict(int root_fd, int abi, int want_write,
                             const char* prefix) {
    struct landlock_ruleset_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.handled_access_fs = landlock_fs_handled(abi);
    /* Network is handled by seccomp already; asking Landlock for it as
       well would break on ABIs < 4. */
    int rs = (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
    if (rs < 0) return -1;
    struct landlock_path_beneath_attr pb;
    memset(&pb, 0, sizeof pb);
    pb.allowed_access =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    pb.parent_fd = root_fd;
    int r = (int)syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH,
                         &pb, 0);
    if (r < 0) {
        close(rs);
        return -1;
    }

    if (want_write && prefix) {
        int wfd = (int)pg_openat2(root_fd, prefix,
                                  O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (wfd >= 0) {
            struct landlock_path_beneath_attr wp;
            uint64_t allowed = LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_READ_DIR |
                               LANDLOCK_ACCESS_FS_WRITE_FILE |
                               LANDLOCK_ACCESS_FS_MAKE_REG |
                               LANDLOCK_ACCESS_FS_REMOVE_FILE |
                               LANDLOCK_ACCESS_FS_MAKE_DIR;
            if (abi >= 3) allowed |= LANDLOCK_ACCESS_FS_TRUNCATE;
            memset(&wp, 0, sizeof wp);
            wp.allowed_access = allowed;
            wp.parent_fd = wfd;
            (void)syscall(SYS_landlock_add_rule, rs,
                          LANDLOCK_RULE_PATH_BENEATH, &wp, 0);
            close(wfd);
        }
    }

    r = (int)syscall(SYS_landlock_restrict_self, rs, 0);
    close(rs);
    return r;
}

static int apply_rlimits(const PgLimits* l) {
    struct rlimit r;
    int ok = 1;
    r.rlim_cur = r.rlim_max = (rlim_t)l->max_open_files;
    ok &= setrlimit(RLIMIT_NOFILE, &r) == 0;
    r.rlim_cur = r.rlim_max = (rlim_t)l->max_file_size;
    ok &= setrlimit(RLIMIT_FSIZE, &r) == 0;
    r.rlim_cur = r.rlim_max = (rlim_t)l->max_cpu_seconds;
    ok &= setrlimit(RLIMIT_CPU, &r) == 0;
    r.rlim_cur = r.rlim_max = (rlim_t)l->max_processes;
    ok &= setrlimit(RLIMIT_NPROC, &r) == 0;
    r.rlim_cur = r.rlim_max = (rlim_t)l->max_addr_space_mb * 1024 * 1024;
    ok &= setrlimit(RLIMIT_AS, &r) == 0;
    return ok;
}

/* Default action is EPERM, not KILL: a blocked syscall makes the worker
   fail the operation it was attempting while the process stays alive to
   report the denial.  Architecture mismatch and the x32 ABI bit are the
   exception: their syscall numbers are not comparable, so a filter hit
   there means the ABI contract is broken and the process is killed. */
static int install_seccomp(void) {
    struct sock_filter filt[64];
    size_t n = 0;

    filt[n++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                             PG_AUDIT_ARCH, 1, 0);
    filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                             SECCOMP_RET_KILL_PROCESS);
    filt[n++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
#if defined(__x86_64__)
    /* x32 syscalls share the table but not the calling convention. */
    filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                                             0x40000000u, 0, 1);
    filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                             SECCOMP_RET_KILL_PROCESS);
#endif

#define PG_ALLOW(nr)                                                       \
    do {                                                                   \
        filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, \
                                                 (nr), 0, 1);              \
        filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,          \
                                                 SECCOMP_RET_ALLOW);       \
    } while (0)
    PG_ALLOWED_SYSCALLS(PG_ALLOW);
#undef PG_ALLOW

    filt[n++] = (struct sock_filter)BPF_STMT(        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));

    struct sock_fprog prog;
    prog.len = (unsigned short)n;
    prog.filter = filt;
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) return -1;
    seccomp_active = 1;
    return 0;
}

int pg_sandbox_lock(PgSandboxState* st, int root_fd, const PgLimits* lim,
                    unsigned flags, int want_write,
                    const char* writable_prefix) {
    int ok = 1;

    /* Required by Landlock and by unprivileged seccomp, and it keeps
       setuid/exec from shedding the sandbox.  It must be set before
       landlock_restrict_self: that call needs no_new_privs or
       CAP_SYS_ADMIN, and the capability was dropped on purpose. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;
    st->no_new_privs = 1;

    if (flags & PG_SB_LANDLOCK) {
        int abi = pg_sandbox_landlock_abi();
        st->landlock_abi = abi;
        if (abi == 0) {
            ok = 0;
        } else if (landlock_restrict(root_fd, abi, want_write,
                                     writable_prefix) != 0) {
            ok = 0;
        }
    }
    if (flags & PG_SB_RLIMIT) st->rlimits = apply_rlimits(lim) ? 1 : 0;
    if (flags & PG_SB_SECCOMP) st->seccomp = install_seccomp() == 0 ? 1 : 0;

    return ok ? 0 : -1;
}

int pg_sandbox_seccomp_active(void) { return seccomp_active; }
