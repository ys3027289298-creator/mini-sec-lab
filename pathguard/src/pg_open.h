#ifndef PG_OPEN_H
#define PG_OPEN_H

/* openat2(2) is the only opener used on untrusted names.  The resolve
   flags make path resolution itself the security boundary, so there is
   no window between "the name looked fine" and "the kernel resolved the
   name" in which a symlink or mount can change the answer. */

#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/openat2.h>

#define PG_RESOLVE_ALL                                                   \
    (RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |     \
     RESOLVE_NO_XDEV)

/* Raw opener.  resolve=0 reproduces a naive opener and is only used by
   the self-test to prove that Landlock still denies the escape. */
static inline long pg_openat2_raw(int dfd, const char* path, uint64_t flags,
                                  uint64_t resolve) {
    struct open_how how;
    how.flags = flags;
    how.mode = 0;
    how.resolve = resolve;
    return syscall(SYS_openat2, dfd, path, &how, sizeof how);
}

static inline long pg_openat2_at(int dfd, const char* path, uint64_t flags,
                                 uint64_t mode) {
    struct open_how how;
    how.flags = flags;
    how.mode = (flags & (O_CREAT | O_TMPFILE)) ? mode : 0;
    how.resolve = PG_RESOLVE_ALL;
    return syscall(SYS_openat2, dfd, path, &how, sizeof how);
}

static inline long pg_openat2(int dfd, const char* path, uint64_t flags) {
    return pg_openat2_raw(dfd, path, flags, PG_RESOLVE_ALL);
}

#endif
