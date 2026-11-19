
/* pathguard: filesystem path policy for untrusted relative names.

   Two-stage validation:
     stage 1 (lexical): percent-decode + normalize; reject traversal,
       absolute paths, control bytes, over-long components, dotfiles.
     stage 2 (filesystem): resolve the normalized path segment by
       segment with openat(2) relative to the parent directory fd and
       O_NOFOLLOW; reject symlinks, hard links and non-regular targets;
       allow a non-existent tail in create mode.

   Zero TOCTOU: check and use are the same kernel object.  Each segment
   is resolved exactly once by the kernel, every metadata decision is
   fstat() on the fd the kernel just returned, and the caller receives
   the validated fd itself, never a path string to re-open later.
   See README.md for the full design note. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define PATH_MAX_COMP 64
#define PATH_MAX_DEPTH 8

typedef enum {
    PG_OK = 0,
    PG_EMPTY,
    PG_ABSOLUTE,
    PG_TRAVERSAL,
    PG_CONTROL,
    PG_TOO_LONG,
    PG_TOO_DEEP,
    PG_ENCODED,
    PG_DOTFILE,
    PG_BACKSLASH,
    /* stage 2: filesystem outcomes */
    PG_NOTFOUND,   /* a segment does not exist (existence, not policy) */
    PG_SYMLINK,    /* denied: a segment is a symbolic link */
    PG_HARDLINK,   /* denied: hard-linked file / anomalous dir link count */
    PG_NOTDIR,     /* denied: intermediate segment is not a directory */
    PG_NOTREG,     /* denied: final target is not a regular file */
    PG_EXISTS,     /* denied: create mode and final segment exists */
    PG_PERM,       /* denied: kernel permission check */
    PG_IO          /* any other errno */
} PgErr;

static const char* pg_name(PgErr e) {
    switch (e) {
    case PG_OK: return "ok";
    case PG_EMPTY: return "empty";
    case PG_ABSOLUTE: return "absolute";
    case PG_TRAVERSAL: return "traversal";
    case PG_CONTROL: return "control";
    case PG_TOO_LONG: return "too_long";
    case PG_TOO_DEEP: return "too_deep";
    case PG_ENCODED: return "encoded";
    case PG_DOTFILE: return "dotfile";
    case PG_BACKSLASH: return "backslash";
    case PG_NOTFOUND: return "notfound";
    case PG_SYMLINK: return "symlink";
    case PG_HARDLINK: return "hardlink";
    case PG_NOTDIR: return "notdir";
    case PG_NOTREG: return "notreg";
    case PG_EXISTS: return "exists";
    case PG_PERM: return "perm";
    case PG_IO: return "io";
    }
    return "?";
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* decode %XX in place; return 0 on malformed */
static int decode_percent(const char* in, char* out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; in[i]; i++) {
        if (o + 1 >= cap) return 0;
        if (in[i] == '%') {
            int h = hexval(in[i + 1]), l = h >= 0 ? hexval(in[i + 2]) : -1;
            if (h < 0 || l < 0) return 0;
            out[o++] = (char)((h << 4) | l);
            i += 2;
        } else {
            out[o++] = in[i];
        }
    }
    out[o] = 0;
    return 1;
}

/* stage 1: lexical validation + normalization.
   On PG_OK, out holds the normalized relative path: percent-decoded,
   no empty, "." or ".." segments, no leading slash.  This stage only
   ever rejects; it never proves anything about the filesystem. */
static PgErr pg_normalize(const char* raw, char* out, size_t cap) {
    if (!raw || !*raw) return PG_EMPTY;
    if (raw[0] == '/') return PG_ABSOLUTE;
    if (strchr(raw, '\\')) return PG_BACKSLASH;

    for (const char* p = raw; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7f) return PG_CONTROL;
    }

    if (!decode_percent(raw, out, cap)) return PG_ENCODED;
    for (const char* p = out; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7f) return PG_CONTROL;
    }
    if (out[0] == '/') return PG_ABSOLUTE;

    int depth = 0;
    const char* seg = out;
    while (*seg) {
        const char* slash = strchr(seg, '/');
        size_t n = slash ? (size_t)(slash - seg) : strlen(seg);
        if (n == 0) return PG_EMPTY;
        if (n >= PATH_MAX_COMP) return PG_TOO_LONG;
        if (n == 1 && seg[0] == '.') return PG_DOTFILE;
        if (n == 2 && seg[0] == '.' && seg[1] == '.') return PG_TRAVERSAL;
        depth++;
        if (depth > PATH_MAX_DEPTH) return PG_TOO_DEEP;
        if (!slash) break;
        seg = slash + 1;
    }
    return PG_OK;
}

static PgErr check_rel(const char* raw) {
    char norm[512];
    return pg_normalize(raw, norm, sizeof(norm));
}

static PgErr map_errno(int e) {
    switch (e) {
    case ENOENT: return PG_NOTFOUND;
    case ELOOP: return PG_SYMLINK;
    case ENOTDIR: return PG_NOTDIR;
    case EEXIST: return PG_EXISTS;
    case EACCES: case EPERM: return PG_PERM;
    }
    return PG_IO;
}

#define PG_OPEN_EXISTING 0
#define PG_OPEN_CREATE   1

/* stage 2: resolve norm (already normalized) under rootfd.
   On PG_OK, *outfd holds the open, validated file; the caller uses
   that fd, never the path.  Every check below is fused with the open
   it guards, so there is no check-then-use gap to race. */
static PgErr pg_walk(int rootfd, const char* norm, int mode, int* outfd) {
    int dirfd = openat(rootfd, ".", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) return PG_IO;

    const char* seg = norm;
    for (;;) {
        const char* slash = strchr(seg, '/');
        size_t n = slash ? (size_t)(slash - seg) : strlen(seg);
        char name[PATH_MAX_COMP];
        memcpy(name, seg, n);
        name[n] = 0;

        if (slash) {
            /* intermediate segment: must resolve to a real directory.
               O_PATH|O_NOFOLLOW opens a symlink itself instead of
               failing, so the fstat below classifies exactly what the
               kernel resolved: symlink, non-directory, or real dir.
               (O_DIRECTORY|O_NOFOLLOW would conflate symlinks into
               ENOTDIR.)  Lookups below an O_PATH dirfd still enforce
               search permission on every component. */
            int flags = O_PATH | O_NOFOLLOW | O_CLOEXEC;
            int next = openat(dirfd, name, flags);
            if (next < 0 && errno == ENOENT && mode == PG_OPEN_CREATE) {
                /* new tail segment: create it, then re-open.  Still no
                   check-then-act: mkdirat is atomic, and the re-open
                   re-validates whatever the name points to now. */
                if (mkdirat(dirfd, name, 0700) < 0 && errno != EEXIST) {
                    PgErr e = map_errno(errno);
                    close(dirfd);
                    return e;
                }
                next = openat(dirfd, name, flags);
            }
            if (next < 0) {
                PgErr e = map_errno(errno);
                close(dirfd);
                return e;
            }
            struct stat st;
            if (fstat(next, &st) < 0) {
                close(next);
                close(dirfd);
                return PG_IO;
            }
            if (S_ISLNK(st.st_mode)) {
                close(next);
                close(dirfd);
                return PG_SYMLINK;
            }
            if (!S_ISDIR(st.st_mode)) {
                close(next);
                close(dirfd);
                return PG_NOTDIR;
            }
            /* mainstream filesystems forbid directory hard links, so a
               link count below 2 means something foreign planted it */
            if (st.st_nlink < 2) {
                close(next);
                close(dirfd);
                return PG_HARDLINK;
            }
            close(dirfd);
            dirfd = next;
            seg = slash + 1;
        } else {
            int flags = O_CLOEXEC | O_NOFOLLOW;
            if (mode == PG_OPEN_CREATE)
                flags |= O_WRONLY | O_CREAT | O_EXCL;
            else
                flags |= O_RDONLY;
            int f = openat(dirfd, name, flags, 0600);
            if (f < 0) {
                PgErr e = map_errno(errno);
                close(dirfd);
                return e;
            }
            struct stat st;
            if (fstat(f, &st) < 0) {
                close(f);
                close(dirfd);
                return PG_IO;
            }
            if (!S_ISREG(st.st_mode)) {
                close(f);
                close(dirfd);
                return PG_NOTREG;
            }
            if (st.st_nlink != 1) {
                /* a second name for this inode exists somewhere:
                   it would alias content we never vetted */
                close(f);
                close(dirfd);
                return PG_HARDLINK;
            }
            close(dirfd);
            *outfd = f;
            return PG_OK;
        }
    }
}

/* full two-stage entry point: normalize, then resolve on disk */
static PgErr pg_open(int rootfd, const char* raw, int mode, int* outfd) {
    char norm[512];
    PgErr e = pg_normalize(raw, norm, sizeof(norm));
    if (e != PG_OK) return e;
    return pg_walk(rootfd, norm, mode, outfd);
}

static int failures = 0;
static void expect(const char* name, PgErr got, PgErr want) {
    int ok = got == want;
    printf("%s=%d\n", name, ok ? 1 : 0);
    if (!ok) {
        printf("  got=%s want=%s\n", pg_name(got), pg_name(want));
        failures++;
    }
}
static void check(const char* name, int ok) {
    printf("%s=%d\n", name, ok ? 1 : 0);
    if (!ok) failures++;
}

static void lexical_tests(void) {
    expect("plain_ok", check_rel("a/b/c.txt"), PG_OK);
    expect("single_ok", check_rel("file.txt"), PG_OK);
    expect("empty_rejected", check_rel(""), PG_EMPTY);
    expect("absolute_rejected", check_rel("/etc/passwd"), PG_ABSOLUTE);
    expect("traversal_rejected", check_rel("../x"), PG_TRAVERSAL);
    expect("inner_traversal_rejected", check_rel("a/../../b"), PG_TRAVERSAL);
    expect("encoded_rejected", check_rel("%2e%2e/x"), PG_TRAVERSAL);
    expect("encoded_slash_rejected", check_rel("a%2f..%2fb"), PG_TRAVERSAL);
    expect("dotfile_rejected", check_rel("a/./b"), PG_DOTFILE);
    expect("backslash_rejected", check_rel("a\\b"), PG_BACKSLASH);
    expect("control_rejected", check_rel("a\x01" "b"), PG_CONTROL);
    expect("too_deep_rejected", check_rel("a/b/c/d/e/f/g/h/i"), PG_TOO_DEEP);
    expect("bad_percent", check_rel("a%zz"), PG_ENCODED);

    char longseg[80];
    memset(longseg, 'a', sizeof(longseg));
    longseg[79] = 0;
    expect("too_long_rejected", check_rel(longseg), PG_TOO_LONG);
}

static void write_file(const char* path, const char* data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        ssize_t w = write(fd, data, strlen(data));
        (void)w;
        close(fd);
    }
}

static void fs_tests(void) {
    char dir[] = "/tmp/pathguard.XXXXXX";
    if (!mkdtemp(dir)) {
        check("fs_setup", 0);
        return;
    }
    char p[512], q[512];

    snprintf(p, sizeof(p), "%s/real", dir);
    mkdir(p, 0700);
    snprintf(p, sizeof(p), "%s/real/file.txt", dir);
    write_file(p, "hello");
    snprintf(p, sizeof(p), "%s/real/secret.txt", dir);
    write_file(p, "s");
    snprintf(q, sizeof(q), "%s/real/alias.txt", dir);
    if (link(p, q) < 0) perror("link");          /* hard link to secret.txt */
    snprintf(p, sizeof(p), "%s/link", dir);
    if (symlink("real", p) < 0) perror("symlink"); /* symlinked directory */
    snprintf(p, sizeof(p), "%s/linkfile.txt", dir);
    if (symlink("real/file.txt", p) < 0) perror("symlink"); /* symlinked leaf */

    int root = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int fd = -1;

    expect("fs_existing_ok", pg_open(root, "real/file.txt", PG_OPEN_EXISTING, &fd), PG_OK);
    if (fd >= 0) {
        char buf[8] = {0};
        check("fs_fd_is_usable", read(fd, buf, 5) == 5 && memcmp(buf, "hello", 5) == 0);
        close(fd);
        fd = -1;
    }
    expect("fs_symlink_dir_rejected", pg_open(root, "link/file.txt", PG_OPEN_EXISTING, &fd), PG_SYMLINK);
    expect("fs_symlink_final_rejected", pg_open(root, "linkfile.txt", PG_OPEN_EXISTING, &fd), PG_SYMLINK);
    expect("fs_hardlink_rejected", pg_open(root, "real/alias.txt", PG_OPEN_EXISTING, &fd), PG_HARDLINK);
    expect("fs_missing_is_notfound", pg_open(root, "real/missing.txt", PG_OPEN_EXISTING, &fd), PG_NOTFOUND);
    expect("fs_notdir_rejected", pg_open(root, "real/file.txt/x", PG_OPEN_EXISTING, &fd), PG_NOTDIR);
    expect("fs_create_leaf_ok", pg_open(root, "real/new.txt", PG_OPEN_CREATE, &fd), PG_OK);
    if (fd >= 0) { close(fd); fd = -1; }
    expect("fs_create_nested_ok", pg_open(root, "d1/d2/f.txt", PG_OPEN_CREATE, &fd), PG_OK);
    if (fd >= 0) { close(fd); fd = -1; }
    expect("fs_create_existing_rejected", pg_open(root, "real/file.txt", PG_OPEN_CREATE, &fd), PG_EXISTS);
    expect("fs_lexical_runs_first", pg_open(root, "../escape", PG_OPEN_EXISTING, &fd), PG_TRAVERSAL);

    close(root);
    snprintf(p, sizeof(p), "%s/real/file.txt", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/real/secret.txt", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/real/alias.txt", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/real/new.txt", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/linkfile.txt", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/link", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/d1/d2/f.txt", dir); unlink(p);
    snprintf(p, sizeof(p), "%s/d1/d2", dir); rmdir(p);
    snprintf(p, sizeof(p), "%s/d1", dir); rmdir(p);
    snprintf(p, sizeof(p), "%s/real", dir); rmdir(p);
    rmdir(dir);
}

int main(void) {
    lexical_tests();
    fs_tests();
    printf("all_ok=%d\n", failures == 0);
    return failures == 0 ? 0 : 1;
}
