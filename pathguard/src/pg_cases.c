#include "pg_cases.h"

const char* const PG_VALID_NAMES[PG_VALID_COUNT] = {
    "data/a.txt",
    "data/b.txt",
    "data/sub/c.txt",
    "scratch/note.txt",
};

const char* const PG_VALID_BODY[PG_VALID_COUNT] = {
    "inside-a",
    "inside-b",
    "inside-c",
    "note",
};

const char* const PG_ESCAPE_NAMES[PG_ESCAPE_COUNT] = {
    "link_abs",                      /* -> /etc/passwd */
    "link_rel",                      /* -> ../outside/secret.txt */
    "link_dir/secret.txt",           /* symlinked dir -> ../outside */
    "link_loop",                     /* self-referential symlink */
    "link_chain",                    /* symlink -> symlink -> outside */
    "../outside/secret.txt",         /* plain traversal */
    "/etc/passwd",                   /* absolute */
    "%2e%2e/outside/secret.txt",     /* encoded traversal */
    "data/../../outside/secret.txt", /* inner traversal */
    "/proc/self/root/etc/passwd",    /* procfs root */
    "..%2foutside/secret.txt",       /* encoded slash traversal */
    "link_dir/../../../etc/passwd",  /* symlinked dir + traversal */
};

const PgLexCase PG_LEX_CASES[PG_LEX_COUNT] = {
    {"", PG_EMPTY},
    {"/etc/passwd", PG_ABSOLUTE},
    {"../x", PG_TRAVERSAL},
    {"a/../../b", PG_TRAVERSAL},
    {"%2e%2e/x", PG_TRAVERSAL},
    {"a%2f..%2fb", PG_TRAVERSAL},
    {"a/./b", PG_DOTFILE},
    {"a\\b", PG_BACKSLASH},
    {"a\x01" "b", PG_CONTROL},
    {"a%zz", PG_ENCODED},
    {"a%00b", PG_CONTROL},   /* encoded NUL would truncate the opened name */
    {"a//b", PG_EMPTY},      /* empty component */
};

const char* const PG_OK_NAMES[PG_OK_COUNT] = {
    "a/b/c.txt",
    "file.txt",
    "scratch/note%2etxt",
};
