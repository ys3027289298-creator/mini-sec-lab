/* pg_cases: fixtures shared by the driver (which builds the tree) and the
   worker (which attacks it). */
#ifndef PG_CASES_H
#define PG_CASES_H

#include "pg_policy.h"

/* Byte string planted outside the granted tree.  Any read of it is an
   escape and fails the test. */
#define PG_SECRET "outside-secret"

/* Names that must stay readable inside the granted tree. */
#define PG_VALID_COUNT 4
extern const char* const PG_VALID_NAMES[PG_VALID_COUNT];
extern const char* const PG_VALID_BODY[PG_VALID_COUNT];

/* Every name below either leaves the granted tree or relies on a symlink.
   All of them must be refused once validation and open are confined. */
#define PG_ESCAPE_COUNT 12
extern const char* const PG_ESCAPE_NAMES[PG_ESCAPE_COUNT];

/* Lexically invalid names: these never reach the filesystem. */
typedef struct {
    const char* name;
    PgErr err;
} PgLexCase;

#define PG_LEX_COUNT 12
extern const PgLexCase PG_LEX_CASES[PG_LEX_COUNT];

/* Positive policy cases. */
#define PG_OK_COUNT 3
extern const char* const PG_OK_NAMES[PG_OK_COUNT];

/* Check/use race fixture: the driver swaps data/sub for data/sub.evil, a
   symlink to outside/, between the worker's validation and its open. */
#define PG_TOCTOU_NAME "data/sub/c.txt"
#define PG_TOCTOU_EVIL "data/sub.evil"
#define PG_TOCTOU_MOVED "data/sub.real"

#endif
