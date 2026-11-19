CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra
CPPFLAGS ?=

SRCS = src/pathguard.c src/pg_worker.c src/pg_policy.c src/pg_sandbox.c \
       src/pg_cases.c
HDRS = src/pg_policy.h src/pg_open.h src/pg_sandbox.h src/pg_worker.h \
       src/pg_cases.h

all: pathguard

pathguard: $(SRCS) $(HDRS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SRCS) -o $@

test: pathguard
	./pathguard

bench: pathguard
	./pathguard --bench 20000

clean:
	rm -f pathguard

.PHONY: all test bench clean
