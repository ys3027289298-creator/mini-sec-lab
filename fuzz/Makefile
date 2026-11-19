# fuzz/: mutation fuzzing drivers for the three mini-sec-lab components.
# The engine is libc/POSIX-only; sanitizers ship with the compiler, so
# the driver introduces no new library dependency.
CC ?= gcc
SANITIZE = -fsanitize=address,undefined
CFLAGS ?= -O1 -g -std=c11 -Wall -Wextra -Wno-unused-function
CPPFLAGS =

LDLIBS_tokenauth = -lcrypto

TARGETS = fuzz-reqguard fuzz-pathguard fuzz-tokenauth fuzz-selftest
CORPORA = corpus/reqguard corpus/pathguard corpus/tokenauth corpus/selftest

.PHONY: all seeds clean distclean test
all: $(TARGETS)

fuzz-%: harness_%.c engine.c engine.h
	$(CC) $(CFLAGS) $(SANITIZE) $(CPPFLAGS) harness_$*.c engine.c -o $@ $(LDLIBS_$*)

# Regenerate seed corpora from each harness's own canonical seeds.
seeds: $(TARGETS)
	./fuzz-reqguard seed | ./fuzz-reqguard unseed --out corpus/reqguard
	./fuzz-pathguard seed | ./fuzz-pathguard unseed --out corpus/pathguard
	./fuzz-tokenauth seed | ./fuzz-tokenauth unseed --out corpus/tokenauth
	./fuzz-selftest seed | ./fuzz-selftest unseed --out corpus/selftest

# Quick smoke run (small iteration count); use run_fuzz.sh for the full
# 100k campaign.
test: all seeds
	./run_fuzz.sh smoke

clean:
	rm -f $(TARGETS)

distclean: clean
	rm -rf corpus out
