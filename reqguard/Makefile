CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

all: reqguard

reqguard: src/reqguard.c
	$(CC) $(CFLAGS) $< -o $@ -lcrypto

test: reqguard
	./reqguard

reqguard-diff: src/reqguard.c
	$(CC) $(CFLAGS) -DREQGUARD_DIFF $< -o $@ -lcrypto

diff: reqguard-diff
	python3 -I diff/difftest.py

clean:
	rm -f reqguard reqguard-diff
