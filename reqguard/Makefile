CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

all: reqguard

reqguard: src/reqguard.c
	$(CC) $(CFLAGS) $< -o $@ -lcrypto

test: reqguard
	./reqguard
	python3 -I tests/crosscheck.py

fuzz: reqguard
	$(CC) $(CFLAGS) -g -O1 -fsanitize=address,undefined src/reqguard.c -o reqguard-san -lcrypto
	REQGUARD_BIN=./reqguard-san python3 -I tests/fuzz_crosscheck.py

clean:
	rm -f reqguard reqguard-san
