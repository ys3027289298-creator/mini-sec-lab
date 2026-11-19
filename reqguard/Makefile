CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

all: reqguard

reqguard: src/reqguard.c
	$(CC) $(CFLAGS) $< -o $@

test: reqguard
	./reqguard

clean:
	rm -f reqguard
