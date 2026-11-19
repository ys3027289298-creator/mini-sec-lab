CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

all: pathguard

pathguard: src/pathguard.c
	$(CC) $(CFLAGS) $< -o $@ 

test: pathguard
	./pathguard

clean:
	rm -f pathguard
