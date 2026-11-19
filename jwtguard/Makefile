CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra
LDLIBS = -lcrypto

all: jwtguard

jwtguard: src/jwtguard.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

test: jwtguard
	python3 -I tests/harness.py

clean:
	rm -f jwtguard
