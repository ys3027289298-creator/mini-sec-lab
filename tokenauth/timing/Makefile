CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

.PHONY: all run clean

all: out/timing_harness

out/timing_harness: timing_harness.c
	mkdir -p out
	$(CC) $(CFLAGS) -fno-inline-functions -g $< -o $@ -lcrypto

run:
	./run.sh

clean:
	rm -rf out
