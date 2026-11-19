CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

SRCS = src/reqguard.c src/hpack.c

all: reqguard

reqguard: $(SRCS) src/hpack.h src/hpack_tables.h
	$(CC) $(CFLAGS) $(SRCS) -o $@

test: reqguard
	./reqguard
	python3 -I tools/hpack_crosscheck.py

# Differential + sanitizer fuzz of the HPACK decoder against the
# independent Python reference in tools/ref_hpack.py.
fuzz: reqguard-san
	python3 -I tools/hpack_fuzz.py

reqguard-san: $(SRCS) src/hpack.h src/hpack_tables.h
	$(CC) $(CFLAGS) -g -O1 -fsanitize=address,undefined $(SRCS) -o $@

# Throughput of 10,000 streams over one connection; also run by `make test`.
bench: reqguard
	./reqguard bench 10000

clean:
	rm -f reqguard reqguard-san

.PHONY: all test fuzz bench clean
