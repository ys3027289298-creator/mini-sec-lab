CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

OBJS = build/tlsrecord.o build/tlshttp.o build/main.o

all: tlsrecord

build:
	mkdir -p build

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -Isrc -c $< -o $@

# tlshttp.c compiles the upstream reqguard source verbatim; silence only
# warnings that originate inside that included file.
build/tlshttp.o: src/tlshttp.c | build
	$(CC) $(CFLAGS) -Wno-unused-function -Wno-stringop-truncation -Isrc -c $< -o $@

tlsrecord: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

test: tlsrecord
	./tlsrecord

bench: tlsrecord
	./tlsrecord bench

# field-by-field parity against the independent Python reference parser
refcheck: tlsrecord
	python3 -I tools/gen_vectors.py vectors
	bash tools/refcheck.sh

clean:
	rm -rf tlsrecord build vectors tools/__pycache__

.PHONY: all test bench refcheck clean
