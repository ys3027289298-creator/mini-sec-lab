CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

all: pathguard

pathguard: src/pathguard.c
	$(CC) $(CFLAGS) -DSELF_TEST $< -o $@

drv: ../checker/pathguard_drv

../checker/pathguard_drv: src/pathguard.c ../checker/pathguard_drv.c ../checker/drv_json.h
	$(CC) $(CFLAGS) -I../checker ../checker/pathguard_drv.c -o $@

test: pathguard
	./pathguard

clean:
	rm -f pathguard ../checker/pathguard_drv

.PHONY: all drv test clean
