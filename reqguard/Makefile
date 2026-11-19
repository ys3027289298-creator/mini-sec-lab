CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

all: reqguard

reqguard: src/reqguard.c
	$(CC) $(CFLAGS) -DSELF_TEST $< -o $@ -lcrypto

drv: ../checker/reqguard_drv

../checker/reqguard_drv: src/reqguard.c ../checker/reqguard_drv.c ../checker/drv_json.h
	$(CC) $(CFLAGS) -I../checker ../checker/reqguard_drv.c -o $@ -lcrypto

test: reqguard
	./reqguard

clean:
	rm -f reqguard ../checker/reqguard_drv

.PHONY: all drv test clean
