CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

all: tokenauth

tokenauth: src/tokenauth.c
	$(CC) $(CFLAGS) -DSELF_TEST $< -o $@ -lcrypto

drv: ../checker/tokenauth_drv

../checker/tokenauth_drv: src/tokenauth.c ../checker/tokenauth_drv.c ../checker/drv_json.h
	$(CC) $(CFLAGS) -I../checker ../checker/tokenauth_drv.c -o $@ -lcrypto

test: tokenauth
	./tokenauth

clean:
	rm -f tokenauth ../checker/tokenauth_drv

.PHONY: all drv test clean
