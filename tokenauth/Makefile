CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

all: tokenauth

tokenauth: src/tokenauth.c
	$(CC) $(CFLAGS) $< -o $@ -lcrypto

test: tokenauth
	./tokenauth

clean:
	rm -f tokenauth
