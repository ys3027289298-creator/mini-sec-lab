CC ?= gcc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra

CRYPTO_DRIVERS := reqguard_drv tokenauth_drv
DRIVERS := reqguard_drv pathguard_drv tokenauth_drv

all: $(DRIVERS)

reqguard_drv tokenauth_drv: %_drv: %_drv.c drv_json.h
	$(CC) $(CFLAGS) -I. $< -o $@ -lcrypto

pathguard_drv: %_drv: %_drv.c drv_json.h
	$(CC) $(CFLAGS) -I. $< -o $@

check: all
	python3 -I run_checks.py

clean:
	rm -f $(DRIVERS)

.PHONY: all check clean
