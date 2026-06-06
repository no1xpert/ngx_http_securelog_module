# tests/Makefile
CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -g \
          $(shell pkg-config --cflags cmocka openssl)
LDFLAGS = $(shell pkg-config --libs cmocka openssl)

TESTS   = test_aes_crypto

.PHONY: all clean run

all: $(TESTS)

test_aes_crypto: test_aes_crypto.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

run: all
	@echo "=========================================="
	@echo " securelog unit tests"
	@echo "=========================================="
	@./test_aes_crypto 2>&1 | awk \
	'/^\[==========\]/ { print; next } \
	/^\[ RUN      \]/ { gsub(/\[ RUN      \] /, ""); name = $$0; next } \
	/^\[       OK \]/ { printf "[ %-45s  OK ]\n", name; next } \
	/^\[  FAILED  \]/ { printf "[ %-45s FAIL]\n", name; next } \
	/^\[  PASSED  \]/ { print; next } \
	{ print }'

clean:
	rm -f $(TESTS)
