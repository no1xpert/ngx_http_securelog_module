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
	@./test_aes_crypto

clean:
	rm -f $(TESTS)
