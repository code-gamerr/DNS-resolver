# sysDNS — Phases 1 and 2
# CLI foundation plus DNS header and checked big-endian wire helpers.
# Target: Linux/POSIX.  Also builds with mingw32-make on Windows.

CC     = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion

SRCS_MAIN := src/main.c src/wire.c src/dns_hdr.c
SRCS_TEST := src/test_phase2.c src/wire.c src/dns_hdr.c

ifeq ($(OS),Windows_NT)
    BIN      := sysdns.exe
    TEST_BIN := test_phase2.exe
    RM       := del /Q /F
else
    BIN      := sysdns
    TEST_BIN := test_phase2
    RM       := rm -f
endif

.PHONY: all clean debug sanitize test

all: $(BIN)

$(BIN): $(SRCS_MAIN)
	$(CC) $(CFLAGS) -o $@ $(SRCS_MAIN)

$(TEST_BIN): $(SRCS_TEST)
	$(CC) $(CFLAGS) -o $@ $(SRCS_TEST)

debug:
	$(CC) $(CFLAGS) -g -O0 -DDEBUG -o $(BIN) $(SRCS_MAIN)

# Requires libasan/libubsan (Linux gcc/clang). MinGW usually lacks them.
sanitize:
	$(CC) $(CFLAGS) -g -O1 -fsanitize=address,undefined -o $(BIN) $(SRCS_MAIN)
	$(CC) $(CFLAGS) -g -O1 -fsanitize=address,undefined -o $(TEST_BIN) $(SRCS_TEST)
	./$(TEST_BIN)

test: $(BIN) $(TEST_BIN)
	./$(TEST_BIN)
	./$(BIN) --help
	./$(BIN) --version
	./$(BIN) example.com A

clean:
	-$(RM) $(BIN) $(TEST_BIN)
