# sysDNS — end-to-end DNS resolver (phases 1–12)
# Target: Linux/POSIX. Also builds with mingw32-make on Windows.

CC     = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion

COMMON := src/wire.c src/dns_hdr.c src/dns_encode.c src/dns_query.c \
          src/hexdump.c src/dns_socket.c src/dns_parse.c src/dns_name.c \
          src/dns_records.c src/dns_cache.c src/dns_resolver.c src/recursive.c

SRCS_MAIN := src/main.c $(COMMON)

SRCS_TEST2 := src/test_phase2.c src/wire.c src/dns_hdr.c
SRCS_TEST3 := src/test_encode.c src/dns_encode.c
SRCS_TEST4 := src/test_query.c src/wire.c src/dns_hdr.c src/dns_encode.c src/dns_query.c
SRCS_TEST6 := src/test_parse.c src/wire.c src/dns_hdr.c src/dns_parse.c
SRCS_TEST7 := src/test_records.c src/wire.c src/dns_hdr.c src/dns_name.c \
              src/dns_records.c src/dns_parse.c
SRCS_TEST8 := src/test_cache.c src/dns_cache.c src/dns_name.c src/dns_records.c \
              src/dns_parse.c src/wire.c src/dns_hdr.c

ifeq ($(OS),Windows_NT)
    BIN       := sysdns.exe
    TEST2_BIN := test_phase2.exe
    TEST3_BIN := test_encode.exe
    TEST4_BIN := test_query.exe
    TEST6_BIN := test_parse.exe
    TEST7_BIN := test_records.exe
    TEST8_BIN := test_cache.exe
    RM        := del /Q /F
    LDLIBS    := -lws2_32
else
    BIN       := sysdns
    TEST2_BIN := test_phase2
    TEST3_BIN := test_encode
    TEST4_BIN := test_query
    TEST6_BIN := test_parse
    TEST7_BIN := test_records
    TEST8_BIN := test_cache
    RM        := rm -f
    LDLIBS    :=
endif

.PHONY: all clean debug sanitize test

all: $(BIN)

$(BIN): $(SRCS_MAIN)
	$(CC) $(CFLAGS) -o $@ $(SRCS_MAIN) $(LDLIBS)

$(TEST2_BIN): $(SRCS_TEST2)
	$(CC) $(CFLAGS) -o $@ $(SRCS_TEST2) $(LDLIBS)

$(TEST3_BIN): $(SRCS_TEST3)
	$(CC) $(CFLAGS) -o $@ $(SRCS_TEST3) $(LDLIBS)

$(TEST4_BIN): $(SRCS_TEST4)
	$(CC) $(CFLAGS) -o $@ $(SRCS_TEST4) $(LDLIBS)

$(TEST6_BIN): $(SRCS_TEST6)
	$(CC) $(CFLAGS) -o $@ $(SRCS_TEST6) $(LDLIBS)

$(TEST7_BIN): $(SRCS_TEST7)
	$(CC) $(CFLAGS) -o $@ $(SRCS_TEST7) $(LDLIBS)

$(TEST8_BIN): $(SRCS_TEST8)
	$(CC) $(CFLAGS) -o $@ $(SRCS_TEST8) $(LDLIBS)

debug:
	$(CC) $(CFLAGS) -g -O0 -DDEBUG -o $(BIN) $(SRCS_MAIN) $(LDLIBS)

sanitize:
	$(CC) $(CFLAGS) -g -O1 -fsanitize=address,undefined -o $(BIN) $(SRCS_MAIN) $(LDLIBS)
	$(CC) $(CFLAGS) -g -O1 -fsanitize=address,undefined -o $(TEST7_BIN) $(SRCS_TEST7) $(LDLIBS)
	$(CC) $(CFLAGS) -g -O1 -fsanitize=address,undefined -o $(TEST8_BIN) $(SRCS_TEST8) $(LDLIBS)
	./$(TEST7_BIN)
	./$(TEST8_BIN)

test: $(BIN) $(TEST2_BIN) $(TEST3_BIN) $(TEST4_BIN) $(TEST6_BIN) $(TEST7_BIN) $(TEST8_BIN)
	./$(TEST2_BIN)
	./$(TEST3_BIN)
	./$(TEST4_BIN)
	./$(TEST6_BIN)
	./$(TEST7_BIN)
	./$(TEST8_BIN)
	./$(BIN) --help
	./$(BIN) --version

clean:
	-$(RM) $(BIN) $(TEST2_BIN) $(TEST3_BIN) $(TEST4_BIN) $(TEST6_BIN) $(TEST7_BIN) $(TEST8_BIN)
