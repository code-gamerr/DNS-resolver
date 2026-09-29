/*
 * test_encode.c — Phase 3 unit tests for DNS name encoding
 */

#include "dns_encode.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) \
    do { \
        if (cond) { \
            g_pass++; \
        } else { \
            fprintf(stderr, "FAIL  %s:%d  " #cond "\n", __FILE__, __LINE__); \
            g_fail++; \
        } \
    } while (0)

static void expect_bytes(const char *name, const uint8_t *want, size_t want_len)
{
    uint8_t buf[DNS_NAME_WIRE_MAX + 8];
    size_t off = 0;
    int n;
    size_t i;

    memset(buf, 0xA5, sizeof(buf));
    n = dns_encode_name(name, buf, &off, sizeof(buf));
    CHECK(n > 0);
    CHECK((size_t)n == want_len);
    CHECK(off == want_len);
    for (i = 0; i < want_len; i++) {
        CHECK(buf[i] == want[i]);
    }
}

static void test_valid_names(void)
{
    /* example.com → 07 example 03 com 00 */
    {
        static const uint8_t want[] = {
            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00
        };
        expect_bytes("example.com", want, sizeof(want));
    }

    /* google.com */
    {
        static const uint8_t want[] = {
            0x06, 'g', 'o', 'o', 'g', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00
        };
        expect_bytes("google.com", want, sizeof(want));
    }

    /* sub.example.com */
    {
        static const uint8_t want[] = {
            0x03, 's', 'u', 'b',
            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00
        };
        expect_bytes("sub.example.com", want, sizeof(want));
    }

    /* www.example.com */
    {
        static const uint8_t want[] = {
            0x03, 'w', 'w', 'w',
            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00
        };
        expect_bytes("www.example.com", want, sizeof(want));
    }

    /* single-label */
    {
        static const uint8_t want[] = {
            0x05, 'l', 'o', 'c', 'a', 'l',
            0x00
        };
        expect_bytes("local", want, sizeof(want));
    }

    /* trailing FQDN dot is accepted */
    {
        static const uint8_t want[] = {
            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00
        };
        expect_bytes("example.com.", want, sizeof(want));
    }

}

static void test_xn_punycode_style(void)
{
    static const uint8_t want[] = {
        0x08, 'x', 'n', '-', '-', 'p', '1', 'a', 'i',
        0x03, 'c', 'o', 'm',
        0x00
    };
    expect_bytes("xn--p1ai.com", want, sizeof(want));
}

static void test_max_label(void)
{
    char name[DNS_LABEL_MAX + 8];
    uint8_t buf[DNS_NAME_WIRE_MAX];
    size_t off = 0;
    int n;
    int i;

    /* Exactly 63 'a' characters — valid. */
    for (i = 0; i < DNS_LABEL_MAX; i++) {
        name[i] = 'a';
    }
    name[DNS_LABEL_MAX] = '\0';

    n = dns_encode_name(name, buf, &off, sizeof(buf));
    CHECK(n == DNS_LABEL_MAX + 2); /* len + 63 chars + 0 */
    CHECK(buf[0] == DNS_LABEL_MAX);
}

static void test_invalid_names(void)
{
    uint8_t buf[DNS_NAME_WIRE_MAX];
    size_t off;

    off = 0;
    CHECK(dns_encode_name(NULL, buf, &off, sizeof(buf)) == DNS_ENCODE_ERR_NULL);
    CHECK(off == 0u);

    off = 0;
    CHECK(dns_encode_name("example.com", NULL, &off, sizeof(buf)) ==
          DNS_ENCODE_ERR_NULL);

    off = 0;
    CHECK(dns_encode_name("example.com", buf, NULL, sizeof(buf)) ==
          DNS_ENCODE_ERR_NULL);

    off = 0;
    CHECK(dns_encode_name("", buf, &off, sizeof(buf)) == DNS_ENCODE_ERR_EMPTY);
    CHECK(off == 0u);

    off = 0;
    CHECK(dns_encode_name(".", buf, &off, sizeof(buf)) == DNS_ENCODE_ERR_EMPTY);

    off = 0;
    CHECK(dns_encode_name("example..com", buf, &off, sizeof(buf)) ==
          DNS_ENCODE_ERR_EMPTY_LABEL);
    CHECK(off == 0u);

    off = 0;
    CHECK(dns_encode_name(".example.com", buf, &off, sizeof(buf)) ==
          DNS_ENCODE_ERR_EMPTY_LABEL);

    off = 0;
    CHECK(dns_encode_name("exam ple.com", buf, &off, sizeof(buf)) ==
          DNS_ENCODE_ERR_CHAR);

    off = 0;
    CHECK(dns_encode_name("exam_ple.com", buf, &off, sizeof(buf)) ==
          DNS_ENCODE_ERR_CHAR);

    off = 0;
    CHECK(dns_encode_name("-bad.com", buf, &off, sizeof(buf)) ==
          DNS_ENCODE_ERR_HYPHEN);

    off = 0;
    CHECK(dns_encode_name("bad-.com", buf, &off, sizeof(buf)) ==
          DNS_ENCODE_ERR_HYPHEN);

    /* Label length 64 */
    {
        char name[DNS_LABEL_MAX + 8];
        int i;
        for (i = 0; i < DNS_LABEL_MAX + 1; i++) {
            name[i] = 'a';
        }
        name[DNS_LABEL_MAX + 1] = '\0';
        off = 0;
        CHECK(dns_encode_name(name, buf, &off, sizeof(buf)) ==
              DNS_ENCODE_ERR_LABEL_LEN);
        CHECK(off == 0u);
    }

    /* Buffer too small for "a.com" (1+1 + 1+3 + 1 = 7 bytes) */
    {
        uint8_t tiny[4];
        off = 0;
        CHECK(dns_encode_name("a.com", tiny, &off, sizeof(tiny)) ==
              DNS_ENCODE_ERR_OVERFLOW);
        CHECK(off == 0u);
    }
}

static void test_offset_advance(void)
{
    uint8_t buf[64];
    size_t off = 4;
    int n;
    static const uint8_t want[] = {
        0x03, 'f', 'o', 'o',
        0x00
    };
    size_t i;

    memset(buf, 0x00, sizeof(buf));
    n = dns_encode_name("foo", buf, &off, sizeof(buf));
    CHECK(n == (int)sizeof(want));
    CHECK(off == 4u + sizeof(want));
    for (i = 0; i < sizeof(want); i++) {
        CHECK(buf[4u + i] == want[i]);
    }
}

static void test_total_wire_limit(void)
{
    /*
     * Build a name whose encoded form would exceed 255 octets.
     * Four labels of 63 chars: 4 * (1 + 63) + 1 = 257 > 255.
     */
    char name[(DNS_LABEL_MAX + 1) * 4];
    uint8_t buf[DNS_NAME_WIRE_MAX + 16];
    size_t off = 0;
    size_t pos = 0;
    int lab;

    for (lab = 0; lab < 4; lab++) {
        int i;
        if (lab > 0) {
            name[pos++] = '.';
        }
        for (i = 0; i < DNS_LABEL_MAX; i++) {
            name[pos++] = 'a';
        }
    }
    name[pos] = '\0';

    CHECK(dns_encode_name(name, buf, &off, sizeof(buf)) ==
          DNS_ENCODE_ERR_TOTAL_LEN);
    CHECK(off == 0u);
}

int main(void)
{
    test_valid_names();
    test_xn_punycode_style();
    test_max_label();
    test_invalid_names();
    test_offset_advance();
    test_total_wire_limit();

    if (g_fail == 0) {
        printf("OK  %d/%d tests passed\n", g_pass, g_pass + g_fail);
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "FAIL  %d/%d tests failed\n", g_fail, g_pass + g_fail);
    return EXIT_FAILURE;
}
