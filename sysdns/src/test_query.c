/*
 * test_query.c — Phase 4: DNS query packet construction tests
 */

#include "dns.h"
#include "dns_query.h"
#include "wire.h"

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

static void test_example_com_a(void)
{
    uint8_t buf[DNS_UDP_PAYLOAD_MAX];
    int n;
    size_t off;
    uint16_t u16;
    struct dns_header hdr;

    /* Fixed ID so the packet is deterministic. */
    n = dns_query_build_with_id(buf, sizeof(buf), 0x1234u, "example.com",
                                DNS_QTYPE_A);
    CHECK(n == 29); /* 12 header + 13 QNAME + 2 QTYPE + 2 QCLASS */

    off = 0;
    CHECK(dns_header_read(buf, (size_t)n, &off, &hdr) == 0);
    CHECK(hdr.id == 0x1234u);
    CHECK(hdr.flags == DNS_FLAG_RD);
    CHECK(hdr.qdcount == 1u);
    CHECK(hdr.ancount == 0u);
    CHECK(hdr.nscount == 0u);
    CHECK(hdr.arcount == 0u);
    CHECK(off == 12u);

    /* QNAME: 07 example 03 com 00 */
    CHECK(buf[12] == 0x07);
    CHECK(buf[13] == 'e');
    CHECK(buf[20] == 0x03);
    CHECK(buf[21] == 'c');
    CHECK(buf[24] == 0x00);

    off = 25;
    CHECK(wire_read_u16be(buf, (size_t)n, &off, &u16));
    CHECK(u16 == DNS_QTYPE_A);
    CHECK(wire_read_u16be(buf, (size_t)n, &off, &u16));
    CHECK(u16 == DNS_QCLASS_IN);
    CHECK(off == (size_t)n);
}

static void test_google_aaaa(void)
{
    uint8_t buf[DNS_UDP_PAYLOAD_MAX];
    int n;
    size_t off = 0;
    uint16_t qtype = 0;

    n = dns_query_build_with_id(buf, sizeof(buf), 0xABCDu, "google.com",
                                DNS_QTYPE_AAAA);
    CHECK(n == 28); /* 12 + 12 + 2 + 2 */

    off = (size_t)n - 4u;
    CHECK(wire_read_u16be(buf, (size_t)n, &off, &qtype));
    CHECK(qtype == DNS_QTYPE_AAAA);
}

static void test_reject_bad(void)
{
    uint8_t buf[DNS_UDP_PAYLOAD_MAX];

    CHECK(dns_query_build_with_id(NULL, sizeof(buf), 1u, "a.com",
                                  DNS_QTYPE_A) < 0);
    CHECK(dns_query_build_with_id(buf, sizeof(buf), 1u, NULL, DNS_QTYPE_A) < 0);
    CHECK(dns_query_build_with_id(buf, sizeof(buf), 1u, "a.com", 0u) < 0);
    CHECK(dns_query_build_with_id(buf, sizeof(buf), 1u, "bad..name",
                                  DNS_QTYPE_A) < 0);
    CHECK(dns_query_build_with_id(buf, 8, 1u, "example.com", DNS_QTYPE_A) < 0);
}

static void test_build_generates_id(void)
{
    uint8_t buf[DNS_UDP_PAYLOAD_MAX];
    uint16_t txid = 0;
    int n;

    n = dns_query_build(buf, sizeof(buf), "local.test", DNS_QTYPE_TXT, &txid);
    CHECK(n > DNS_HEADER_WIRE_SIZE);
    CHECK(buf[0] == (uint8_t)((txid >> 8) & 0xFFu));
    CHECK(buf[1] == (uint8_t)(txid & 0xFFu));
}

int main(void)
{
    test_example_com_a();
    test_google_aaaa();
    test_reject_bad();
    test_build_generates_id();

    if (g_fail == 0) {
        printf("OK  %d/%d tests passed\n", g_pass, g_pass + g_fail);
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "FAIL  %d/%d tests failed\n", g_fail, g_pass + g_fail);
    return EXIT_FAILURE;
}
