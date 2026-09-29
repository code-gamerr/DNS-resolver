/*
 * test_parse.c — Phase 6: response header parse/validate tests
 */

#include "dns.h"
#include "dns_parse.h"
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

static void write_hdr(uint8_t *buf, uint16_t id, uint16_t flags,
                      uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar)
{
    struct dns_header h;

    h.id = id;
    h.flags = flags;
    h.qdcount = qd;
    h.ancount = an;
    h.nscount = ns;
    h.arcount = ar;
    CHECK(dns_header_write(&h, buf, 0, DNS_HEADER_WIRE_SIZE) ==
          DNS_HEADER_WIRE_SIZE);
}

static void test_ok_response(void)
{
    uint8_t buf[DNS_HEADER_WIRE_SIZE];
    struct dns_response_info info;
    uint16_t flags = (uint16_t)(DNS_FLAG_QR_RESPONSE | DNS_FLAG_RD |
                                DNS_FLAG_RA);

    write_hdr(buf, 0x4242u, flags, 1u, 2u, 0u, 0u);
    CHECK(dns_parse_response_header(buf, sizeof(buf), 0x4242u, &info) ==
          DNS_PARSE_OK);
    CHECK(info.hdr.qdcount == 1u);
    CHECK(info.hdr.ancount == 2u);
    CHECK(info.rcode == 0u);
    CHECK(info.recursion_available == 1);
    CHECK(info.is_truncated == 0);
}

static void test_id_mismatch(void)
{
    uint8_t buf[DNS_HEADER_WIRE_SIZE];
    struct dns_response_info info;
    uint16_t flags = DNS_FLAG_QR_RESPONSE;

    write_hdr(buf, 0x1111u, flags, 1u, 0u, 0u, 0u);
    CHECK(dns_parse_response_header(buf, sizeof(buf), 0x2222u, &info) ==
          DNS_PARSE_ERR_ID_MISMATCH);
}

static void test_not_response(void)
{
    uint8_t buf[DNS_HEADER_WIRE_SIZE];
    struct dns_response_info info;

    write_hdr(buf, 0x0001u, DNS_FLAG_RD, 1u, 0u, 0u, 0u);
    CHECK(dns_parse_response_header(buf, sizeof(buf), 0x0001u, &info) ==
          DNS_PARSE_ERR_NOT_RESPONSE);
}

static void test_nxdomain(void)
{
    uint8_t buf[DNS_HEADER_WIRE_SIZE];
    struct dns_response_info info;
    uint16_t flags = (uint16_t)(DNS_FLAG_QR_RESPONSE | DNS_FLAG_RCODE_NXDOMAIN);

    write_hdr(buf, 0x0007u, flags, 1u, 0u, 0u, 0u);
    CHECK(dns_parse_response_header(buf, sizeof(buf), 0x0007u, &info) ==
          DNS_PARSE_ERR_RCODE);
    CHECK(info.rcode == 3u);
    CHECK(strcmp(dns_rcode_name(info.rcode), "NXDOMAIN") == 0);
}

static void test_short_packet(void)
{
    uint8_t buf[11] = {0};
    struct dns_response_info info;

    CHECK(dns_parse_response_header(buf, sizeof(buf), 0u, &info) ==
          DNS_PARSE_ERR_SHORT);
    CHECK(dns_parse_response_header(NULL, 12, 0u, &info) == DNS_PARSE_ERR_ARGS);
}

static void test_truncated_and_aa(void)
{
    uint8_t buf[DNS_HEADER_WIRE_SIZE];
    struct dns_response_info info;
    uint16_t flags = (uint16_t)(DNS_FLAG_QR_RESPONSE | DNS_FLAG_AA | DNS_FLAG_TC);

    write_hdr(buf, 0x55AAu, flags, 1u, 1u, 0u, 0u);
    CHECK(dns_parse_response_header(buf, sizeof(buf), 0x55AAu, &info) ==
          DNS_PARSE_OK);
    CHECK(info.is_truncated == 1);
    CHECK(info.is_authoritative == 1);
}

static void test_rcode_names(void)
{
    CHECK(strcmp(dns_rcode_name(0), "NOERROR") == 0);
    CHECK(strcmp(dns_rcode_name(1), "FORMERR") == 0);
    CHECK(strcmp(dns_rcode_name(2), "SERVFAIL") == 0);
    CHECK(strcmp(dns_rcode_name(5), "REFUSED") == 0);
}

int main(void)
{
    test_ok_response();
    test_id_mismatch();
    test_not_response();
    test_nxdomain();
    test_short_packet();
    test_truncated_and_aa();
    test_rcode_names();

    if (g_fail == 0) {
        printf("OK  %d/%d tests passed\n", g_pass, g_pass + g_fail);
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "FAIL  %d/%d tests failed\n", g_fail, g_pass + g_fail);
    return EXIT_FAILURE;
}
