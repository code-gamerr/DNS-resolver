/*
 * test_phase2.c — unit tests for wire helpers and DNS header (Phase 2)
 *
 * Build:  see Makefile target 'test'
 * Run:    ./test_phase2[.exe]
 */

#include "dns.h"
#include "wire.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Minimal test harness                                                */
/* ------------------------------------------------------------------ */
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

static void test_wire_reads(void)
{
    const uint8_t buf[] = {
        0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF
    };
    size_t off = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;

    CHECK(wire_read_u16be(buf, sizeof(buf), &off, &u16));
    CHECK(u16 == 0x1234u);
    CHECK(off == 2u);
    CHECK(wire_read_u32be(buf, sizeof(buf), &off, &u32));
    CHECK(u32 == 0xDEADBEEFu);
    CHECK(off == sizeof(buf));

    /* A failed read leaves both the cursor and destination unchanged. */
    u16 = 0xCAFEu;
    CHECK(!wire_read_u16be(buf, sizeof(buf), &off, &u16));
    CHECK(off == sizeof(buf));
    CHECK(u16 == 0xCAFEu);

    CHECK(!wire_read_u16be(NULL, sizeof(buf), &off, &u16));
    CHECK(!wire_read_u16be(buf, sizeof(buf), NULL, &u16));
    CHECK(!wire_read_u16be(buf, sizeof(buf), &off, NULL));
    CHECK(!wire_read_u32be(NULL, sizeof(buf), &off, &u32));
    CHECK(!wire_read_u32be(buf, sizeof(buf), NULL, &u32));
    CHECK(!wire_read_u32be(buf, sizeof(buf), &off, NULL));
}

/* ------------------------------------------------------------------ */
/* wire_put_u8                                                         */
/* ------------------------------------------------------------------ */
static void test_wire_u8(void)
{
    uint8_t buf[4] = {0};

    /* normal write at offset 0 */
    CHECK(wire_put_u8(buf, 0, 0xAB, sizeof(buf)) == 1);
    CHECK(buf[0] == 0xAB);

    /* chained write */
    CHECK(wire_put_u8(buf, 1, 0xCD, sizeof(buf)) == 2);
    CHECK(buf[1] == 0xCD);

    /* write at last byte */
    CHECK(wire_put_u8(buf, 3, 0xFF, sizeof(buf)) == 4);
    CHECK(buf[3] == 0xFF);

    /* overflow: one past the end */
    CHECK(wire_put_u8(buf, 4, 0x00, sizeof(buf)) == -1);

    /* overflow: negative offset */
    CHECK(wire_put_u8(buf, -1, 0x00, sizeof(buf)) == -1);

    /* zero-capacity buffer */
    CHECK(wire_put_u8(buf, 0, 0x00, 0) == -1);
    CHECK(wire_put_u8(NULL, 0, 0x00, sizeof(buf)) == -1);
    CHECK(wire_put_u8(buf, INT_MAX, 0x00, (size_t)INT_MAX + 1u) == -1);
}

/* ------------------------------------------------------------------ */
/* wire_put_u16be                                                      */
/* ------------------------------------------------------------------ */
static void test_wire_u16be(void)
{
    uint8_t buf[8] = {0};

    /* value 0x1234 → bytes 0x12 0x34 */
    CHECK(wire_put_u16be(buf, 0, 0x1234u, sizeof(buf)) == 2);
    CHECK(buf[0] == 0x12);
    CHECK(buf[1] == 0x34);

    /* value 0x0001 */
    CHECK(wire_put_u16be(buf, 2, 0x0001u, sizeof(buf)) == 4);
    CHECK(buf[2] == 0x00);
    CHECK(buf[3] == 0x01);

    /* value 0xFFFF */
    CHECK(wire_put_u16be(buf, 4, 0xFFFFu, sizeof(buf)) == 6);
    CHECK(buf[4] == 0xFF);
    CHECK(buf[5] == 0xFF);

    /* overflow: only 1 byte left */
    CHECK(wire_put_u16be(buf, 7, 0x0000u, sizeof(buf)) == -1);

    /* overflow: at capacity */
    CHECK(wire_put_u16be(buf, 8, 0x0000u, sizeof(buf)) == -1);

    /* overflow: negative offset */
    CHECK(wire_put_u16be(buf, -1, 0x0000u, sizeof(buf)) == -1);
    CHECK(wire_put_u16be(NULL, 0, 0x0000u, sizeof(buf)) == -1);
}

/* ------------------------------------------------------------------ */
/* wire_put_u32be                                                      */
/* ------------------------------------------------------------------ */
static void test_wire_u32be(void)
{
    uint8_t buf[8] = {0};

    /* value 0xDEADBEEF */
    CHECK(wire_put_u32be(buf, 0, 0xDEADBEEFu, sizeof(buf)) == 4);
    CHECK(buf[0] == 0xDE);
    CHECK(buf[1] == 0xAD);
    CHECK(buf[2] == 0xBE);
    CHECK(buf[3] == 0xEF);

    /* write at offset 4 */
    CHECK(wire_put_u32be(buf, 4, 0x00000001u, sizeof(buf)) == 8);
    CHECK(buf[7] == 0x01);

    /* overflow: needs 4 bytes but only 3 remain */
    CHECK(wire_put_u32be(buf, 5, 0x00u, sizeof(buf)) == -1);

    /* overflow: negative offset */
    CHECK(wire_put_u32be(buf, -1, 0x00u, sizeof(buf)) == -1);
    CHECK(wire_put_u32be(NULL, 0, 0x00u, sizeof(buf)) == -1);
}

/* ------------------------------------------------------------------ */
/* wire_put_bytes                                                      */
/* ------------------------------------------------------------------ */
static void test_wire_bytes(void)
{
    uint8_t buf[8]  = {0};
    const uint8_t src[3] = {0x01, 0x02, 0x03};

    CHECK(wire_put_bytes(buf, 0, src, 3, sizeof(buf)) == 3);
    CHECK(buf[0] == 0x01);
    CHECK(buf[1] == 0x02);
    CHECK(buf[2] == 0x03);

    /* zero-length copy is a no-op */
    CHECK(wire_put_bytes(buf, 3, src, 0, sizeof(buf)) == 3);

    /* overflow */
    CHECK(wire_put_bytes(buf, 6, src, 3, sizeof(buf)) == -1);

    /* negative len */
    CHECK(wire_put_bytes(buf, 0, src, -1, sizeof(buf)) == -1);
    CHECK(wire_put_bytes(NULL, 0, src, 3, sizeof(buf)) == -1);
    CHECK(wire_put_bytes(buf, 0, NULL, 3, sizeof(buf)) == -1);
}

/* ------------------------------------------------------------------ */
/* dns_header_write                                                    */
/* ------------------------------------------------------------------ */
static void test_dns_header_write(void)
{
    uint8_t buf[16] = {0};
    struct dns_header hdr;

    hdr.id      = 0xABCDu;
    hdr.flags   = DNS_FLAG_RD;
    hdr.qdcount = 1;
    hdr.ancount = 0;
    hdr.nscount = 0;
    hdr.arcount = 0;

    CHECK(dns_header_write(&hdr, buf, 0, sizeof(buf)) == DNS_HEADER_WIRE_SIZE);

    /* ID */
    CHECK(buf[0] == 0xAB);
    CHECK(buf[1] == 0xCD);

    /* Flags: RD = bit 8 = 0x0100 → bytes 0x01 0x00 */
    CHECK(buf[2] == 0x01);
    CHECK(buf[3] == 0x00);

    /* QDCOUNT = 1 */
    CHECK(buf[4] == 0x00);
    CHECK(buf[5] == 0x01);

    /* ANCOUNT = 0 */
    CHECK(buf[6] == 0x00);
    CHECK(buf[7] == 0x00);

    /* NSCOUNT = 0 */
    CHECK(buf[8] == 0x00);
    CHECK(buf[9] == 0x00);

    /* ARCOUNT = 0 */
    CHECK(buf[10] == 0x00);
    CHECK(buf[11] == 0x00);

    /* overflow: buffer too small (only 11 bytes) */
    CHECK(dns_header_write(&hdr, buf, 0, 11) == -1);
    CHECK(dns_header_write(NULL, buf, 0, sizeof(buf)) == -1);
    CHECK(dns_header_write(&hdr, NULL, 0, sizeof(buf)) == -1);

    /* write at non-zero offset */
    {
        uint8_t buf2[16] = {0};
        CHECK(dns_header_write(&hdr, buf2, 2, sizeof(buf2)) == 14);
        CHECK(buf2[2] == 0xAB);
        CHECK(buf2[3] == 0xCD);
    }
}

static void test_dns_header_read(void)
{
    const uint8_t packet[DNS_HEADER_WIRE_SIZE] = {
        0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01,
        0x00, 0x02, 0x00, 0x03, 0x00, 0x04
    };
    struct dns_header hdr = {0};
    size_t off = 0;

    CHECK(dns_header_read(packet, sizeof(packet), &off, &hdr) == 0);
    CHECK(off == DNS_HEADER_WIRE_SIZE);
    CHECK(hdr.id == 0xABCDu);
    CHECK(hdr.flags == 0x8180u);
    CHECK(hdr.qdcount == 1u);
    CHECK(hdr.ancount == 2u);
    CHECK(hdr.nscount == 3u);
    CHECK(hdr.arcount == 4u);

    off = 0;
    hdr.id = 0x7777u;
    CHECK(dns_header_read(packet, DNS_HEADER_WIRE_SIZE - 1u, &off, &hdr) == -1);
    CHECK(off == 0u);
    CHECK(hdr.id == 0x7777u);
    CHECK(dns_header_read(NULL, sizeof(packet), &off, &hdr) == -1);
    CHECK(dns_header_read(packet, sizeof(packet), NULL, &hdr) == -1);
    CHECK(dns_header_read(packet, sizeof(packet), &off, NULL) == -1);
}

/* ------------------------------------------------------------------ */
/* dns_qtype_from_str                                                  */
/* ------------------------------------------------------------------ */
static void test_dns_qtype_from_str(void)
{
    CHECK(dns_qtype_from_str("A")     == DNS_QTYPE_A);
    CHECK(dns_qtype_from_str("NS")    == DNS_QTYPE_NS);
    CHECK(dns_qtype_from_str("CNAME") == DNS_QTYPE_CNAME);
    CHECK(dns_qtype_from_str("MX")    == DNS_QTYPE_MX);
    CHECK(dns_qtype_from_str("TXT")   == DNS_QTYPE_TXT);
    CHECK(dns_qtype_from_str("AAAA")  == DNS_QTYPE_AAAA);

    /* unknown / wrong case → 0 */
    CHECK(dns_qtype_from_str("PTR")   == 0);
    CHECK(dns_qtype_from_str("a")     == 0);
    CHECK(dns_qtype_from_str("")      == 0);
    CHECK(dns_qtype_from_str(NULL)    == 0);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(void)
{
    test_wire_reads();
    test_wire_u8();
    test_wire_u16be();
    test_wire_u32be();
    test_wire_bytes();
    test_dns_header_write();
    test_dns_header_read();
    test_dns_qtype_from_str();

    if (g_fail == 0) {
        printf("OK  %d/%d tests passed\n", g_pass, g_pass + g_fail);
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "FAIL  %d/%d tests failed\n", g_fail, g_pass + g_fail);
    return EXIT_FAILURE;
}
