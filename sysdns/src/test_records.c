/*
 * test_records.c — name compression, record parsers, malformed packets.
 */

#include "dns.h"
#include "dns_name.h"
#include "dns_records.h"

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

static void put_hdr(uint8_t *buf, uint16_t an, uint16_t ns, uint16_t ar)
{
    struct dns_header h;
    h.id = 0x1234u;
    h.flags = (uint16_t)(DNS_FLAG_QR_RESPONSE | DNS_FLAG_RD | DNS_FLAG_RA);
    h.qdcount = 1u;
    h.ancount = an;
    h.nscount = ns;
    h.arcount = ar;
    CHECK(dns_header_write(&h, buf, 0, 64) == 12);
}

static void test_decode_plain(void)
{
    uint8_t pkt[32];
    char name[DNS_NAME_CAP];
    size_t off = 0;
    const uint8_t raw[] = {
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0
    };

    memcpy(pkt, raw, sizeof(raw));
    CHECK(dns_name_decode(pkt, sizeof(raw), &off, name, sizeof(name)) == 0);
    CHECK(off == sizeof(raw));
    CHECK(strcmp(name, "www.example.com") == 0);
}

static void test_compression_pointer(void)
{
    uint8_t pkt[64];
    char name[DNS_NAME_CAP];
    size_t off;
    struct dns_message msg;
    char text[64];

    memset(pkt, 0, sizeof(pkt));
    put_hdr(pkt, 1, 0, 0);
    /* QNAME at offset 12: example.com */
    pkt[12] = 7;
    memcpy(pkt + 13, "example", 7);
    pkt[20] = 3;
    memcpy(pkt + 21, "com", 3);
    pkt[24] = 0;
    pkt[25] = 0; pkt[26] = 1; /* A */
    pkt[27] = 0; pkt[28] = 1; /* IN */
    /* Answer name is a pointer to offset 12. */
    pkt[29] = 0xC0; pkt[30] = 0x0C;
    pkt[31] = 0; pkt[32] = 1; /* A */
    pkt[33] = 0; pkt[34] = 1;
    pkt[35] = 0; pkt[36] = 0; pkt[37] = 0; pkt[38] = 60; /* ttl */
    pkt[39] = 0; pkt[40] = 4;
    pkt[41] = 93; pkt[42] = 184; pkt[43] = 216; pkt[44] = 34;

    off = 29;
    CHECK(dns_name_decode(pkt, 45, &off, name, sizeof(name)) == 0);
    CHECK(strcmp(name, "example.com") == 0);
    CHECK(off == 31);

    CHECK(dns_message_parse(pkt, 45, 0x1234u, &msg) == DNS_MSG_OK);
    CHECK(msg.nanswer == 1);
    CHECK(msg.answer[0].kind == DNS_RDATA_A);
    CHECK(dns_rr_rdata_text(&msg.answer[0], text, sizeof(text)) == 0);
    CHECK(strcmp(text, "93.184.216.34") == 0);
    CHECK(msg.answer[0].ttl == 60u);
}

static void test_mixed_pointer(void)
{
    uint8_t pkt[64];
    char name[DNS_NAME_CAP];
    size_t off = 25;

    memset(pkt, 0, sizeof(pkt));
    pkt[12] = 7;
    memcpy(pkt + 13, "example", 7);
    pkt[20] = 3;
    memcpy(pkt + 21, "com", 3);
    pkt[24] = 0;
    pkt[25] = 3;
    memcpy(pkt + 26, "www", 3);
    pkt[29] = 0xC0;
    pkt[30] = 12;

    CHECK(dns_name_decode(pkt, 31, &off, name, sizeof(name)) == 0);
    CHECK(strcmp(name, "www.example.com") == 0);
    CHECK(off == 31);
}

static void test_pointer_loop(void)
{
    uint8_t pkt[16];
    char name[DNS_NAME_CAP];
    size_t off = 12;

    memset(pkt, 0, sizeof(pkt));
    pkt[12] = 0xC0;
    pkt[13] = 12;
    CHECK(dns_name_decode(pkt, 14, &off, name, sizeof(name)) != 0);
    CHECK(off == 12);
}

static void test_oob_and_bad_id(void)
{
    uint8_t pkt[12];
    struct dns_message msg;
    char name[8];
    size_t off = 0;

    memset(pkt, 0, sizeof(pkt));
    CHECK(dns_message_parse(pkt, 11, 0, &msg) == DNS_MSG_ERR_SHORT);
    pkt[0] = 20; /* label claims 20 bytes; packet is only 12 */
    CHECK(dns_name_decode(pkt, sizeof(pkt), &off, name, sizeof(name)) != 0);
    CHECK(off == 0u);

    put_hdr(pkt, 0, 0, 0);
    /* header only, but qdcount is 1 — truncated question */
    CHECK(dns_message_parse(pkt, 12, 0x1234u, &msg) == DNS_MSG_ERR_FORM);
    CHECK(dns_message_parse(pkt, 12, 0x0001u, &msg) == DNS_MSG_ERR_ID);
}

static void test_aaaa_mx_ns_txt_cname(void)
{
    uint8_t pkt[128];
    struct dns_message msg;
    char text[128];
    size_t at;

    memset(pkt, 0, sizeof(pkt));
    put_hdr(pkt, 1, 0, 0);
    pkt[12] = 3; memcpy(pkt + 13, "dns", 3);
    pkt[16] = 7; memcpy(pkt + 17, "example", 7);
    pkt[24] = 3; memcpy(pkt + 25, "com", 3);
    pkt[28] = 0;
    pkt[29] = 0; pkt[30] = 28; /* AAAA question */
    pkt[31] = 0; pkt[32] = 1;
    at = 33;
    pkt[at++] = 0xC0; pkt[at++] = 12;
    pkt[at++] = 0; pkt[at++] = 28;
    pkt[at++] = 0; pkt[at++] = 1;
    pkt[at++] = 0; pkt[at++] = 0; pkt[at++] = 0; pkt[at++] = 30;
    pkt[at++] = 0; pkt[at++] = 16;
    memset(pkt + at, 0, 16);
    pkt[at + 15] = 1;
    CHECK(dns_message_parse(pkt, at + 16, 0x1234u, &msg) == DNS_MSG_OK);
    CHECK(msg.answer[0].kind == DNS_RDATA_AAAA);
    CHECK(dns_rr_rdata_text(&msg.answer[0], text, sizeof(text)) == 0);
    CHECK(strstr(text, "1") != NULL);

    /* CNAME with pointer */
    memset(pkt, 0, sizeof(pkt));
    put_hdr(pkt, 1, 0, 0);
    pkt[12] = 3; memcpy(pkt + 13, "www", 3);
    pkt[16] = 7; memcpy(pkt + 17, "example", 7);
    pkt[24] = 3; memcpy(pkt + 25, "com", 3);
    pkt[28] = 0;
    pkt[29] = 0; pkt[30] = 5;
    pkt[31] = 0; pkt[32] = 1;
    pkt[33] = 0xC0; pkt[34] = 12;
    pkt[35] = 0; pkt[36] = 5;
    pkt[37] = 0; pkt[38] = 1;
    pkt[39] = 0; pkt[40] = 0; pkt[41] = 0; pkt[42] = 10;
    pkt[43] = 0; pkt[44] = 2;
    pkt[45] = 0xC0; pkt[46] = 16; /* pointer at example.com */
    CHECK(dns_message_parse(pkt, 47, 0x1234u, &msg) == DNS_MSG_OK);
    CHECK(msg.answer[0].kind == DNS_RDATA_NAME);
    CHECK(strcmp(msg.answer[0].target, "example.com") == 0);

    /* NS */
    pkt[36] = 2;
    pkt[30] = 2;
    CHECK(dns_message_parse(pkt, 47, 0x1234u, &msg) == DNS_MSG_OK);
    CHECK(msg.answer[0].type == DNS_QTYPE_NS);

    /* MX: preference 10 + pointer */
    memset(pkt, 0, sizeof(pkt));
    put_hdr(pkt, 1, 0, 0);
    pkt[12] = 7; memcpy(pkt + 13, "example", 7);
    pkt[20] = 3; memcpy(pkt + 21, "com", 3);
    pkt[24] = 0;
    pkt[25] = 0; pkt[26] = 15;
    pkt[27] = 0; pkt[28] = 1;
    pkt[29] = 0xC0; pkt[30] = 12;
    pkt[31] = 0; pkt[32] = 15;
    pkt[33] = 0; pkt[34] = 1;
    pkt[35] = 0; pkt[36] = 0; pkt[37] = 0; pkt[38] = 20;
    pkt[39] = 0; pkt[40] = 4; /* pref + pointer */
    pkt[41] = 0; pkt[42] = 10;
    pkt[43] = 0xC0; pkt[44] = 12;
    CHECK(dns_message_parse(pkt, 45, 0x1234u, &msg) == DNS_MSG_OK);
    CHECK(msg.answer[0].kind == DNS_RDATA_MX);
    CHECK(msg.answer[0].preference == 10u);
    CHECK(strcmp(msg.answer[0].target, "example.com") == 0);

    /* TXT */
    memset(pkt, 0, sizeof(pkt));
    put_hdr(pkt, 1, 0, 0);
    pkt[12] = 3; memcpy(pkt + 13, "txt", 3);
    pkt[16] = 0;
    pkt[17] = 0; pkt[18] = 16;
    pkt[19] = 0; pkt[20] = 1;
    pkt[21] = 0xC0; pkt[22] = 12;
    pkt[23] = 0; pkt[24] = 16;
    pkt[25] = 0; pkt[26] = 1;
    pkt[27] = 0; pkt[28] = 0; pkt[29] = 0; pkt[30] = 5;
    pkt[31] = 0; pkt[32] = 5;
    pkt[33] = 4; memcpy(pkt + 34, "hiya", 4);
    CHECK(dns_message_parse(pkt, 38, 0x1234u, &msg) == DNS_MSG_OK);
    CHECK(msg.answer[0].kind == DNS_RDATA_TXT);
    CHECK(strcmp(msg.answer[0].text, "hiya") == 0);
}

static void test_suffix_and_eq(void)
{
    CHECK(dns_name_eq("Example.COM", "example.com."));
    CHECK(!dns_name_eq("example.com", "example.org"));
    CHECK(dns_name_suffix("www.google.com", "com"));
    CHECK(dns_name_suffix("www.google.com", "google.com"));
    CHECK(!dns_name_suffix("google.com", "www.google.com"));
    CHECK(dns_name_suffix("google.com", "."));
}

int main(void)
{
    test_decode_plain();
    test_compression_pointer();
    test_mixed_pointer();
    test_pointer_loop();
    test_oob_and_bad_id();
    test_aaaa_mx_ns_txt_cname();
    test_suffix_and_eq();

    if (g_fail == 0) {
        printf("OK  %d/%d tests passed\n", g_pass, g_pass + g_fail);
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "FAIL  %d/%d tests failed\n", g_fail, g_pass + g_fail);
    return EXIT_FAILURE;
}
