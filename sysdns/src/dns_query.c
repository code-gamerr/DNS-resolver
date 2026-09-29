#include "dns_query.h"

#include "dns.h"
#include "dns_encode.h"
#include "wire.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

uint16_t dns_txid_generate(void)
{
    static int seeded = 0;

    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    return (uint16_t)((unsigned int)rand() & 0xFFFFu);
}

int dns_query_build_ex(uint8_t *buf, size_t cap, uint16_t txid,
                       const char *name, uint16_t qtype, int rd)
{
    struct dns_header hdr;
    size_t off = 0;
    int woff;
    int n;

    if (buf == NULL || name == NULL || cap < DNS_HEADER_WIRE_SIZE) {
        return -1;
    }
    if (qtype == 0u) {
        return -2;
    }

    hdr.id = txid;
    hdr.flags = rd ? DNS_FLAG_RD : DNS_FLAG_QR_QUERY;
    hdr.qdcount = 1u;
    hdr.ancount = 0u;
    hdr.nscount = 0u;
    hdr.arcount = 0u;

    woff = dns_header_write(&hdr, buf, 0, cap);
    if (woff < 0) {
        return -3;
    }
    off = (size_t)woff;

    n = dns_encode_name(name, buf, &off, cap);
    if (n < 0) {
        return -4;
    }

    woff = wire_put_u16be(buf, (int)off, qtype, cap);
    if (woff < 0) {
        return -5;
    }
    off = (size_t)woff;

    woff = wire_put_u16be(buf, (int)off, DNS_QCLASS_IN, cap);
    if (woff < 0) {
        return -6;
    }

    return woff;
}

int dns_query_build_with_id(uint8_t *buf, size_t cap, uint16_t txid,
                            const char *name, uint16_t qtype)
{
    return dns_query_build_ex(buf, cap, txid, name, qtype, 1);
}

int dns_query_build(uint8_t *buf, size_t cap, const char *name, uint16_t qtype,
                    uint16_t *txid_out)
{
    uint16_t txid = dns_txid_generate();
    int n = dns_query_build_with_id(buf, cap, txid, name, qtype);

    if (n > 0 && txid_out != NULL) {
        *txid_out = txid;
    }
    return n;
}
