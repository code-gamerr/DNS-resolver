#ifndef DNS_QUERY_H
#define DNS_QUERY_H

/*
 * dns_query.h — build a complete standard DNS query packet (Phase 4)
 *
 * Layout:
 *   12-byte header | QNAME | QTYPE (2) | QCLASS (2)
 */

#include <stddef.h>
#include <stdint.h>

#define DNS_UDP_PAYLOAD_MAX 512

/*
 * Build a recursive query (RD=1) for name/qtype into buf.
 * *txid_out receives the generated transaction ID.
 * Returns packet length on success, negative on failure.
 */
int dns_query_build(uint8_t *buf, size_t cap, const char *name, uint16_t qtype,
                    uint16_t *txid_out);

/* Build with an explicit transaction ID (RD=1, for tests). */
int dns_query_build_with_id(uint8_t *buf, size_t cap, uint16_t txid,
                            const char *name, uint16_t qtype);

/* Same as dns_query_build_with_id, but RD is set only when rd is non-zero. */
int dns_query_build_ex(uint8_t *buf, size_t cap, uint16_t txid,
                       const char *name, uint16_t qtype, int rd);

/* Generate a 16-bit transaction ID. */
uint16_t dns_txid_generate(void);

#endif /* DNS_QUERY_H */
