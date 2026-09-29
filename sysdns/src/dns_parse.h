#ifndef DNS_PARSE_H
#define DNS_PARSE_H

/*
 * dns_parse.h — DNS response header validation (Phase 6)
 */

#include "dns.h"

#include <stddef.h>
#include <stdint.h>

enum dns_parse_err {
    DNS_PARSE_OK              = 0,
    DNS_PARSE_ERR_ARGS        = -1,
    DNS_PARSE_ERR_SHORT       = -2,
    DNS_PARSE_ERR_ID_MISMATCH = -3,
    DNS_PARSE_ERR_NOT_RESPONSE = -4,
    DNS_PARSE_ERR_OPCODE      = -5,
    DNS_PARSE_ERR_RCODE       = -6
};

struct dns_response_info {
    struct dns_header hdr;
    uint16_t rcode;
    int is_truncated;
    int is_authoritative;
    int recursion_available;
};

/* Extract RCODE (low 4 bits of flags). */
uint16_t dns_flags_rcode(uint16_t flags);

/* Human-readable RCODE name. */
const char *dns_rcode_name(uint16_t rcode);

/* Human-readable parse error. */
const char *dns_parse_strerror(int err);

/*
 * Parse and validate a DNS response header.
 * expected_id must match the transaction ID in the packet.
 * Returns DNS_PARSE_OK or a dns_parse_err code.
 * On RCODE errors, *out is still filled so the caller can print details.
 */
int dns_parse_response_header(const uint8_t *buf, size_t len,
                              uint16_t expected_id,
                              struct dns_response_info *out);

#endif /* DNS_PARSE_H */
