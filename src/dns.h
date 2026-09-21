#ifndef DNS_H
#define DNS_H

/*
 * dns.h — DNS wire-format constants and header structure (Phase 2)
 *
 * All multi-byte values are stored in HOST byte order inside the struct.
 * Use dns_header_write() to serialise to network (big-endian) byte order.
 */

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Header flags (RFC 1035 §4.1.1)                                     */
/* ------------------------------------------------------------------ */

/* Bit 15: QR — 0 = query, 1 = response */
#define DNS_FLAG_QR_QUERY    ((uint16_t)0x0000u)
#define DNS_FLAG_QR_RESPONSE ((uint16_t)0x8000u)

/* Bits 14-11: OPCODE — standard query */
#define DNS_FLAG_OPCODE_QUERY ((uint16_t)0x0000u)

/* Bit 10: AA — Authoritative Answer */
#define DNS_FLAG_AA ((uint16_t)0x0400u)

/* Bit 9: TC — TrunCated */
#define DNS_FLAG_TC ((uint16_t)0x0200u)

/* Bit 8: RD — Recursion Desired */
#define DNS_FLAG_RD ((uint16_t)0x0100u)

/* Bit 7: RA — Recursion Available (set by server) */
#define DNS_FLAG_RA ((uint16_t)0x0080u)

/* Bits 3-0: RCODE — response code */
#define DNS_FLAG_RCODE_OK     ((uint16_t)0x0000u)
#define DNS_FLAG_RCODE_NXDOMAIN ((uint16_t)0x0003u)

/* ------------------------------------------------------------------ */
/* QTYPE values (RFC 1035 §3.2.2 + RFC 3596)                          */
/* ------------------------------------------------------------------ */
#define DNS_QTYPE_A     ((uint16_t)1u)
#define DNS_QTYPE_NS    ((uint16_t)2u)
#define DNS_QTYPE_CNAME ((uint16_t)5u)
#define DNS_QTYPE_MX    ((uint16_t)15u)
#define DNS_QTYPE_TXT   ((uint16_t)16u)
#define DNS_QTYPE_AAAA  ((uint16_t)28u)

/* ------------------------------------------------------------------ */
/* QCLASS values                                                       */
/* ------------------------------------------------------------------ */
#define DNS_QCLASS_IN ((uint16_t)1u)

/* ------------------------------------------------------------------ */
/* Header structure (always 12 bytes on the wire)                     */
/* ------------------------------------------------------------------ */
#define DNS_HEADER_WIRE_SIZE 12

struct dns_header {
    uint16_t id;      /* transaction ID               */
    uint16_t flags;   /* flags word (host byte order) */
    uint16_t qdcount; /* number of questions          */
    uint16_t ancount; /* number of answers            */
    uint16_t nscount; /* number of authority RRs      */
    uint16_t arcount; /* number of additional RRs     */
};

/*
 * Serialise *hdr into buf starting at byte offset off.
 * Returns new offset (off + 12) on success, or -1 on buffer overflow.
 */
int dns_header_write(const struct dns_header *hdr, uint8_t *buf, int off,
                     size_t cap);

/*
 * Parse a 12-byte header without casting network bytes to a C structure.
 * Advances *off only when the complete header is available.
 */
int dns_header_read(const uint8_t *buf, size_t len, size_t *off,
                    struct dns_header *hdr);

/*
 * Map a canonical type string (e.g. "A", "AAAA") to its QTYPE constant.
 * Returns 0 if the string is not recognised.
 */
uint16_t dns_qtype_from_str(const char *s);

#endif /* DNS_H */
