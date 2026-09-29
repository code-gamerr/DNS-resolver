#ifndef DNS_ENCODE_H
#define DNS_ENCODE_H

/*
 * dns_encode.h — DNS domain-name wire encoding (Phase 3)
 *
 * Converts a presentation-form name such as "example.com" into the
 * length-prefixed DNS wire format:
 *
 *   07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 03 'c' 'o' 'm' 00
 *
 * Rules (RFC 1035):
 *   - each label is at most DNS_LABEL_MAX octets
 *   - the complete encoded name is at most DNS_NAME_WIRE_MAX octets
 *   - the name is terminated by a zero-length label (0x00)
 */

#include <stddef.h>
#include <stdint.h>

#define DNS_LABEL_MAX      63
#define DNS_NAME_WIRE_MAX  255

/* Error codes returned by dns_encode_name() (negative). */
enum dns_encode_err {
    DNS_ENCODE_OK            =  0,
    DNS_ENCODE_ERR_NULL      = -1,
    DNS_ENCODE_ERR_EMPTY     = -2,
    DNS_ENCODE_ERR_LABEL_LEN = -3,
    DNS_ENCODE_ERR_EMPTY_LABEL = -4,
    DNS_ENCODE_ERR_TOTAL_LEN = -5,
    DNS_ENCODE_ERR_OVERFLOW  = -6,
    DNS_ENCODE_ERR_CHAR      = -7,
    DNS_ENCODE_ERR_HYPHEN    = -8
};

/*
 * Encode presentation-form name into buf starting at *off.
 * On success: advances *off, returns the number of bytes written (> 0).
 * On failure: leaves *off unchanged, returns a dns_encode_err value (< 0).
 *
 * A trailing '.' (FQDN form) is accepted and stripped.
 */
int dns_encode_name(const char *name, uint8_t *buf, size_t *off, size_t cap);

/* Human-readable description of a dns_encode_err code. */
const char *dns_encode_strerror(int err);

#endif /* DNS_ENCODE_H */
