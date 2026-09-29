#ifndef DNS_NAME_H
#define DNS_NAME_H

/*
 * dns_name.h — decode DNS wire names, including compression pointers.
 *
 * A name is a sequence of labels ending in a zero byte. A label whose top
 * two bits are 11 is a 14-bit pointer to an earlier offset in the same
 * message (RFC 1035 §4.1.4).
 */

#include <stddef.h>
#include <stdint.h>

#define DNS_NAME_CAP 254

/*
 * Decode the name at *cursor into out (presentation form, no trailing dot
 * except for the root name ".").
 * On success advances *cursor past the name's on-wire bytes (a pointer
 * counts as 2 bytes) and returns 0.
 * On failure leaves *cursor unchanged and returns -1.
 */
int dns_name_decode(const uint8_t *pkt, size_t pkt_len, size_t *cursor,
                    char *out, size_t out_cap);

/* Case-insensitive compare. A single trailing dot is ignored. */
int dns_name_eq(const char *a, const char *b);

/* 1 if zone is a DNS suffix of name ("com" matches "www.google.com"). */
int dns_name_suffix(const char *name, const char *zone);

#endif /* DNS_NAME_H */
