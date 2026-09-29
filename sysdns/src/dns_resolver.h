#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

/*
 * dns_resolver.h — forward a query to one DNS server with retries.
 */

#include "dns_query.h"
#include "dns_records.h"
#include "dns_socket.h"

#include <stddef.h>
#include <stdint.h>

struct dns_result {
    char qname[DNS_NAME_CAP];
    uint16_t qtype;
    uint16_t rcode;
    struct dns_rr answer[DNS_RR_CAP];
    int nanswer;
    struct dns_message msg;
    uint8_t query[DNS_UDP_PAYLOAD_MAX];
    size_t query_len;
    uint8_t response[DNS_UDP_PAYLOAD_MAX];
    size_t response_len;
    int elapsed_ms;
    int from_cache;
};

uint64_t dns_now_ms(void);

/*
 * One nameserver, with retries. rd selects the recursion-desired bit.
 * Returns DNS_MSG_OK when a packet was parsed. Socket errors are negative.
 */
int dns_query_server(const struct dns_endpoint *server, const char *name,
                     uint16_t qtype, int rd, int timeout_ms, int attempts,
                     int debug, struct dns_message *msg, uint8_t *query,
                     size_t *query_len, uint8_t *response, size_t *response_len);

/*
 * Ask one recursive resolver (RD=1). attempts is the number of tries.
 * Returns 0 when a response was parsed (check rcode). Negative on I/O failure.
 */
int dns_forward_lookup(const struct dns_endpoint *server, const char *name,
                       uint16_t qtype, int timeout_ms, int attempts, int debug,
                       struct dns_result *out);

/* Minimum TTL of the given records, or 0 if there are none. */
uint32_t dns_rr_min_ttl(const struct dns_rr *rr, int n);

#endif /* DNS_RESOLVER_H */
