#ifndef DNS_SOCKET_H
#define DNS_SOCKET_H

/*
 * dns_socket.h — raw UDP DNS transport (Phase 5)
 *
 * Uses POSIX sockets on Linux and Winsock2 on Windows/MinGW.
 * Never uses getaddrinfo() for DNS resolution; server IPv4 is numeric only.
 */

#include <stddef.h>
#include <stdint.h>

#define DNS_DEFAULT_SERVER "8.8.8.8"
#define DNS_DEFAULT_PORT   53
#define DNS_DEFAULT_TIMEOUT_MS 3000

struct dns_endpoint {
    char ip[16]; /* dotted IPv4, e.g. "1.1.1.1" */
    uint16_t port;
};

/* Validate and copy a dotted IPv4 address into ep->ip. */
int dns_endpoint_set_ipv4(struct dns_endpoint *ep, const char *ip,
                          uint16_t port);

/*
 * Send query and wait for one UDP reply.
 * timeout_ms applies to the receive wait.
 * Returns response length on success, negative on failure.
 */
int dns_udp_exchange(const struct dns_endpoint *server,
                     const uint8_t *query, size_t query_len,
                     uint8_t *resp, size_t resp_cap, int timeout_ms);

const char *dns_socket_strerror(int err);

enum dns_socket_err {
    DNS_SOCK_OK            = 0,
    DNS_SOCK_ERR_ARGS      = -1,
    DNS_SOCK_ERR_INIT      = -2,
    DNS_SOCK_ERR_SOCKET    = -3,
    DNS_SOCK_ERR_ADDR      = -4,
    DNS_SOCK_ERR_SEND      = -5,
    DNS_SOCK_ERR_TIMEOUT   = -6,
    DNS_SOCK_ERR_RECV      = -7,
    DNS_SOCK_ERR_TOO_SMALL = -8
};

#endif /* DNS_SOCKET_H */
