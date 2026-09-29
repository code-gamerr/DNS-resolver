#include "dns_socket.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
   typedef SOCKET dns_sock_t;
#  define DNS_INVALID_SOCK INVALID_SOCKET
#  define dns_close_sock(s) closesocket(s)
#else
#  include <arpa/inet.h>
#  include <errno.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <unistd.h>
   typedef int dns_sock_t;
#  define DNS_INVALID_SOCK (-1)
#  define dns_close_sock(s) close(s)
#endif

const char *dns_socket_strerror(int err)
{
    switch (err) {
    case DNS_SOCK_OK:            return "ok";
    case DNS_SOCK_ERR_ARGS:      return "invalid arguments";
    case DNS_SOCK_ERR_INIT:      return "socket subsystem init failed";
    case DNS_SOCK_ERR_SOCKET:    return "socket() failed";
    case DNS_SOCK_ERR_ADDR:      return "invalid IPv4 address";
    case DNS_SOCK_ERR_SEND:      return "sendto() failed";
    case DNS_SOCK_ERR_TIMEOUT:   return "receive timeout";
    case DNS_SOCK_ERR_RECV:      return "recvfrom() failed";
    case DNS_SOCK_ERR_TOO_SMALL: return "response buffer too small";
    default:                     return "unknown socket error";
    }
}

static int ipv4_is_dotted(const char *ip)
{
    unsigned a = 0;
    unsigned b = 0;
    unsigned c = 0;
    unsigned d = 0;
    char tail = '\0';

    if (ip == NULL) {
        return 0;
    }
    /* Strict dotted-quad only — no DNS lookups. */
    if (sscanf(ip, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4) {
        return 0;
    }
    if (a > 255u || b > 255u || c > 255u || d > 255u) {
        return 0;
    }
    return 1;
}

int dns_endpoint_set_ipv4(struct dns_endpoint *ep, const char *ip,
                          uint16_t port)
{
    if (ep == NULL || ip == NULL || port == 0u) {
        return DNS_SOCK_ERR_ARGS;
    }
    if (!ipv4_is_dotted(ip)) {
        return DNS_SOCK_ERR_ADDR;
    }
    if (strlen(ip) >= sizeof(ep->ip)) {
        return DNS_SOCK_ERR_ADDR;
    }
    memset(ep, 0, sizeof(*ep));
    memcpy(ep->ip, ip, strlen(ip) + 1u);
    ep->port = port;
    return DNS_SOCK_OK;
}

static int socket_startup(void)
{
#ifdef _WIN32
    static int ready = 0;
    WSADATA wsa;

    if (ready) {
        return 0;
    }
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return -1;
    }
    ready = 1;
#endif
    return 0;
}

static int set_recv_timeout(dns_sock_t fd, int timeout_ms)
{
#ifdef _WIN32
    DWORD ms;

    if (timeout_ms < 0) {
        timeout_ms = 0;
    }
    ms = (DWORD)timeout_ms;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms,
                   (int)sizeof(ms)) != 0) {
        return -1;
    }
#else
    struct timeval tv;

    if (timeout_ms < 0) {
        timeout_ms = 0;
    }
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        return -1;
    }
#endif
    return 0;
}

int dns_udp_exchange(const struct dns_endpoint *server,
                     const uint8_t *query, size_t query_len,
                     uint8_t *resp, size_t resp_cap, int timeout_ms)
{
    dns_sock_t fd;
    struct sockaddr_in dest;
    int nsent;
    int nrecv;

    if (server == NULL || query == NULL || resp == NULL ||
        query_len == 0u || resp_cap == 0u) {
        return DNS_SOCK_ERR_ARGS;
    }
    if (socket_startup() != 0) {
        return DNS_SOCK_ERR_INIT;
    }

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == DNS_INVALID_SOCK) {
        return DNS_SOCK_ERR_SOCKET;
    }

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(server->port);
    if (inet_pton(AF_INET, server->ip, &dest.sin_addr) != 1) {
        dns_close_sock(fd);
        return DNS_SOCK_ERR_ADDR;
    }

    if (set_recv_timeout(fd, timeout_ms) != 0) {
        dns_close_sock(fd);
        return DNS_SOCK_ERR_INIT;
    }

#ifdef _WIN32
    nsent = sendto(fd, (const char *)query, (int)query_len, 0,
                   (const struct sockaddr *)&dest, (int)sizeof(dest));
#else
    nsent = (int)sendto(fd, query, query_len, 0,
                        (const struct sockaddr *)&dest, sizeof(dest));
#endif
    if (nsent < 0 || (size_t)nsent != query_len) {
        dns_close_sock(fd);
        return DNS_SOCK_ERR_SEND;
    }

#ifdef _WIN32
    nrecv = recvfrom(fd, (char *)resp, (int)resp_cap, 0, NULL, NULL);
    if (nrecv == SOCKET_ERROR) {
        int werr = WSAGetLastError();
        dns_close_sock(fd);
        if (werr == WSAETIMEDOUT || werr == WSAEWOULDBLOCK) {
            return DNS_SOCK_ERR_TIMEOUT;
        }
        return DNS_SOCK_ERR_RECV;
    }
#else
    nrecv = (int)recvfrom(fd, resp, resp_cap, 0, NULL, NULL);
    if (nrecv < 0) {
        int e = errno;
        dns_close_sock(fd);
        if (e == EAGAIN || e == EWOULDBLOCK) {
            return DNS_SOCK_ERR_TIMEOUT;
        }
        return DNS_SOCK_ERR_RECV;
    }
#endif

    dns_close_sock(fd);
    if (nrecv == 0) {
        return DNS_SOCK_ERR_RECV;
    }
    return nrecv;
}
