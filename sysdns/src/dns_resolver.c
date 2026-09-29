#include "dns_resolver.h"

#include "dns_parse.h"
#include "dns_query.h"
#include "hexdump.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <time.h>
#endif

uint64_t dns_now_ms(void)
{
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

uint32_t dns_rr_min_ttl(const struct dns_rr *rr, int n)
{
    uint32_t min = 0;
    int i;

    if (rr == NULL || n <= 0) {
        return 0;
    }
    min = rr[0].ttl;
    for (i = 1; i < n; i++) {
        if (rr[i].ttl < min) {
            min = rr[i].ttl;
        }
    }
    if (min > 604800u) {
        min = 604800u; /* cap at 7 days */
    }
    return min;
}

int dns_query_server(const struct dns_endpoint *server, const char *name,
                     uint16_t qtype, int rd, int timeout_ms, int attempts,
                     int debug, struct dns_message *msg, uint8_t *query,
                     size_t *query_len, uint8_t *response, size_t *response_len)
{
    int try_n;

    if (server == NULL || name == NULL || msg == NULL || query == NULL ||
        query_len == NULL || response == NULL || response_len == NULL ||
        attempts < 1) {
        return DNS_MSG_ERR_ARGS;
    }

    for (try_n = 0; try_n < attempts; try_n++) {
        uint16_t txid = dns_txid_generate();
        int qlen;
        int rlen;
        int prc;

        qlen = dns_query_build_ex(query, DNS_UDP_PAYLOAD_MAX, txid, name,
                                  qtype, rd);
        if (qlen < 0) {
            return qlen;
        }
        *query_len = (size_t)qlen;
        if (debug) {
            printf("QUERY %s %s @ %s txid=0x%04x (try %d)\n", name,
                   dns_type_name(qtype), server->ip, txid, try_n + 1);
            hexdump_print(stdout, query, *query_len);
        }

        rlen = dns_udp_exchange(server, query, *query_len, response,
                                DNS_UDP_PAYLOAD_MAX, timeout_ms);
        if (rlen == DNS_SOCK_ERR_TIMEOUT || rlen == DNS_SOCK_ERR_SEND ||
            rlen == DNS_SOCK_ERR_RECV) {
            if (debug) {
                fprintf(stderr, "attempt %d: %s\n", try_n + 1,
                        dns_socket_strerror(rlen));
            }
            if (try_n + 1 < attempts) {
                continue;
            }
            return rlen;
        }
        if (rlen < 0) {
            return rlen;
        }
        *response_len = (size_t)rlen;
        if (debug) {
            printf("RESPONSE %d bytes\n", rlen);
            hexdump_print(stdout, response, *response_len);
        }
        prc = dns_message_parse(response, *response_len, txid, msg);
        if (prc == DNS_MSG_ERR_ID && try_n + 1 < attempts) {
            if (debug) {
                fputs("attempt: transaction ID mismatch, retrying\n", stderr);
            }
            continue;
        }
        return prc;
    }
    return DNS_SOCK_ERR_TIMEOUT;
}

int dns_forward_lookup(const struct dns_endpoint *server, const char *name,
                       uint16_t qtype, int timeout_ms, int attempts, int debug,
                       struct dns_result *out)
{
    uint64_t t0;
    int rc;

    if (out == NULL) {
        return DNS_MSG_ERR_ARGS;
    }
    memset(out, 0, sizeof(*out));
    if (name != NULL) {
        strncpy(out->qname, name, sizeof(out->qname) - 1u);
    }
    out->qtype = qtype;
    t0 = dns_now_ms();
    rc = dns_query_server(server, name, qtype, 1, timeout_ms, attempts, debug,
                          &out->msg, out->query, &out->query_len, out->response,
                          &out->response_len);
    out->elapsed_ms = (int)(dns_now_ms() - t0);
    if (rc != DNS_MSG_OK) {
        return rc;
    }
    out->rcode = out->msg.rcode;
    out->nanswer = out->msg.nanswer;
    if (out->nanswer > DNS_RR_CAP) {
        out->nanswer = DNS_RR_CAP;
    }
    if (out->nanswer > 0) {
        memcpy(out->answer, out->msg.answer,
               (size_t)out->nanswer * sizeof(out->answer[0]));
    }
    if (out->msg.truncated) {
        fputs("warning: response marked truncated (TC)\n", stderr);
    }
    return DNS_MSG_OK;
}
