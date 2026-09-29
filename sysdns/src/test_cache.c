/*
 * test_cache.c — TTL cache hit, miss, and expiration.
 */

#include "dns_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) \
    do { \
        if (cond) { \
            g_pass++; \
        } else { \
            fprintf(stderr, "FAIL  %s:%d  " #cond "\n", __FILE__, __LINE__); \
            g_fail++; \
        } \
    } while (0)

static struct dns_rr sample(const char *owner, uint32_t ttl)
{
    struct dns_rr rr;
    memset(&rr, 0, sizeof(rr));
    strncpy(rr.owner, owner, sizeof(rr.owner) - 1u);
    rr.type = DNS_QTYPE_A;
    rr.ttl = ttl;
    rr.kind = DNS_RDATA_A;
    rr.addr[0] = 1;
    rr.addr[1] = 2;
    rr.addr[2] = 3;
    rr.addr[3] = 4;
    return rr;
}

int main(void)
{
    struct dns_cache cache;
    struct dns_rr rr;
    struct dns_rr out[4];
    int n = 0;

    dns_cache_init(&cache);
    rr = sample("example.com", 10);
    CHECK(dns_cache_lookup(&cache, "example.com", DNS_QTYPE_A, 1000, out, 4,
                           &n) == 0);

    dns_cache_store(&cache, "example.com", DNS_QTYPE_A, &rr, 1, 10, 1000);
    n = 0;
    CHECK(dns_cache_lookup(&cache, "Example.COM.", DNS_QTYPE_A, 1000, out, 4,
                           &n) == 1);
    CHECK(n == 1);
    CHECK(out[0].addr[3] == 4);

    /* Different type is a miss. */
    n = 0;
    CHECK(dns_cache_lookup(&cache, "example.com", DNS_QTYPE_AAAA, 1000, out, 4,
                           &n) == 0);

    /* Still valid one millisecond before expiry (ttl 10s => expires at 11000). */
    n = 0;
    CHECK(dns_cache_lookup(&cache, "example.com", DNS_QTYPE_A, 10999, out, 4,
                           &n) == 1);

    /* Expired records are not returned. */
    n = 0;
    CHECK(dns_cache_lookup(&cache, "example.com", DNS_QTYPE_A, 11000, out, 4,
                           &n) == 0);
    CHECK(dns_cache_lookup(&cache, "example.com", DNS_QTYPE_A, 12000, out, 4,
                           &n) == 0);

    /* ttl 0 is not stored. */
    dns_cache_store(&cache, "zero.test", DNS_QTYPE_A, &rr, 1, 0, 1000);
    CHECK(dns_cache_lookup(&cache, "zero.test", DNS_QTYPE_A, 1000, out, 4,
                           &n) == 0);

    if (g_fail == 0) {
        printf("OK  %d/%d tests passed\n", g_pass, g_pass + g_fail);
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "FAIL  %d/%d tests failed\n", g_fail, g_pass + g_fail);
    return EXIT_FAILURE;
}
