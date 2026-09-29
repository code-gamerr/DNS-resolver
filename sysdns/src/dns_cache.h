#ifndef DNS_CACHE_H
#define DNS_CACHE_H

/*
 * dns_cache.h — process-local DNS cache.
 * Entries die with the process. Expired TTLs are never returned.
 */

#include "dns_records.h"

#include <stdint.h>

#define DNS_CACHE_SLOTS 32
#define DNS_CACHE_RR 8

struct dns_cache_entry {
    int used;
    char name[DNS_NAME_CAP];
    uint16_t type;
    uint64_t expires_ms;
    int nrr;
    struct dns_rr rr[DNS_CACHE_RR];
};

struct dns_cache {
    struct dns_cache_entry slot[DNS_CACHE_SLOTS];
};

void dns_cache_init(struct dns_cache *cache);

/* Stores a copy. ttl_sec == 0 is not stored. now_ms is caller-supplied. */
void dns_cache_store(struct dns_cache *cache, const char *name, uint16_t type,
                     const struct dns_rr *rr, int nrr, uint32_t ttl_sec,
                     uint64_t now_ms);

/* Returns 1 and copies records on a live hit, else 0. */
int dns_cache_lookup(struct dns_cache *cache, const char *name, uint16_t type,
                     uint64_t now_ms, struct dns_rr *out, int cap, int *nout);

#endif /* DNS_CACHE_H */
