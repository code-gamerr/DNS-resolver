#include "dns_cache.h"

#include "dns_name.h"

#include <string.h>

void dns_cache_init(struct dns_cache *cache)
{
    if (cache != NULL) {
        memset(cache, 0, sizeof(*cache));
    }
}

static struct dns_cache_entry *find_slot(struct dns_cache *cache,
                                         const char *name, uint16_t type,
                                         int *free_idx)
{
    int i;
    int free_at = -1;

    for (i = 0; i < DNS_CACHE_SLOTS; i++) {
        struct dns_cache_entry *e = &cache->slot[i];
        if (!e->used) {
            if (free_at < 0) {
                free_at = i;
            }
            continue;
        }
        if (e->type == type && dns_name_eq(e->name, name)) {
            if (free_idx != NULL) {
                *free_idx = i;
            }
            return e;
        }
    }
    if (free_idx != NULL) {
        *free_idx = free_at;
    }
    return NULL;
}

void dns_cache_store(struct dns_cache *cache, const char *name, uint16_t type,
                     const struct dns_rr *rr, int nrr, uint32_t ttl_sec,
                     uint64_t now_ms)
{
    struct dns_cache_entry *e;
    int idx = -1;
    int n;
    int i;

    if (cache == NULL || name == NULL || rr == NULL || nrr <= 0 ||
        ttl_sec == 0u) {
        return;
    }
    e = find_slot(cache, name, type, &idx);
    if (e == NULL) {
        if (idx < 0) {
            idx = 0; /* overwrite slot 0 when the table is full */
        }
        e = &cache->slot[idx];
        memset(e, 0, sizeof(*e));
    }
    n = nrr;
    if (n > DNS_CACHE_RR) {
        n = DNS_CACHE_RR;
    }
    memset(e, 0, sizeof(*e));
    e->used = 1;
    e->type = type;
    e->expires_ms = now_ms + (uint64_t)ttl_sec * 1000u;
    e->nrr = n;
    for (i = 0; i < n; i++) {
        e->rr[i] = rr[i];
    }
    strncpy(e->name, name, sizeof(e->name) - 1u);
    e->name[sizeof(e->name) - 1u] = '\0';
}

int dns_cache_lookup(struct dns_cache *cache, const char *name, uint16_t type,
                     uint64_t now_ms, struct dns_rr *out, int cap, int *nout)
{
    struct dns_cache_entry *e;
    int i;
    int n;

    if (nout != NULL) {
        *nout = 0;
    }
    if (cache == NULL || name == NULL || out == NULL || cap <= 0 ||
        nout == NULL) {
        return 0;
    }
    e = find_slot(cache, name, type, NULL);
    if (e == NULL) {
        return 0;
    }
    if (now_ms >= e->expires_ms) {
        e->used = 0;
        return 0;
    }
    n = e->nrr;
    if (n > cap) {
        n = cap;
    }
    for (i = 0; i < n; i++) {
        out[i] = e->rr[i];
    }
    *nout = n;
    return 1;
}
