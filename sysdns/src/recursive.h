#ifndef RECURSIVE_H
#define RECURSIVE_H

/*
 * recursive.h — iterative resolution from a root hint.
 * Follows referrals and glue. Does not call getaddrinfo().
 */

#include "dns_cache.h"
#include "dns_resolver.h"

/*
 * Resolve name/qtype starting at root_ip (an IPv4 root or other hint).
 * use_cache reads and writes the process-local cache.
 * Returns 0 when a response was obtained (check out->rcode).
 */
int dns_recursive_lookup(const char *root_ip, const char *name, uint16_t qtype,
                         int timeout_ms, int attempts, int debug, int use_cache,
                         struct dns_cache *cache, struct dns_result *out);

#endif /* RECURSIVE_H */
