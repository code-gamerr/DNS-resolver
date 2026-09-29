#include "dns_name.h"

#include "dns_query.h" /* DNS_UDP_PAYLOAD_MAX */

#include <stdint.h>
#include <string.h>

static int fold(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (int)(c - 'A' + 'a');
    }
    return (int)c;
}

static size_t copy_strip_dot(const char *s, char *dst, size_t cap)
{
    size_t n;

    if (s == NULL) {
        s = "";
    }
    n = strlen(s);
    if (n > 0u && s[n - 1u] == '.') {
        n--;
    }
    if (n >= cap) {
        n = cap - 1u;
    }
    memcpy(dst, s, n);
    dst[n] = '\0';
    return n;
}

int dns_name_eq(const char *a, const char *b)
{
    char aa[DNS_NAME_CAP];
    char bb[DNS_NAME_CAP];
    size_t i;
    size_t na;
    size_t nb;

    na = copy_strip_dot(a, aa, sizeof(aa));
    nb = copy_strip_dot(b, bb, sizeof(bb));
    if (na != nb) {
        return 0;
    }
    for (i = 0; i < na; i++) {
        if (fold((unsigned char)aa[i]) != fold((unsigned char)bb[i])) {
            return 0;
        }
    }
    return 1;
}

int dns_name_suffix(const char *name, const char *zone)
{
    char nbuf[DNS_NAME_CAP];
    char zbuf[DNS_NAME_CAP];
    size_t ln;
    size_t lz;

    ln = copy_strip_dot(name, nbuf, sizeof(nbuf));
    lz = copy_strip_dot(zone, zbuf, sizeof(zbuf));
    if (lz == 0u) {
        return 1; /* root */
    }
    if (lz > ln) {
        return 0;
    }
    if (lz == ln) {
        return dns_name_eq(nbuf, zbuf);
    }
    if (nbuf[ln - lz - 1u] != '.') {
        return 0;
    }
    return dns_name_eq(nbuf + (ln - lz), zbuf);
}

int dns_name_decode(const uint8_t *pkt, size_t pkt_len, size_t *cursor,
                    char *out, size_t out_cap)
{
    size_t pos;
    size_t end_at = 0;
    size_t out_len = 0;
    int jumped = 0;
    int hops = 0;
    uint8_t seen[DNS_UDP_PAYLOAD_MAX];

    if (pkt == NULL || cursor == NULL || out == NULL || out_cap == 0u) {
        return -1;
    }
    if (pkt_len == 0u || pkt_len > DNS_UDP_PAYLOAD_MAX || *cursor >= pkt_len) {
        return -1;
    }

    memset(seen, 0, pkt_len);
    pos = *cursor;

    for (;;) {
        uint8_t lab;

        if (pos >= pkt_len || seen[pos] != 0u) {
            return -1;
        }
        seen[pos] = 1u;
        lab = pkt[pos];

        if (lab == 0u) {
            if (!jumped) {
                end_at = pos + 1u;
            }
            if (out_len == 0u) {
                if (out_cap < 2u) {
                    return -1;
                }
                out[0] = '.';
                out[1] = '\0';
            } else {
                if (out_len >= out_cap) {
                    return -1;
                }
                out[out_len] = '\0';
            }
            *cursor = end_at;
            return 0;
        }

        if ((lab & 0xC0u) == 0xC0u) {
            size_t ptr;

            if (pos + 1u >= pkt_len) {
                return -1;
            }
            ptr = ((size_t)(lab & 0x3Fu) << 8) | (size_t)pkt[pos + 1u];
            if (ptr >= pkt_len) {
                return -1;
            }
            if (!jumped) {
                end_at = pos + 2u;
                jumped = 1;
            }
            if (++hops > 16) {
                return -1;
            }
            pos = ptr;
            continue;
        }

        if ((lab & 0xC0u) != 0u || lab > 63u) {
            return -1;
        }
        if (pos + 1u + (size_t)lab > pkt_len) {
            return -1;
        }
        if (out_len > 0u) {
            if (out_len + 1u >= out_cap) {
                return -1;
            }
            out[out_len++] = '.';
        }
        if (out_len + (size_t)lab >= out_cap) {
            return -1;
        }
        memcpy(out + out_len, pkt + pos + 1u, (size_t)lab);
        out_len += (size_t)lab;
        pos += 1u + (size_t)lab;
    }
}
