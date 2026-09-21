#include "dns.h"
#include "wire.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int dns_header_write(const struct dns_header *hdr, uint8_t *buf, int off,
                     size_t cap)
{
    if (hdr == NULL || buf == NULL) {
        return -1;
    }
    off = wire_put_u16be(buf, off, hdr->id,      cap); if (off < 0) return -1;
    off = wire_put_u16be(buf, off, hdr->flags,   cap); if (off < 0) return -1;
    off = wire_put_u16be(buf, off, hdr->qdcount, cap); if (off < 0) return -1;
    off = wire_put_u16be(buf, off, hdr->ancount, cap); if (off < 0) return -1;
    off = wire_put_u16be(buf, off, hdr->nscount, cap); if (off < 0) return -1;
    off = wire_put_u16be(buf, off, hdr->arcount, cap); if (off < 0) return -1;
    return off;
}

int dns_header_read(const uint8_t *buf, size_t len, size_t *off,
                    struct dns_header *hdr)
{
    struct dns_header parsed;
    size_t pos;

    if (buf == NULL || off == NULL || hdr == NULL) {
        return -1;
    }
    pos = *off;
    if (!wire_read_u16be(buf, len, &pos, &parsed.id) ||
        !wire_read_u16be(buf, len, &pos, &parsed.flags) ||
        !wire_read_u16be(buf, len, &pos, &parsed.qdcount) ||
        !wire_read_u16be(buf, len, &pos, &parsed.ancount) ||
        !wire_read_u16be(buf, len, &pos, &parsed.nscount) ||
        !wire_read_u16be(buf, len, &pos, &parsed.arcount)) {
        return -1;
    }

    *hdr = parsed;
    *off = pos;
    return 0;
}

uint16_t dns_qtype_from_str(const char *s)
{
    /* ponytail: flat table — no deps, trivially fast for 6 entries */
    static const struct { const char *name; uint16_t val; } k_types[] = {
        {"A",     DNS_QTYPE_A    },
        {"NS",    DNS_QTYPE_NS   },
        {"CNAME", DNS_QTYPE_CNAME},
        {"MX",    DNS_QTYPE_MX   },
        {"TXT",   DNS_QTYPE_TXT  },
        {"AAAA",  DNS_QTYPE_AAAA },
    };
    size_t i;

    if (s == NULL) {
        return 0;
    }
    for (i = 0; i < sizeof(k_types) / sizeof(k_types[0]); i++) {
        if (strcmp(s, k_types[i].name) == 0) {
            return k_types[i].val;
        }
    }
    return 0;
}
