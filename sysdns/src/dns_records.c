#include "dns_records.h"

#include "dns_parse.h"
#include "wire.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#endif

const char *dns_type_name(uint16_t type)
{
    switch (type) {
    case DNS_QTYPE_A:     return "A";
    case DNS_QTYPE_NS:    return "NS";
    case DNS_QTYPE_CNAME: return "CNAME";
    case DNS_QTYPE_MX:    return "MX";
    case DNS_QTYPE_TXT:   return "TXT";
    case DNS_QTYPE_AAAA:  return "AAAA";
    default:              return "TYPE";
    }
}

const char *dns_msg_strerror(int err)
{
    switch (err) {
    case DNS_MSG_OK:        return "ok";
    case DNS_MSG_ERR_ARGS:  return "invalid arguments";
    case DNS_MSG_ERR_SHORT: return "truncated packet";
    case DNS_MSG_ERR_ID:    return "transaction ID mismatch";
    case DNS_MSG_ERR_QR:    return "QR bit is not a response";
    case DNS_MSG_ERR_FORM:  return "malformed resource record";
    default:                return "unknown message error";
    }
}

static int parse_one(const uint8_t *pkt, size_t len, size_t *off,
                     struct dns_rr *rr, int question)
{
    size_t rdata_at;
    size_t rdata_end;
    uint16_t rdlen = 0;
    uint16_t typ = 0;
    uint16_t cls = 0;
    uint32_t ttl = 0;

    memset(rr, 0, sizeof(*rr));
    if (dns_name_decode(pkt, len, off, rr->owner, sizeof(rr->owner)) != 0) {
        return -1;
    }
    if (!wire_read_u16be(pkt, len, off, &typ) ||
        !wire_read_u16be(pkt, len, off, &cls)) {
        return -1;
    }
    rr->type = typ;
    rr->rrclass = cls;
    if (question) {
        return 0;
    }
    if (!wire_read_u32be(pkt, len, off, &ttl) ||
        !wire_read_u16be(pkt, len, off, &rdlen)) {
        return -1;
    }
    rr->ttl = ttl;
    rr->rdlength = rdlen;
    rdata_at = *off;
    if (rdlen > len || rdata_at > len - (size_t)rdlen) {
        return -1;
    }
    rdata_end = rdata_at + (size_t)rdlen;

    if (typ == DNS_QTYPE_A && rdlen == 4u) {
        memcpy(rr->addr, pkt + rdata_at, 4u);
        rr->kind = DNS_RDATA_A;
        *off = rdata_end;
        return 0;
    }
    if (typ == DNS_QTYPE_AAAA && rdlen == 16u) {
        memcpy(rr->addr, pkt + rdata_at, 16u);
        rr->kind = DNS_RDATA_AAAA;
        *off = rdata_end;
        return 0;
    }
    if (typ == DNS_QTYPE_CNAME || typ == DNS_QTYPE_NS) {
        size_t name_off = rdata_at;
        if (dns_name_decode(pkt, len, &name_off, rr->target,
                            sizeof(rr->target)) != 0 ||
            name_off != rdata_end) {
            return -1;
        }
        rr->kind = DNS_RDATA_NAME;
        *off = rdata_end;
        return 0;
    }
    if (typ == DNS_QTYPE_MX) {
        size_t name_off;
        uint16_t pref = 0;
        if (rdlen < 3u ||
            !wire_read_u16be(pkt, len, off, &pref)) {
            return -1;
        }
        rr->preference = pref;
        name_off = *off;
        if (dns_name_decode(pkt, len, &name_off, rr->target,
                            sizeof(rr->target)) != 0 ||
            name_off != rdata_end) {
            return -1;
        }
        rr->kind = DNS_RDATA_MX;
        *off = rdata_end;
        return 0;
    }
    if (typ == DNS_QTYPE_TXT) {
        size_t pos = rdata_at;
        size_t out = 0;
        while (pos < rdata_end) {
            uint8_t n = pkt[pos++];
            size_t k;
            if ((size_t)n > rdata_end - pos) {
                return -1;
            }
            for (k = 0; k < (size_t)n && out + 1u < sizeof(rr->text); k++) {
                unsigned char c = pkt[pos + k];
                rr->text[out++] = (c >= 32u && c < 127u) ? (char)c : '.';
            }
            pos += (size_t)n;
        }
        rr->text[out] = '\0';
        rr->kind = DNS_RDATA_TXT;
        *off = rdata_end;
        return 0;
    }

    rr->kind = DNS_RDATA_RAW;
    *off = rdata_end;
    return 0;
}

static int parse_section(const uint8_t *pkt, size_t len, size_t *off,
                         uint16_t count, struct dns_rr *dst, int cap,
                         int *stored, int question)
{
    uint16_t i;
    int n = 0;

    for (i = 0; i < count; i++) {
        struct dns_rr rr;
        if (parse_one(pkt, len, off, &rr, question) != 0) {
            return -1;
        }
        if (n < cap) {
            dst[n++] = rr;
        }
    }
    *stored = n;
    return 0;
}

int dns_message_parse(const uint8_t *pkt, size_t len, uint16_t expect_id,
                      struct dns_message *msg)
{
    size_t off = 0;

    if (pkt == NULL || msg == NULL) {
        return DNS_MSG_ERR_ARGS;
    }
    memset(msg, 0, sizeof(*msg));
    if (len < DNS_HEADER_WIRE_SIZE) {
        return DNS_MSG_ERR_SHORT;
    }
    if (dns_header_read(pkt, len, &off, &msg->hdr) != 0) {
        return DNS_MSG_ERR_SHORT;
    }
    if (msg->hdr.id != expect_id) {
        return DNS_MSG_ERR_ID;
    }
    if ((msg->hdr.flags & DNS_FLAG_QR_RESPONSE) == 0u) {
        return DNS_MSG_ERR_QR;
    }
    msg->rcode = (uint16_t)(msg->hdr.flags & 0x000Fu);
    msg->authoritative = (msg->hdr.flags & DNS_FLAG_AA) != 0;
    msg->truncated = (msg->hdr.flags & DNS_FLAG_TC) != 0;
    msg->recursion_available = (msg->hdr.flags & DNS_FLAG_RA) != 0;

    if (parse_section(pkt, len, &off, msg->hdr.qdcount, &msg->question, 1,
                      &msg->nquestion, 1) != 0 ||
        parse_section(pkt, len, &off, msg->hdr.ancount, msg->answer,
                      DNS_RR_CAP, &msg->nanswer, 0) != 0 ||
        parse_section(pkt, len, &off, msg->hdr.nscount, msg->authority,
                      DNS_RR_CAP, &msg->nauthority, 0) != 0 ||
        parse_section(pkt, len, &off, msg->hdr.arcount, msg->additional,
                      DNS_RR_CAP, &msg->nadditional, 0) != 0) {
        return DNS_MSG_ERR_FORM;
    }
    return DNS_MSG_OK;
}

int dns_rr_rdata_text(const struct dns_rr *rr, char *buf, size_t cap)
{
    if (rr == NULL || buf == NULL || cap == 0u) {
        return -1;
    }
    buf[0] = '\0';
    switch (rr->kind) {
    case DNS_RDATA_A: {
        struct in_addr a;
        memcpy(&a, rr->addr, 4u);
#ifdef _WIN32
        if (inet_ntop(AF_INET, &a, buf, cap) == NULL) {
            return -1;
        }
#else
        if (cap > 65535u ||
            inet_ntop(AF_INET, &a, buf, (socklen_t)cap) == NULL) {
            return -1;
        }
#endif
        return 0;
    }
    case DNS_RDATA_AAAA: {
        struct in6_addr a;
        memcpy(&a, rr->addr, 16u);
#ifdef _WIN32
        if (inet_ntop(AF_INET6, &a, buf, cap) == NULL) {
            return -1;
        }
#else
        if (cap > 65535u ||
            inet_ntop(AF_INET6, &a, buf, (socklen_t)cap) == NULL) {
            return -1;
        }
#endif
        return 0;
    }
    case DNS_RDATA_NAME:
        snprintf(buf, cap, "%s", rr->target);
        return 0;
    case DNS_RDATA_MX:
        snprintf(buf, cap, "%u %s", (unsigned)rr->preference, rr->target);
        return 0;
    case DNS_RDATA_TXT:
        snprintf(buf, cap, "\"%s\"", rr->text);
        return 0;
    default:
        snprintf(buf, cap, "\\# %u", (unsigned)rr->rdlength);
        return 0;
    }
}

static void print_owner(const char *owner)
{
    if (owner[0] == '.' && owner[1] == '\0') {
        fputs(".", stdout);
        return;
    }
    fputs(owner, stdout);
    if (owner[0] != '\0' && owner[strlen(owner) - 1u] != '.') {
        fputc('.', stdout);
    }
}

void dns_rr_print(const struct dns_rr *rr)
{
    char data[512];

    if (rr == NULL) {
        return;
    }
    print_owner(rr->owner);
    if (dns_rr_rdata_text(rr, data, sizeof(data)) != 0) {
        snprintf(data, sizeof(data), "?");
    }
    printf("\t%u\t%s\t%s\n", (unsigned)rr->ttl, dns_type_name(rr->type), data);
}

void dns_section_print(const char *title, const struct dns_rr *rrs, int n)
{
    int i;

    if (n <= 0) {
        return;
    }
    printf("\n%s\n\n", title);
    for (i = 0; i < n; i++) {
        fputs("    ", stdout);
        dns_rr_print(&rrs[i]);
    }
}

void dns_message_print(const struct dns_message *msg, int debug)
{
    if (msg == NULL) {
        return;
    }
    if (debug) {
        puts("DNS HEADER");
        printf("  id=0x%04x rcode=%s qd=%u an=%u ns=%u ar=%u aa=%d tc=%d ra=%d\n",
               msg->hdr.id, dns_rcode_name(msg->rcode),
               (unsigned)msg->hdr.qdcount, (unsigned)msg->hdr.ancount,
               (unsigned)msg->hdr.nscount, (unsigned)msg->hdr.arcount,
               msg->authoritative, msg->truncated, msg->recursion_available);
        if (msg->nquestion > 0) {
            printf("QUESTION\n  %s %s\n", msg->question.owner,
                   dns_type_name(msg->question.type));
        }
        dns_section_print("AUTHORITY", msg->authority, msg->nauthority);
        dns_section_print("ADDITIONAL", msg->additional, msg->nadditional);
        return;
    }
    dns_section_print("ANSWER", msg->answer, msg->nanswer);
}
