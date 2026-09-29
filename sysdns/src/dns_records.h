#ifndef DNS_RECORDS_H
#define DNS_RECORDS_H

/*
 * dns_records.h — parse DNS questions and resource records.
 * Packet bytes are never cast to structs. Every read is bounds-checked.
 */

#include "dns.h"
#include "dns_name.h"

#include <stddef.h>
#include <stdint.h>

#define DNS_TXT_CAP 256
#define DNS_RR_CAP 12

enum dns_rdata_kind {
    DNS_RDATA_RAW = 0,
    DNS_RDATA_A = 1,
    DNS_RDATA_AAAA = 2,
    DNS_RDATA_NAME = 3,
    DNS_RDATA_MX = 4,
    DNS_RDATA_TXT = 5
};

struct dns_rr {
    char owner[DNS_NAME_CAP];
    uint16_t type;
    uint16_t rrclass;
    uint32_t ttl;
    uint16_t rdlength;
    int kind;
    uint8_t addr[16];
    char target[DNS_NAME_CAP];
    uint16_t preference;
    char text[DNS_TXT_CAP];
};

struct dns_message {
    struct dns_header hdr;
    uint16_t rcode;
    int authoritative;
    int truncated;
    int recursion_available;
    struct dns_rr question;
    int nquestion;
    struct dns_rr answer[DNS_RR_CAP];
    int nanswer;
    struct dns_rr authority[DNS_RR_CAP];
    int nauthority;
    struct dns_rr additional[DNS_RR_CAP];
    int nadditional;
};

enum dns_msg_err {
    DNS_MSG_OK = 0,
    DNS_MSG_ERR_ARGS = -1,
    DNS_MSG_ERR_SHORT = -2,
    DNS_MSG_ERR_ID = -3,
    DNS_MSG_ERR_QR = -4,
    DNS_MSG_ERR_FORM = -5
};

const char *dns_type_name(uint16_t type);
const char *dns_msg_strerror(int err);

/* Parse a response. RCODE is stored; a non-zero RCODE is still DNS_MSG_OK. */
int dns_message_parse(const uint8_t *pkt, size_t len, uint16_t expect_id,
                      struct dns_message *msg);

/* Presentation of RDATA. Returns 0 on success. */
int dns_rr_rdata_text(const struct dns_rr *rr, char *buf, size_t cap);

void dns_rr_print(const struct dns_rr *rr);
void dns_section_print(const char *title, const struct dns_rr *rrs, int n);
void dns_message_print(const struct dns_message *msg, int debug);

#endif /* DNS_RECORDS_H */
