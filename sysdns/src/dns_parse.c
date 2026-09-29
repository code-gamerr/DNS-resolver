#include "dns_parse.h"

#include "dns.h"
#include "wire.h"

#include <stddef.h>
#include <stdint.h>

uint16_t dns_flags_rcode(uint16_t flags)
{
    return (uint16_t)(flags & 0x000Fu);
}

const char *dns_rcode_name(uint16_t rcode)
{
    switch (rcode) {
    case 0:  return "NOERROR";
    case 1:  return "FORMERR";
    case 2:  return "SERVFAIL";
    case 3:  return "NXDOMAIN";
    case 4:  return "NOTIMP";
    case 5:  return "REFUSED";
    default: return "UNKNOWN";
    }
}

const char *dns_parse_strerror(int err)
{
    switch (err) {
    case DNS_PARSE_OK:               return "ok";
    case DNS_PARSE_ERR_ARGS:         return "invalid arguments";
    case DNS_PARSE_ERR_SHORT:        return "packet shorter than DNS header";
    case DNS_PARSE_ERR_ID_MISMATCH:  return "transaction ID mismatch";
    case DNS_PARSE_ERR_NOT_RESPONSE: return "QR bit indicates query, not response";
    case DNS_PARSE_ERR_OPCODE:       return "unsupported OPCODE";
    case DNS_PARSE_ERR_RCODE:        return "non-zero RCODE";
    default:                         return "unknown parse error";
    }
}

int dns_parse_response_header(const uint8_t *buf, size_t len,
                              uint16_t expected_id,
                              struct dns_response_info *out)
{
    struct dns_response_info info;
    size_t off = 0;
    uint16_t opcode;

    if (buf == NULL || out == NULL) {
        return DNS_PARSE_ERR_ARGS;
    }
    if (len < DNS_HEADER_WIRE_SIZE) {
        return DNS_PARSE_ERR_SHORT;
    }

    if (dns_header_read(buf, len, &off, &info.hdr) != 0) {
        return DNS_PARSE_ERR_SHORT;
    }

    info.rcode = dns_flags_rcode(info.hdr.flags);
    info.is_truncated = (info.hdr.flags & DNS_FLAG_TC) != 0;
    info.is_authoritative = (info.hdr.flags & DNS_FLAG_AA) != 0;
    info.recursion_available = (info.hdr.flags & DNS_FLAG_RA) != 0;
    *out = info;

    if (info.hdr.id != expected_id) {
        return DNS_PARSE_ERR_ID_MISMATCH;
    }
    if ((info.hdr.flags & DNS_FLAG_QR_RESPONSE) == 0u) {
        return DNS_PARSE_ERR_NOT_RESPONSE;
    }

    opcode = (uint16_t)((info.hdr.flags >> 11) & 0x0Fu);
    if (opcode != 0u) {
        return DNS_PARSE_ERR_OPCODE;
    }

    if (info.rcode != 0u) {
        return DNS_PARSE_ERR_RCODE;
    }

    return DNS_PARSE_OK;
}
