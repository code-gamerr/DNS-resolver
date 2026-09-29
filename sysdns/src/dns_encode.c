#include "dns_encode.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static int is_ldh(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           (c == '-');
}

const char *dns_encode_strerror(int err)
{
    switch (err) {
    case DNS_ENCODE_OK:            return "ok";
    case DNS_ENCODE_ERR_NULL:      return "null argument";
    case DNS_ENCODE_ERR_EMPTY:     return "empty domain";
    case DNS_ENCODE_ERR_LABEL_LEN: return "label longer than 63 octets";
    case DNS_ENCODE_ERR_EMPTY_LABEL: return "empty label";
    case DNS_ENCODE_ERR_TOTAL_LEN: return "encoded name exceeds 255 octets";
    case DNS_ENCODE_ERR_OVERFLOW:  return "output buffer too small";
    case DNS_ENCODE_ERR_CHAR:      return "invalid character in label";
    case DNS_ENCODE_ERR_HYPHEN:    return "label starts or ends with hyphen";
    default:                       return "unknown encode error";
    }
}

int dns_encode_name(const char *name, uint8_t *buf, size_t *off, size_t cap)
{
    size_t pos;
    size_t i;
    size_t name_len;
    size_t written = 0;

    if (name == NULL || buf == NULL || off == NULL) {
        return DNS_ENCODE_ERR_NULL;
    }

    name_len = strlen(name);
    if (name_len == 0u) {
        return DNS_ENCODE_ERR_EMPTY;
    }

    /* Accept FQDN trailing dot: "example.com." → "example.com" */
    if (name[name_len - 1u] == '.') {
        if (name_len == 1u) {
            return DNS_ENCODE_ERR_EMPTY;
        }
        name_len -= 1u;
    }

    pos = *off;

    i = 0;
    while (i < name_len) {
        size_t label_start = i;
        size_t label_len;
        size_t j;

        while (i < name_len && name[i] != '.') {
            unsigned char c = (unsigned char)name[i];
            if (!is_ldh(c)) {
                return DNS_ENCODE_ERR_CHAR;
            }
            i++;
        }

        label_len = i - label_start;
        if (label_len == 0u) {
            return DNS_ENCODE_ERR_EMPTY_LABEL;
        }
        if (label_len > DNS_LABEL_MAX) {
            return DNS_ENCODE_ERR_LABEL_LEN;
        }

        /* Labels must not start or end with '-'. */
        if (name[label_start] == '-' ||
            name[label_start + label_len - 1u] == '-') {
            return DNS_ENCODE_ERR_HYPHEN;
        }

        /* length byte + label + eventual terminator must fit wire limit */
        if (written + 1u + label_len + 1u > DNS_NAME_WIRE_MAX) {
            return DNS_ENCODE_ERR_TOTAL_LEN;
        }
        if (pos + 1u + label_len > cap) {
            return DNS_ENCODE_ERR_OVERFLOW;
        }

        buf[pos++] = (uint8_t)label_len;
        for (j = 0; j < label_len; j++) {
            buf[pos++] = (uint8_t)name[label_start + j];
        }
        written += 1u + label_len;

        if (i < name_len && name[i] == '.') {
            i++; /* skip separator; empty next label caught above */
        }
    }

    /* Root terminator. */
    if (written + 1u > DNS_NAME_WIRE_MAX) {
        return DNS_ENCODE_ERR_TOTAL_LEN;
    }
    if (pos + 1u > cap) {
        return DNS_ENCODE_ERR_OVERFLOW;
    }
    buf[pos++] = 0x00;
    written += 1u;

    *off = pos;
    return (int)written;
}
