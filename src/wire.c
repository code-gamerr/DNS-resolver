#include "wire.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static bool has_bytes(size_t len, size_t off, size_t needed)
{
    return off <= len && needed <= len - off;
}

bool wire_read_u16be(const uint8_t *buf, size_t len, size_t *off,
                     uint16_t *out)
{
    size_t pos;

    if (buf == NULL || off == NULL || out == NULL) {
        return false;
    }
    pos = *off;
    if (!has_bytes(len, pos, 2u)) {
        return false;
    }

    *out = (uint16_t)(((uint16_t)buf[pos] << 8) |
                      (uint16_t)buf[pos + 1u]);
    *off = pos + 2u;
    return true;
}

bool wire_read_u32be(const uint8_t *buf, size_t len, size_t *off,
                     uint32_t *out)
{
    size_t pos;

    if (buf == NULL || off == NULL || out == NULL) {
        return false;
    }
    pos = *off;
    if (!has_bytes(len, pos, 4u)) {
        return false;
    }

    *out = ((uint32_t)buf[pos] << 24) |
           ((uint32_t)buf[pos + 1u] << 16) |
           ((uint32_t)buf[pos + 2u] << 8) |
           (uint32_t)buf[pos + 3u];
    *off = pos + 4u;
    return true;
}

int wire_put_u8(uint8_t *buf, int off, uint8_t v, size_t cap)
{
    if (buf == NULL || off < 0 || off == INT_MAX ||
        !has_bytes(cap, (size_t)off, 1u)) {
        return -1;
    }
    buf[off] = v;
    return off + 1;
}

int wire_put_u16be(uint8_t *buf, int off, uint16_t v, size_t cap)
{
    if (buf == NULL || off < 0 || off > INT_MAX - 2 ||
        !has_bytes(cap, (size_t)off, 2u)) {
        return -1;
    }
    buf[off]     = (uint8_t)((v >> 8) & 0xFFu);
    buf[off + 1] = (uint8_t)(v & 0xFFu);
    return off + 2;
}

int wire_put_u32be(uint8_t *buf, int off, uint32_t v, size_t cap)
{
    if (buf == NULL || off < 0 || off > INT_MAX - 4 ||
        !has_bytes(cap, (size_t)off, 4u)) {
        return -1;
    }
    buf[off]     = (uint8_t)((v >> 24) & 0xFFu);
    buf[off + 1] = (uint8_t)((v >> 16) & 0xFFu);
    buf[off + 2] = (uint8_t)((v >>  8) & 0xFFu);
    buf[off + 3] = (uint8_t)(v & 0xFFu);
    return off + 4;
}

int wire_put_bytes(uint8_t *buf, int off, const uint8_t *src, int len,
                   size_t cap)
{
    if (buf == NULL || off < 0 || len < 0 || off > INT_MAX - len ||
        !has_bytes(cap, (size_t)off, (size_t)len)) {
        return -1;
    }
    if (len == 0) {
        return off;
    }
    if (src == NULL) {
        return -1;
    }
    memcpy(buf + off, src, (size_t)len);
    return off + len;
}
