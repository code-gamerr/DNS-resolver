#ifndef WIRE_H
#define WIRE_H

/*
 * wire.h — safe, bounds-checked big-endian byte helpers (Phase 2)
 *
 * Every function takes a running offset and returns the NEW offset after the
 * write, or -1 if the write would overflow the buffer.  Chain calls with an
 * early-exit check:
 *
 *   off = wire_put_u16be(buf, off, val, cap);
 *   if (off < 0) return -1;
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* Read values from *off and advance it only on success. */
bool wire_read_u16be(const uint8_t *buf, size_t len, size_t *off,
                     uint16_t *out);
bool wire_read_u32be(const uint8_t *buf, size_t len, size_t *off,
                     uint32_t *out);

/* Write a single byte; return new offset or -1. */
int wire_put_u8(uint8_t *buf, int off, uint8_t v, size_t cap);

/* Write a 16-bit value in big-endian order; return new offset or -1. */
int wire_put_u16be(uint8_t *buf, int off, uint16_t v, size_t cap);

/* Write a 32-bit value in big-endian order; return new offset or -1. */
int wire_put_u32be(uint8_t *buf, int off, uint32_t v, size_t cap);

/* Copy len raw bytes; return new offset or -1. */
int wire_put_bytes(uint8_t *buf, int off, const uint8_t *src, int len,
                   size_t cap);

#endif /* WIRE_H */
