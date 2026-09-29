#ifndef HEXDUMP_H
#define HEXDUMP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Print a classic hex dump (16 bytes/line) to out. */
void hexdump_print(FILE *out, const uint8_t *buf, size_t len);

#endif /* HEXDUMP_H */
