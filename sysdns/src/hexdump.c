#include "hexdump.h"

#include <ctype.h>
#include <stdio.h>

void hexdump_print(FILE *out, const uint8_t *buf, size_t len)
{
    size_t i;
    size_t j;

    if (out == NULL || buf == NULL) {
        return;
    }

    for (i = 0; i < len; i += 16u) {
        fprintf(out, "%04lx  ", (unsigned long)i);

        for (j = 0; j < 16u; j++) {
            if (i + j < len) {
                fprintf(out, "%02x ", buf[i + j]);
            } else {
                fputs("   ", out);
            }
            if (j == 7u) {
                fputc(' ', out);
            }
        }

        fputs(" |", out);
        for (j = 0; j < 16u; j++) {
            if (i + j < len) {
                unsigned char c = buf[i + j];
                fputc(isprint(c) ? (int)c : '.', out);
            }
        }
        fputs("|\n", out);
    }
}
