#include "endianness.h"
#include <stdint.h>

int is_little_endian() {
    int i = 1;
    return (int)*((unsigned char *)&i) == 1 ? 1 : 0;
}

uint16_t my_htons(uint16_t x) {
    if (is_little_endian()) {
        unsigned char *s = (unsigned char *)&x;
        return (uint16_t)(s[0] << 8 | s[1]);
    } else {
        return x;
    }
}

uint16_t my_ntohs(uint16_t x) {
    if (is_little_endian()) {
        unsigned char *s = (unsigned char *)&x;
        return (uint16_t)(s[0] << 8 | s[1]);
    } else {
        return x;
    }
}