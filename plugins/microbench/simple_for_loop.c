#include "../helpers.h"

uint64_t simple_for_loop(void *mem) {
    uint64_t sum = 0;
    for (uint64_t i = 0; i < 1000000000; i++) {
        sum = i + sum * 3 / 2;
    }
    return sum;
}