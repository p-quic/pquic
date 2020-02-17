#ifndef SBRK_H
#define SBRK_H

#include <stddef.h>
#include <stdint.h>

void *context_sbrk(intptr_t increment);

#endif // SBRK_H
