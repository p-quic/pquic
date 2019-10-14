#ifndef SBRK_H
#define SBRK_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    void *memory_start;
    void *memory_current_end;
    size_t memory_max_size;
} sbrk_memory_context_t;

int set_current_context(sbrk_memory_context_t *p);

sbrk_memory_context_t *get_current_context(void);

void *context_sbrk(intptr_t increment);

#endif // SBRK_H
