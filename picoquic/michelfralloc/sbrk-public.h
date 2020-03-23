#ifndef SBRH_PUBLIC_H
#define SBRH_PUBLIC_H
#include "sbrk.h"

#include "ptmalloc3/malloc-private.h"

typedef struct {
    void *memory_start;
    void *memory_current_end;
    size_t memory_max_size;
    struct malloc_state dlmalloc_state;    // the state of dlmalloc for this context. This is very hackish, I'll take a look to mspaces later.
} sbrk_memory_context_t;

int set_current_context(sbrk_memory_context_t *p);

sbrk_memory_context_t *get_current_context(void);

#endif