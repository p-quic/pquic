
#include <stdio.h>
#include "sbrk-public.h"


struct malloc_state *_gm_;  // the global state of dlmalloc


// TODO: check compatibility of sbrk with ptmalloc3

static sbrk_memory_context_t *current_context;

int set_current_context(sbrk_memory_context_t *p) {
    current_context = p;
    _gm_ = &current_context->dlmalloc_state;
    return 0;
}

sbrk_memory_context_t *get_current_context() {
    return current_context;
}

/**
 * Home-made implementation of sbrk with a context.
 */
void *context_sbrk(intptr_t increment) {
    if (current_context->memory_current_end + increment - current_context->memory_start > current_context->memory_max_size) {
        /* Out of memory */
        fprintf(stderr, "CONTEXT_SBRK: OUT OF MEMORY\n");
        fflush(stderr);
        return NULL;
    }
    if (increment == 0) return NULL;

    void *previous_end = current_context->memory_current_end;
    current_context->memory_current_end += increment;
    return previous_end;
}
