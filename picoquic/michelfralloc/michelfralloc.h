#ifndef MICHELFRALLOC_H
#define MICHELFRALLOC_H

#include <stdlib.h>
#include <stdint.h>
#include "sbrk-public.h"

typedef sbrk_memory_context_t plugin_dynamic_memory_pool_t;

void *michelfralloc(plugin_dynamic_memory_pool_t *context, size_t size);

void michelfree(plugin_dynamic_memory_pool_t *context, void *pointer);

void *michelfrealloc(plugin_dynamic_memory_pool_t *context, void *pointer, size_t size);



#endif //UNTITLED_LIBRARY_H