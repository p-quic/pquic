#include "memory.h"
#include "memcpy.h"

#include <unistd.h>
#include <michelfralloc/michelfralloc.h>
#include "picoquic_internal.h"

/* This implementation is mostly a translation from C++ to C of the
 * implementation proposed by Ben Kenwright in "Fast Efficient
 * Fixed-Size Memory Pool: No Loops and No Overhead", presented at
 * COMPUTATION TOOLS 2012.
 */

#define MAGIC_NUMBER 0xa110ca7ab1e

uint8_t *addr_from_index(memory_pool_t *mp, uint64_t i) {
	return mp->mem_start + (i * mp->size_of_each_block);
}

uint64_t index_from_addr(memory_pool_t *mp, uint8_t *p) {
	return ((uint64_t)(p - mp->mem_start)) / mp->size_of_each_block;
}

/**
* Search for big enough free space on heap.
* Return the pointer to this slot.
* If no adequately large free slot is available, return NULL.
*/
void *my_malloc(picoquic_cnx_t *cnx, unsigned int size) {
    return cnx->current_plugin->memory_manager.my_malloc(cnx->current_plugin, size);
}

void my_free_in_core(protoop_plugin_t *p, void *ptr) {
    return p->memory_manager.my_free(p, ptr);
}



/**
 * Frees the allocated memory. If first checks if the pointer falls
 * between the allocated heap range. It also checks if the pointer
 * to be deleted is actually allocated. this is done by using the
 * magic number.
 */
void my_free(picoquic_cnx_t *cnx, void *ptr) {
    protoop_plugin_t *p = cnx->current_plugin;
    if (!p) {
        fprintf(stderr, "FATAL ERROR: calling my_free outside plugin scope!\n");
        exit(1);
    }
    my_free_in_core(p, ptr);
}


/**
 * Reallocate the allocated memory to change its size. Three cases are possible.
 * 1) Asking for size lower than the block_size.
 *    The block is left untouched, we simply return it.
 * 2) Asking for larger size, without being able to have free space.
 *    Free the pointer and return NULL.
 * If an invalid pointer is provided, it returns NULL without changing anything.
 */
void *my_realloc(picoquic_cnx_t *cnx, void *ptr, unsigned int size) {
    return cnx->current_plugin->memory_manager.my_realloc(cnx->current_plugin, ptr, size);
}

/**
* Search for big enough free space on heap.
* Return the pointer to this slot.
* If no adequately large free slot is available, return NULL.
*/
void *my_malloc_block(protoop_plugin_t *p, unsigned int size) {
	if (!p) {
		fprintf(stderr, "FATAL ERROR: calling my_malloc outside plugin scope!\n");
		exit(1);
	}
	memory_pool_t *mp = (memory_pool_t *) p->memory_manager.ctx;
    if (!mp) {
        fprintf(stderr, "FATAL ERROR: calling my_malloc_block with a NULL context !\n");
        exit(1);
    }
	if (size > mp->size_of_each_block - 8) {
		printf("Asking for %u bytes by slots up to %" PRIu64 "!\n", size, mp->size_of_each_block - 8);
		return NULL;
	}
	if (mp->num_initialized < mp->num_of_blocks) {
		uint64_t *ptr = (uint64_t *) addr_from_index(mp, mp->num_initialized);
		/* Very important for the mp->next computation */
		*ptr = mp->num_initialized + 1;
		mp->num_initialized++;
	}

	void *ret = NULL;
	if (mp->num_free_blocks > 0) {
		ret = (void *) mp->next;
		mp->num_free_blocks--;
		if (mp->num_free_blocks > 0) {
			mp->next = addr_from_index(mp, *((uint64_t *)mp->next));
		} else {
			mp->next = NULL;
		}
	}

	if (ret) {
        *((uint64_t *)ret) = MAGIC_NUMBER;
        ret += 8;
    } else {
        printf("Out of memory!\n");
	}

	return ret;
}

void *my_malloc_dbg(picoquic_cnx_t *cnx, unsigned int size, char *file, int line) {
    void *p = my_malloc(cnx, size);
    printf("MY MALLOC %s:%d = %p (%d bytes)\n", file, line, p, size);
    return p;
}

void my_free_block(protoop_plugin_t *p, void *ptr) {
	ptr -= 8;
	if (*((uint64_t *) ptr) != MAGIC_NUMBER){
		printf("MEMORY CORRUPTION: BAD METADATA: 0x%" PRIx64 ", ORIGINAL PTR: %p\n", *((uint64_t *) ptr), ptr + 8);
	}
    memory_pool_t *mp = (memory_pool_t *) p->memory_manager.ctx;
    if (!mp) {
        fprintf(stderr, "FATAL ERROR: calling my_malloc_block with a NULL context !\n");
        exit(1);
    }
	if (mp->next != NULL) {
		(*(uint64_t *) ptr) = index_from_addr(mp, mp->next);
		if (!(mp->mem_start <= (uint8_t *) ptr && (uint8_t *) ptr < (mp->mem_start + (mp->num_of_blocks * mp->size_of_each_block)))) {
            printf("MEMORY CORRUPTION: FREEING MEMORY (%p) NOT BELONGING TO THE PLUGIN\n", ptr + 8);
		}
		mp->next = (uint8_t *) ptr;
	} else {
		(*(uint64_t *) ptr) = mp->num_of_blocks;
        if (!(mp->mem_start <= (uint8_t *) ptr && (uint8_t *) ptr < (mp->mem_start + (mp->num_of_blocks * mp->size_of_each_block)))) {
            printf("MEMORY CORRUPTION: FREEING MEMORY (%p) NOT BELONGING TO THE PLUGIN\n", ptr + 8);
        }
		mp->next = (uint8_t *) ptr;
	}
	mp->num_free_blocks++;
}

void my_free_dbg(picoquic_cnx_t *cnx, void *ptr, char *file, int line) {
    printf("MY FREE %s:%d = %p\n", file, line, ptr);
    my_free(cnx, ptr);
}
/**
 * Reallocate the allocated memory to change its size. Three cases are possible.
 * 1) Asking for size lower than the block_size.
 *    The block is left untouched, we simply return it.
 * 2) Asking for larger size, without being able to have free space.
 *    Free the pointer and return NULL.
 * If an invalid pointer is provided, it returns NULL without changing anything.
 */
void *my_realloc_block(protoop_plugin_t *p, void *ptr, unsigned int size) {
	if (!p) {
		fprintf(stderr, "FATAL ERROR: calling my_free outside plugin scope!\n");
		exit(1);
	}
    memory_pool_t *mp = (memory_pool_t *) p->memory_manager.ctx;
    if (!mp) {
        fprintf(stderr, "FATAL ERROR: calling my_malloc_block with a NULL context !\n");
        exit(1);
    }
	// we cannot change the size of the block: if the new size is above the maximum, print an error,
	// otherwise, return the same pointer
	if (size > mp->size_of_each_block - 8) {
		printf("Asking for %u bytes by slots up to %" PRIu64 "!\n", size, mp->size_of_each_block - 8);
		/* Don't forget to free the pointer! */
		my_free_in_core(p, ptr);
		return NULL;
	}
	return ptr;
}

int init_block_memory_management(protoop_plugin_t *p)
{
    p->memory_manager.my_malloc = my_malloc_block;
    p->memory_manager.my_free = my_free_block;
    p->memory_manager.my_realloc = my_realloc_block;

    memory_pool_t *mp = calloc(1, sizeof(memory_pool_t));
    if (!mp) {
        return -1;
    }
    mp->mem_start = (uint8_t *) p->memory;
    mp->size_of_each_block = 2100; /* TEST */
    mp->num_of_blocks = PLUGIN_MEMORY / 2100;
    mp->num_initialized = 0;
    mp->num_free_blocks = mp->num_of_blocks;
    mp->next = mp->mem_start;
    p->memory_manager.ctx = mp;
    return 0;
}

int destroy_block_memory_management(protoop_plugin_t *p)
{
    if (!p->memory_manager.ctx) {
        fprintf(stderr, "cannot free NULL plugin block memory manager context !\n");
    }
    free(p->memory_manager.ctx);
    return 0;
}



void *malloc_dynamic(protoop_plugin_t *p, unsigned int size) {
    void *ptr = michelfralloc((plugin_dynamic_memory_pool_t *) p->memory_manager.ctx, size);
    return ptr;
}


void free_dynamic(protoop_plugin_t *p, void *ptr) {
    return michelfree((plugin_dynamic_memory_pool_t *) p->memory_manager.ctx, ptr);
}

void *realloc_dynamic(protoop_plugin_t *p, void *ptr, unsigned int size) {
    return michelfrealloc((plugin_dynamic_memory_pool_t *) p->memory_manager.ctx, ptr, size);
}



int init_dynamic_memory_management(protoop_plugin_t *p)
{
    p->memory_manager.my_malloc = malloc_dynamic;
    p->memory_manager.my_free = free_dynamic;
    p->memory_manager.my_realloc = realloc_dynamic;

    plugin_dynamic_memory_pool_t *mp = calloc(1, sizeof(plugin_dynamic_memory_pool_t));
    if (!mp) {
        return -1;
    }
    mp->memory_max_size = PLUGIN_MEMORY;
    mp->memory_current_end = mp->memory_start =  (uint8_t *) p->memory;
    p->memory_manager.ctx = mp;
    return 0;
}


int destroy_dynamic_memory_management(protoop_plugin_t *p)
{
    if (!p->memory_manager.ctx) {
        fprintf(stderr, "cannot free NULL plugin dynamic memory manager context !\n");
    }
    free(p->memory_manager.ctx);
    return 0;
}



int init_memory_management(protoop_plugin_t *p) {
    if (!p) {
        fprintf(stderr, "call to init_memory_management with a NULL plugin !\n");
        return -1;
    }
    printf("create memory manager for plugin %s\n", p->name);
    switch (p->params.plugin_memory_manager_type) {
        case plugin_memory_manager_fixed_blocks:
            printf("create fixed block size memory manager\n");
            return init_block_memory_management(p);
        case plugin_memory_manager_dynamic:
            printf("create dynamic memory manager\n");
            return init_dynamic_memory_management(p);
        default:
            fprintf(stderr, "unknown plugin memory manager %d !\n", p->params.plugin_memory_manager_type);
            return -1;
    }

}

int destroy_memory_management(protoop_plugin_t *p) {
    if (!p) {
        fprintf(stderr, "call to destroy_memory_management with a NULL plugin !\n");
        return -1;
    }
    switch (p->params.plugin_memory_manager_type) {
        case plugin_memory_manager_fixed_blocks:
            return destroy_block_memory_management(p);
        case plugin_memory_manager_dynamic:
            return destroy_dynamic_memory_management(p);
        default:
            fprintf(stderr, "unknown plugin memory manager %d !\n", p->params.plugin_memory_manager_type);
            return -1;
    }
}
