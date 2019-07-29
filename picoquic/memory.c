#include "memory.h"
#include "memcpy.h"

#include <unistd.h>
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
	protoop_plugin_t *p = cnx->current_plugin;
	if (!p) {
		fprintf(stderr, "FATAL ERROR: calling my_malloc outside plugin scope!\n");
		exit(1);
	}
	memory_pool_t *mp = &p->memory_pool;
	if (size > mp->size_of_each_block - 8) {
		printf("Asking for %u bytes by slots up to %lu!\n", size, mp->size_of_each_block - 8);
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
	} else {
		printf("Out of memory!\n");
	}
	*((uint64_t *)ret) = MAGIC_NUMBER;
	return ret + 8;
}

void *my_malloc_dbg(picoquic_cnx_t *cnx, unsigned int size, char *file, int line) {
    void *p = my_malloc(cnx, size);
    printf("MY MALLOC %s:%d = %p\n", file, line, p);
    return p;
}

void my_free_in_core(protoop_plugin_t *p, void *ptr) {
	ptr -= 8;
	if (*((uint64_t *) ptr) != MAGIC_NUMBER){
		printf("MEMORY CORRUPTION: BAD METADATA: 0x%lx, ORIGINAL PTR: %p\n", *((uint64_t *) ptr), ptr + 8);
	}
	memory_pool_t *mp = &p->memory_pool;
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
void *my_realloc(picoquic_cnx_t *cnx, void *ptr, unsigned int size) {
	protoop_plugin_t *p = cnx->current_plugin;
	if (!p) {
		fprintf(stderr, "FATAL ERROR: calling my_free outside plugin scope!\n");
		exit(1);
	}
	// we cannot change the size of the block: if the new size is above the maximum, print an error,
	// otherwise, return the same pointer
	if (size > p->memory_pool.size_of_each_block - 8) {
		printf("Asking for %u bytes by slots up to %lu!\n", size, p->memory_pool.size_of_each_block - 8);
		/* Don't forget to free the pointer! */
		my_free_in_core(p, ptr);
		return NULL;
	}
	return ptr;
}

void init_memory_management(protoop_plugin_t *p)
{
	p->memory_pool.mem_start = (uint8_t *) p->memory;
	p->memory_pool.size_of_each_block = 3100; /* TEST */
	p->memory_pool.num_of_blocks = PLUGIN_MEMORY / 3100;
	p->memory_pool.num_initialized = 0;
	p->memory_pool.num_free_blocks = p->memory_pool.num_of_blocks;
	p->memory_pool.next = p->memory_pool.mem_start;
}