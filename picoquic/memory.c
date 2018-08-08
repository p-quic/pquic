#include "memory.h"
#include "memcpy.h"

/* This code is highly inspired from https://github.com/fouady/simple-malloc/blob/master/mem_management.cpp */

#include <unistd.h>
#include "picoquic_internal.h"

/**
 * MEM_BUFFER determines size of RAM
 * METADATA_SIZE is the fixed size of metadata block
 * ALIGNMENT_FACTOR determines the smallest chunk of memory in bytes.
 * MAGIC_NUMBER is used to check if the pointer to be freed is valid.
 */
#define MEM_BUFFER CONTEXT_MEMORY
#define METADATA_SIZE (sizeof(meta_data))
#define ALIGNMENT_FACTOR 4
#define MAGIC_NUMBER 0123

/**
 * This structure contains the metadata.
 * Size determines the size of data excuding the size of metadata
 * next block is the pointer to next slot of memory in heap.
 */
typedef struct meta_data {
	unsigned int size;
	unsigned int available;
	struct meta_data *next_block;
	unsigned int magic_number;
} meta_data;

/**
 * Adjusts the requested size so that the allocated space is always a multiple of alighment factor
 */ 
unsigned int align_size(unsigned int size) {
	return (size % ALIGNMENT_FACTOR) ? size + ALIGNMENT_FACTOR - (size % ALIGNMENT_FACTOR) : size;
}

/**
 * Home-made implementation of sbrk within a given picoquic_cnx_t.
 */
void *my_sbrk(picoquic_cnx_t *cnx, intptr_t increment) {
    if (cnx->heap_end + increment - cnx->heap_start > MEM_BUFFER) {
        /* Out of memory */
        return (void *) -1;
    }

    cnx->heap_end += increment;
    return cnx->heap_end;
}

/**
 * Goes through the whole heap to find an empty slot.
 */ 
meta_data *find_slot(picoquic_cnx_t *cnx, unsigned int size) {
	meta_data *iter = (meta_data*) cnx->heap_start;
	while(iter) {
		if (iter->available && iter->size >= size) {
			iter->available = 0;
			return iter;
		}
		iter = iter->next_block;
	}
	return NULL;
}

/**
 * If a free slot can accommodate atleast 1 more (METADATA_SIZE + ALIGNMENT FACTOR)
 * apart from the requested size, then the slot is divided to save space.
 */ 
void divide_slot(void *slot, unsigned int size) {
	meta_data *slot_to_divide = (meta_data *) slot;
	meta_data *new_slot= (meta_data*) ((char *) slot_to_divide + METADATA_SIZE + size);
	
	new_slot->size=slot_to_divide->size - size - METADATA_SIZE;
	new_slot->available = 1;
	new_slot->next_block = slot_to_divide->next_block;
	new_slot->magic_number = MAGIC_NUMBER;
	
	slot_to_divide->size = size;
	slot_to_divide->next_block = new_slot;
}

/**
 * Extends the heap using sbrk syscall. 
 */
void *extend(picoquic_cnx_t *cnx, unsigned int size) {
	meta_data *new_block = (meta_data*) my_sbrk(cnx, 0);
	if ((char*) new_block - (char*) cnx->heap_start > MEM_BUFFER) return NULL;
	int *flag = (int *) my_sbrk(cnx, size + METADATA_SIZE);
	if (*flag == -1) return NULL;
	new_block->size = size;
	new_block->available = 0;
	new_block->next_block = NULL;
	new_block->magic_number = MAGIC_NUMBER;
	
	if (cnx->heap_last_block) {
		((meta_data *) cnx->heap_last_block)->next_block = new_block;	
	}
	cnx->heap_last_block = new_block;
	return new_block;
}

/**
 * Returns the metadata from heap corresponding to a data pointer.
 */ 
meta_data* get_metadata(void *ptr) {
	return (meta_data *)((char *) ptr - METADATA_SIZE);
}

/**
* Search for big enough free space on heap.
* Split the free space slot if it is too big, else space will be wasted.
* Return the pointer to this slot.
* If no adequately large free slot is available, extend the heap and return the pointer.
*/
void *my_malloc(picoquic_cnx_t *cnx, unsigned int size) {
	size = align_size(size);
	void *slot;
	if (cnx->heap_start){
        DBG_MEMORY_PRINTF("Heap starts at: %p", cnx->heap_start);
		slot = find_slot(cnx, size);
		if (slot) {
			if (((meta_data *) slot)->size > size + METADATA_SIZE) {
				divide_slot(slot, size);
			}
		} else {
			slot = extend(cnx, size);
		}
	} else {
		cnx->heap_start = my_sbrk(cnx, 0);
        DBG_MEMORY_PRINTF("Heap starts at: %p", cnx->heap_start);
		slot = extend(cnx, size);
	}
	
	if (!slot) { return slot; }

    DBG_MEMORY_PRINTF("Memory assigned from %p to %p", slot, (void *)((char *) slot + METADATA_SIZE + ((meta_data *) slot)->size));
    DBG_MEMORY_PRINTF("Memory ends at: %p", my_sbrk(cnx, 0));
    DBG_MEMORY_PRINTF("Size of heap so far: 0x%lx", (unsigned long) ((char *) my_sbrk(cnx, 0) - (char *) cnx->heap_start));

	return ((char *) slot) + METADATA_SIZE;
}

/**
 * Frees the allocated memory. If first checks if the pointer falls
 * between the allocated heap range. It also checks if the pointer
 * to be deleted is actually allocated. this is done by using the
 * magic number. Due to lack of time i haven't worked on fragmentation.
 */ 
void my_free(picoquic_cnx_t *cnx, void *ptr) {
	if (!cnx->heap_start) return;
	if (ptr >= cnx->heap_start + METADATA_SIZE && ptr < my_sbrk(cnx, 0)) {
		meta_data *ptr_metadata = get_metadata(ptr);
		if (ptr_metadata->magic_number == MAGIC_NUMBER) {
			ptr_metadata->available = 1;
            DBG_MEMORY_PRINTF("Memory freed at: %p", ptr_metadata);
		}
	}
}

/**
 * Reallocate the allocated memory to change its size. Three cases are possible.
 * 1) Asking for lower or equal size, or larger size without any block after.
 *    The block is left untouched, we simply increase its size.
 * 2) Asking for larger size, and another block is behind.
 *    We need to request another larger block, then copy the data and finally free it.
 * 3) Asking for larger size, without being able to have free space.
 *    Free the pointer and return NULL.
 * If an invalid pointer is provided, it returns NULL without changing anything.
 */
void *my_realloc(picoquic_cnx_t *cnx, void *ptr, unsigned int size) {
    /* If no previous ptr, fast-track to my_malloc */
    if (!ptr) return my_malloc(cnx, size);
    /* If the previous ptr is invalid, return NULL */
    if (ptr < cnx->heap_start + METADATA_SIZE && ptr >= my_sbrk(cnx, 0)) return NULL;
    /* Now take metadata */
    meta_data *ptr_metadata = get_metadata(ptr);
    if (ptr_metadata->magic_number != MAGIC_NUMBER) {
        /* Invalid pointer */
        return NULL;
    }
    /* Case 1a and 1b */
    unsigned int old_size = ptr_metadata->size;
    if (size <= old_size) {
        ptr_metadata->size = size;
        return ptr;
    }

    /* This is clearly not the most optimized way, but it will always work */
    void *new_ptr = my_malloc(cnx, size);
    if (!new_ptr) {
        my_free(cnx, ptr);
        return NULL;
    }
    my_memcpy(new_ptr, ptr, old_size);
    my_free(cnx, ptr);
    return new_ptr;
}

void init_memory_management(picoquic_cnx_t *cnx)
{
	cnx->heap_start = cnx->memory;
	cnx->heap_end = cnx->memory;
	cnx->heap_last_block = NULL;
}