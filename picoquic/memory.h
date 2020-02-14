#ifndef MEMORY_H
#define MEMORY_H

#include "picoquic.h"

void *my_malloc(picoquic_cnx_t *cnx, unsigned int size);
void *my_malloc_dbg(picoquic_cnx_t *cnx, unsigned int size, char *file, int line);
void my_free(picoquic_cnx_t *cnx, void *ptr);
void my_free_dbg(picoquic_cnx_t *cnx, void *ptr, char *file, int line);
void *my_realloc(picoquic_cnx_t *cnx, void *ptr, unsigned int size);

void my_free_in_core(protoop_plugin_t *p, void *ptr);

int init_memory_management(protoop_plugin_t *p);

int destroy_memory_management(protoop_plugin_t *p);

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef IS_IN_PLUGIN_MEMORY
#define IS_IN_PLUGIN_MEMORY(plugin, ptr) (((ptr) == NULL) || ((void *) (&(plugin)->memory[0]) < ((void *) ptr) && ((void *) ptr) < (void *) (&(plugin)->memory[PLUGIN_MEMORY])))
#endif

#ifdef DEBUG_MEMORY_PRINTF

#define DBG_MEMORY_PRINTF_FILENAME_MAX 24
#define DBG_MEMORY_PRINTF(fmt, ...)                                                                 \
    debug_printf("%s:%u [%s]: " fmt "\n",                                                    \
        __FILE__ + MAX(DBG_MEMORY_PRINTF_FILENAME_MAX, sizeof(__FILE__)) - DBG_MEMORY_PRINTF_FILENAME_MAX, \
        __LINE__, __FUNCTION__, __VA_ARGS__)

#else

#define DBG_MEMORY_PRINTF(fmt, ...)

#endif // #ifdef DEBUG_PLUGIN_PRINTF

#endif // MEMORY_H