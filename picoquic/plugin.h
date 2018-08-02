/**
 * Copyright 2018 Quentin De Coninck
 * Glue needed to run plugins
 */

#ifndef PLUGIN_H
#define PLUGIN_H

#include "picoquic_internal.h"

/* Struct defining which is the next operation to perform */
typedef struct state {
    plugin_id_t val;
    struct state *nxt;
} plugin_state_t;

/* Insert state as the next one in the context */
plugin_state_t *plugin_push_nxt_state(picoquic_cnx_t *cnx, plugin_id_t state);

/* Function to insert plugins */
int plugin_plug_elf(picoquic_cnx_t *cnx, plugin_id_t identifier, char *elf_fname);

/**
 * Function allowing running operations, either built-in or plugged.
 * Notice that this function is reentrant, i.e., a plugin might use an
 * external function that call this one under the hood without any
 * interference.
 * Arguments can be provided to the operations. It ensures that they will
 * be safely passed to them without corrupting previous arguments due to
 * reentrant calls. There are as many arguments in argv as the value of argc.
 */
int plugin_run_operations(picoquic_cnx_t *cnx, plugin_id_t initial_state, int argc, uint64_t *argv);

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifdef DEBUG_PLUGIN_PRINTF

#define DBG_PLUGIN_PRINTF_FILENAME_MAX 24
#define DBG_PLUGIN_PRINTF(fmt, ...)                                                                 \
    debug_printf("%s:%u [%s]: " fmt "\n",                                                    \
        __FILE__ + MAX(DBG_PLUGIN_PRINTF_FILENAME_MAX, sizeof(__FILE__)) - DBG_PLUGIN_PRINTF_FILENAME_MAX, \
        __LINE__, __FUNCTION__, __VA_ARGS__)

#else

#define DBG_PLUGIN_PRINTF(fmt, ...)

#endif // #ifdef DEBUG_PLUGIN_PRINTF

#endif // #ifndef PLUGIN_H