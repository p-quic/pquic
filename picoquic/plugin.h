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

/* Definition operation return values */
#define OPERATION_OK 0
#define OPERATION_STOP 1

/**
 * Function allowing running operations, either built-in or plugged.
 * @pre initial_state < max_state
 */
int plugin_run_operations(picoquic_cnx_t *cnx, plugin_id_t initial_state, plugin_id_t max_state);

#endif // #ifndef PLUGIN_H