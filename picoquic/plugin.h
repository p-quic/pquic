/**
 * Copyright 2018 Quentin De Coninck
 * Glue needed to run plugins
 */

#ifndef PLUGIN_H
#define PLUGIN_H

#include "picoquic_internal.h"

/* Function to insert plugins */
int plugin_plug_elf(picoquic_cnx_t *cnx, protoop_id_t pid, char *elf_fname);

/**
 * Function allowing running operations, either built-in or plugged.
 * It runs at invocation time, and returns to the caller the status of the callee.
 * Notice that this function is reentrant, i.e., a plugin might use an
 * external function that call this one under the hood without any
 * interference.
 * Arguments can be provided to the operations. It ensures that they will
 * be safely passed to them without corrupting previous arguments due to
 * reentrant calls. There are as many arguments in inputv as the value of inputc.
 * Both inputv and outputv are provided by the caller.
 * The size of the output is stored in cnx->protoop_outputc.
 * outputv can be set to NULL if no output is required.
 */
int plugin_run_protoop(picoquic_cnx_t *cnx, protoop_id_t pid, int inputc, uint64_t *inputv, uint64_t *outputv);

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