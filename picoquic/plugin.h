/**
 * Copyright 2018 Quentin De Coninck
 * Glue needed to run plugins
 */

#ifndef PLUGIN_H
#define PLUGIN_H

#include "picoquic.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

typedef enum {
    pluglet_extern,
    pluglet_replace,
    pluglet_pre,
    pluglet_post
} pluglet_type_enum;

/* Function to insert plugins */
int plugin_plug_elf(picoquic_cnx_t *cnx, protoop_plugin_t *p, protoop_str_id_t pid, param_id_t param, pluglet_type_enum pte, char *elf_fname);
/* Function that reset the protocol operation to its default behaviour */
int plugin_unplug(picoquic_cnx_t *cnx, protoop_str_id_t pid, param_id_t param, pluglet_type_enum pte);

/**
 * Function that reads a plugin file and insert plugins described in it
 * in an atomic, transaction style. This means, if one of the plugins
 * cannot be inserted for any reason, all the previously inserted ones
 * will be unplugged.
 * Returns 0 if the plugin insertion succeed, 1 otherwise.
 */
int plugin_insert_plugin(picoquic_cnx_t *cnx, const char *plugin_fname);

/**
 * Function allowing a plugin to access its opaque data space.
 * Given an ID, the function allocates the required space (if possible) the
 * first time the ID is requested and set allocated to 1, otherwise it just
 * returns the corresponding memory area and set allocated to 0.
 * If no additional memory could be allocated, or if the size requested does not
 * match the allocated space, returns NULL
 */
void *get_opaque_data(picoquic_cnx_t *cnx, opaque_id_t oid, size_t size, int *allocated);

/**
 * Function allowing running operations, either built-in or plugged.
 * It runs at invocation time, and returns to the caller the status of the callee.
 * Notice that this function is reentrant, i.e., a plugin might use an
 * external function that call this one under the hood without any
 * interference.
 * Arguments can be provided to the operations. It ensures that they will
 * be safely passed to them without corrupting previous arguments due to
 * reentrant calls. 
 * The (pointer to the) structure pp contains fields containing the protocol operation
 * called (pid), the number of input arguments (inputc), an array with the inputs (inputv)
 * and an array to store the outputs (outputv).
 * There are as many arguments in inputv as the value of inputc.
 * Both inputv and outputv are provided by the caller.
 * The size of the output is stored in cnx->protoop_outputc.
 * outputv can be set to NULL if no output is required.
 * One output is always guaranteed: the return value of this call.
 */
protoop_arg_t plugin_run_protoop_internal(picoquic_cnx_t *cnx, const protoop_params_t *pp);

protoop_arg_t plugin_run_protoop(picoquic_cnx_t *cnx, protoop_params_t *pp, char *pid_str);

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