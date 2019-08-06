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

const char *pluglet_type_name(pluglet_type_enum te);

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
 * Function taking a list of plugin file names with their associated plugin
 * IDs and insert them in the provided order.
 * Notice that this function can reuse some previously cached plugins.
 * plugin_fnames and plugin_ids remain unchanged.
 * Returns the number of plugins that couldn't be inserted.
 */
int plugin_insert_plugins(picoquic_cnx_t *cnx, uint8_t nb_plugins, plugin_fname_t* plugins); 

/**
 * Function taking a list of plugin file names with their associated plugin
 * IDs and insert them in the provided order.
 * Notice that this function can reuse some previously cached plugins.
 * plugin_fnames and plugin_ids remain unchanged.
 * Returns the number of plugins that couldn't be inserted.
 */
int plugin_insert_plugins_from_fnames(picoquic_cnx_t *cnx, uint8_t nb_plugins, char **plugin_fnames); 

/**
 * Function that parses the identifier of a plugin contained in its manifest.
 * The name of the ID is copied in the provided buffer (requires at least 250 bytes).
 * Returns 0 on success.
 */
int plugin_parse_plugin_id(const char *plugin_fname, char *plugin_id);

/**
 * This function prepares an archive containing the plugin to exchange.
 * Returns 0 on success.
 */
int plugin_prepare_plugin_data_exchange(picoquic_cnx_t *cnx, const char *plugin_fname,
    uint8_t* plugin_data, size_t max_plugin_data, size_t* plugin_data_len);

/**
 * This function extracts the archive contained in memory in preq in the cache of
 * the host of the connection.
 * Returns 0 on success.
 */
int plugin_process_plugin_data_exchange(picoquic_cnx_t *cnx, const char* plugin_name, uint8_t *data, size_t data_length);

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

protoop_arg_t plugin_run_protoop(picoquic_cnx_t *cnx, protoop_params_t *pp, char *pid_str, protoop_id_t *pid);

bool plugin_pluglet_exists(picoquic_cnx_t *cnx, protoop_id_t *pid, param_id_t param, pluglet_type_enum anchor);

/**
 * This function sets metadata at `idx` to `val` from a plugin structure metadata hashmap stored at `metadata`
 * If the metadata are not present in the hashmap, it will be allocated and the values at indexes different thant `idx`
 * are set to zero by default
 * Returns 0 if no error, -1 if an error occurred
 */
int set_plugin_metadata(protoop_plugin_t *plugin, plugin_struct_metadata_t **metadata, int idx, uint64_t val);

/**
 * This function sets out to the values of the plugin metadata at `idx` from a plugin structure metadata hashmap stored
 * in `metadata`. If the metadata are not present in the hashmap, it will be allocated and the values are set to zero
 * by default (*out will thus be set to 0)
 * Returns 0 if no error, -1 if an error occurred
 */
int get_plugin_metadata(protoop_plugin_t *plugin, plugin_struct_metadata_t **metadata, int idx, uint64_t *out);

int get_errno();

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