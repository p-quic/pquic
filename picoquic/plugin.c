#include "plugin.h"
#include <stdlib.h>
#include <string.h>

plugin_state_t *plugin_push_nxt_state(picoquic_cnx_t *cnx, plugin_id_t state)
{
    /* Exceptionnaly, it is ok here to use malloc, as we don't want plugins to access future states */
    plugin_state_t *s = (plugin_state_t *)malloc(sizeof(plugin_state_t));
    if (s) {
        s->val = state;
        s->nxt = cnx->protoop_nxt_state;
        cnx->protoop_nxt_state = s;
    }
    return s;
}

int plugin_run_plugged_code(picoquic_cnx_t *cnx) {
    if (cnx->plugins[cnx->protoop_cur_state]) {
        DBG_PLUGIN_PRINTF("Running plugin at state 0x%x", cnx->protoop_cur_state);
        return exec_loaded_code(cnx->plugins[cnx->protoop_cur_state], (void *)cnx, sizeof(picoquic_cnx_t));
    }

    printf("Cannot find plugin with id 0x%x\n", cnx->protoop_cur_state);
    exit(-1);
    return -1;
}

int plugin_plug_elf(picoquic_cnx_t *cnx, plugin_id_t identifier, char *elf_fname) {
    cnx->plugins[identifier] = load_elf_file(elf_fname);

    if (cnx->plugins[identifier]) {
        cnx->ops[identifier] = &plugin_run_plugged_code;
        return 0;
    }

    printf("Failed to insert %s for id 0x%x\n", elf_fname, identifier);

    return 1;
}

int plugin_run_operations(picoquic_cnx_t *cnx, plugin_id_t initial_state, int argc, uint64_t *argv) {
    int status = PICOQUIC_OK;
    plugin_state_t *tmp;
    cnx->protoop_cur_state = initial_state;
    cnx->protoop_stop = 0;
    int continue_run = 1;

    if (argc > PROTOOPARGS_MAX) {
        printf("Too many arguments for protocol operation with initial_state 0x%x : %d > %d\n",
            initial_state, argc, PROTOOPARGS_MAX);
        return PICOQUIC_ERROR_PROTOCOL_OPERATION_TOO_MANY_ARGUMENTS;
    }

    /* First save previous args, and update context with new ones
     * Notice that we store ALL array of protoop_args. This allows using some of them as accumulator
     * without causing issues to caller arguments.
     */
    uint64_t old_args[PROTOOPARGS_MAX];
    memcpy(old_args, cnx->protoop_args, sizeof(uint64_t) * PROTOOPARGS_MAX);
    memcpy(cnx->protoop_args, argv, sizeof(uint64_t) * argc);

    /* We also need to keep track of the current nxt_state, as this function might be reentrant. */
    plugin_state_t *end_state = cnx->protoop_nxt_state;

    do {
        DBG_PLUGIN_PRINTF("Run operation 0x%x", cnx->protoop_cur_state);
        if (!cnx->ops[cnx->protoop_cur_state]) {
            printf("FATAL ERROR: no function for state 0x%x\n", cnx->protoop_cur_state);
            exit(1);
        }
        status = cnx->ops[cnx->protoop_cur_state](cnx);

        /* Do we still have states to explore ? */
        if (cnx->protoop_nxt_state != end_state) {
            tmp = cnx->protoop_nxt_state;
            cnx->protoop_nxt_state = tmp->nxt;
            cnx->protoop_cur_state = tmp->val;
            /* Keep free, as malloc was used for states */
            free(tmp);
        } else {
            continue_run = 0;
        }
    } while (continue_run && cnx->protoop_stop == 0);

    /* Perform clean-up, as abrupt terminations might leave some unfree memory */
    while (cnx->protoop_nxt_state != end_state) {
        tmp = cnx->protoop_nxt_state;
        cnx->protoop_nxt_state = cnx->protoop_nxt_state->nxt;
        /* Keep free, as malloc was used for states */
        free(tmp);
    }

    DBG_PLUGIN_PRINTF("Return status of initial operation 0x%x is 0x%x, stopped is %d", initial_state, status, cnx->protoop_stop);

    /* We want to be reentrant, so stop must be reset now */
    cnx->protoop_stop = 0;

    /* And restore ALL the previous arguments */
    memcpy(cnx->protoop_args, old_args, sizeof(uint64_t) * PROTOOPARGS_MAX);

    return status;
}