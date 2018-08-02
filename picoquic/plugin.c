#include "plugin.h"
#include <stdlib.h>

plugin_state_t *plugin_push_nxt_state(picoquic_cnx_t *cnx, plugin_id_t state)
{
    /* Exceptionnaly, it is ok here to use malloc, as we don't want plugins to access future states */
    plugin_state_t *s = (plugin_state_t *)malloc(sizeof(plugin_state_t));
    if (s) {
        s->val = state;
        s->nxt = cnx->nxt_state;
        cnx->nxt_state = s;
    }
    return s;
}

int plugin_run_plugged_code(picoquic_cnx_t *cnx) {
    if (cnx->plugins[cnx->cur_state]) {
        DBG_PRINTF("Running plugin at state 0x%x", cnx->cur_state);
        return exec_loaded_code(cnx->plugins[cnx->cur_state], (void *)cnx, sizeof(picoquic_cnx_t));
    }

    printf("Cannot find plugin with id 0x%x\n", cnx->cur_state);

    return OPERATION_STOP;
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

int plugin_run_operations(picoquic_cnx_t *cnx, plugin_id_t initial_state, plugin_id_t max_state) {
    int status = OPERATION_OK;
    plugin_state_t *tmp;
    cnx->cur_state = initial_state;

    do {
        DBG_PRINTF("Run operation 0x%x", cnx->cur_state);
        if (!cnx->ops[cnx->cur_state]) {
            printf("FATAL ERROR: no function for state 0x%x\n", cnx->cur_state);
            exit(1);
        }
        status = cnx->ops[cnx->cur_state](cnx);

        /* Do we still have states to explore ? */
        if (status == OPERATION_OK && cnx->nxt_state) {
            tmp = cnx->nxt_state;
            cnx->nxt_state = tmp->nxt;
            cnx->cur_state = tmp->val;
            /* Keep free, as malloc was used for states */
            free(tmp);
        } else if (status == OPERATION_OK) {
            cnx->cur_state = max_state;
        }
    } while (cnx->cur_state < max_state && status == OPERATION_OK);

    /* Perform clean-up, as abrupt terminations might leave some unfree memory */
    while (cnx->nxt_state) {
        tmp = cnx->nxt_state;
        cnx->nxt_state = cnx->nxt_state->nxt;
        /* Keep free, as malloc was used for states */
        free(tmp);
    }

    DBG_PRINTF("Return status is 0x%x", status);

    return status;
}