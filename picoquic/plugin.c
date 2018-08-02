#include "plugin.h"
#include <stdlib.h>

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

int plugin_run_operations(picoquic_cnx_t *cnx, plugin_id_t initial_state, plugin_id_t max_state) {
    int status = PICOQUIC_OK;
    plugin_state_t *tmp;
    cnx->protoop_cur_state = initial_state;
    cnx->protoop_stop = 0;

    do {
        DBG_PLUGIN_PRINTF("Run operation 0x%x", cnx->protoop_cur_state);
        if (!cnx->ops[cnx->protoop_cur_state]) {
            printf("FATAL ERROR: no function for state 0x%x\n", cnx->protoop_cur_state);
            exit(1);
        }
        status = cnx->ops[cnx->protoop_cur_state](cnx);

        /* Do we still have states to explore ? */
        if (cnx->protoop_nxt_state) {
            tmp = cnx->protoop_nxt_state;
            cnx->protoop_nxt_state = tmp->nxt;
            cnx->protoop_cur_state = tmp->val;
            /* Keep free, as malloc was used for states */
            free(tmp);
        } else {
            cnx->protoop_cur_state = max_state;
        }
    } while (cnx->protoop_cur_state < max_state && cnx->protoop_stop == 0);

    /* Perform clean-up, as abrupt terminations might leave some unfree memory */
    while (cnx->protoop_nxt_state) {
        tmp = cnx->protoop_nxt_state;
        cnx->protoop_nxt_state = cnx->protoop_nxt_state->nxt;
        /* Keep free, as malloc was used for states */
        free(tmp);
    }

    DBG_PLUGIN_PRINTF("Return status is 0x%x, stopped is %d", status, cnx->protoop_stop);

    return status;
}