#include "plugin.h"
#include <stdlib.h>
#include <string.h>

protoop_arg_t plugin_run_plugged_code(picoquic_cnx_t *cnx) {
    if (cnx->plugins[cnx->protoop_id]) {
        DBG_PLUGIN_PRINTF("Running plugin at proto op id 0x%x", cnx->protoop_id);
        return (protoop_arg_t) exec_loaded_code(cnx->plugins[cnx->protoop_id], (void *)cnx, sizeof(picoquic_cnx_t));
    }

    printf("Cannot find plugin with proto op id 0x%x\n", cnx->protoop_id);
    exit(-1);
    return -1;
}

int plugin_plug_elf(picoquic_cnx_t *cnx, protoop_id_t pid, char *elf_fname) {
    cnx->plugins[pid] = load_elf_file(elf_fname);

    if (cnx->plugins[pid]) {
        cnx->ops[pid] = &plugin_run_plugged_code;
        return 0;
    }

    printf("Failed to insert %s for proto op id 0x%x\n", elf_fname, pid);

    return 1;
}

protoop_arg_t plugin_run_protoop(picoquic_cnx_t *cnx, protoop_id_t pid, int inputc, uint64_t *inputv, uint64_t *outputv) {
    cnx->protoop_id = pid;

    if (inputc > PROTOOPARGS_MAX) {
        printf("Too many arguments for protocol operation with id 0x%x : %d > %d\n",
            pid, inputc, PROTOOPARGS_MAX);
        return PICOQUIC_ERROR_PROTOCOL_OPERATION_TOO_MANY_ARGUMENTS;
    }

    if (!cnx->ops[pid]) {
        printf("FATAL ERROR: no protocol operation with id 0x%x\n", pid);
        exit(-1);
    }

    /* First save previous args, and update context with new ones
     * Notice that we store ALL array of protoop_inputv and protoop_outputv.
     * With this, even if the called plugin tried to modify the input arguments,
     * they will remain unchanged at caller side.
     */
    int caller_inputc = cnx->protoop_inputc;
    uint64_t *caller_inputv[PROTOOPARGS_MAX];
    uint64_t *caller_outputv[PROTOOPARGS_MAX];
    memcpy(caller_inputv, cnx->protoop_inputv, sizeof(uint64_t) * PROTOOPARGS_MAX);
    memcpy(caller_outputv, cnx->protoop_outputv, sizeof(uint64_t) * PROTOOPARGS_MAX);
    memcpy(cnx->protoop_inputv, inputv, sizeof(uint64_t) * inputc);
    cnx->protoop_inputc = inputc;

#ifdef DBG_PLUGIN_PRINTF
    for (int i = 0; i < inputc; i++) {
        DBG_PLUGIN_PRINTF("Arg %d: 0x%lx", i, inputv[i]);
    }
#endif

    /* Also set protoop_outputv to 0, to prevent callee to see caller state */
    memset(cnx->protoop_outputv, 0, sizeof(uint64_t) * PROTOOPARGS_MAX);
    cnx->protoop_outputc_callee = 0;

    DBG_PLUGIN_PRINTF("Running operation with id 0x%x with %d inputs", pid, inputc);

    protoop_arg_t status = cnx->ops[pid](cnx);
    int outputc = cnx->protoop_outputc_callee;

    DBG_PLUGIN_PRINTF("Protocol operation with id 0x%x returns 0x%lx with %d additional outputs", pid, status, outputc);

    /* Copy the output of the caller to the provided output pointer (if any)... */
    if (outputv) {
        memcpy(outputv, cnx->protoop_outputv, sizeof(uint64_t) * outputc);
#ifdef DBG_PLUGIN_PRINTF
        for (int i = 0; i < outputc; i++) {
            DBG_PLUGIN_PRINTF("Out %d: 0x%lx", i, outputv[i]);
        }
#endif
    } else if (outputc > 0) {
        printf("WARNING: no output value provided for protocol operation with id 0x%x that returns %d additional outputs\n", pid, outputc);
        printf("HINT: this is probably not what you want, so maybe check if you called the right protocol operation...\n");
    }

    /* ... and restore ALL the previous inputs and outputs */
    memcpy(cnx->protoop_inputv, caller_inputv, sizeof(uint64_t) * PROTOOPARGS_MAX);
    memcpy(cnx->protoop_outputv, caller_outputv, sizeof(uint64_t) * PROTOOPARGS_MAX);
    cnx->protoop_inputc = caller_inputc;

    return status;
}