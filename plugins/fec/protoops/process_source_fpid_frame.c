#include "picoquic.h"
#include "../fec_protoops.h"

/**
 * cnx->protoop_inputv[0] = source_fpid_frame_t* frame
 * cnx->protoop_inputv[1] = const uint8_t* bytes_max
 * cnx->protoop_inputv[2] = uint64_t current_time
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t process_source_fpid_frame(picoquic_cnx_t *cnx)
{
    source_fpid_frame_t *frame = (source_fpid_frame_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    PROTOOP_PRINTF(cnx, "PROCESS SFPID FRAME\n");
    bpf_state *state = get_bpf_state(cnx);
    if (!state) {
        return PICOQUIC_ERROR_MEMORY;
    }
    uint8_t *payload = state->current_symbol;
    if (payload){
        source_symbol_t *ss = malloc_source_symbol_with_data(cnx, frame->source_fpid, payload, state->current_symbol_length);
        int ret = receive_source_symbol_helper(cnx, ss);
        if (ret != 1) {
            free_source_symbol(cnx, ss);
            if (ret != 0) return (protoop_arg_t) ret;
        }
    } else {
        PROTOOP_PRINTF(cnx, "NO PACKET PAYLOAD TO PROTECT\n");
    }
    return (protoop_arg_t) 0;
}