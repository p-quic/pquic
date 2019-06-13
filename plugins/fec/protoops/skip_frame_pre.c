#include "picoquic.h"
#include "../fec_protoops.h"


/**
 * cnx->protoop_inputv[0] = fec_frame_t* frame
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t skip_frame(picoquic_cnx_t *cnx)
{
    bpf_state *state = get_bpf_state(cnx);
    if (!state)
        return PICOQUIC_ERROR_MEMORY;
    state->is_in_skip_frame = true;
    return (protoop_arg_t) 0;
}