#include "picoquic_internal.h"
#include "../bpf.h"


/**
 * cnx->protoop_inputv[0] = fec_frame_t* frame
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t skip_frame(picoquic_cnx_t *cnx)
{
    bpf_state *state = get_bpf_state(cnx);
    state->is_in_skip_frame = false;
    return (protoop_arg_t) 0;
}