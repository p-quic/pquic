#include "picoquic_internal.h"
#include "../bpf.h"

/**
 * Select the path on which the next packet will be sent.
 *
 * \param[in] retransmit_p \b picoquic_packet_t* The packet to be retransmitted, or NULL if none
 * \param[in] from_path \b picoquic_path_t* The path from which the packet originates, or NULL if none
 * \param[in] reason \b char* The reason why packet should be retransmitted, or NULL if none
 *
 * \return \b picoquic_path_t* The path on which the next packet will be sent.
 */
protoop_arg_t schedule_frames_on_path(picoquic_cnx_t *cnx)
{
    bpf_state *state = get_bpf_state(cnx);
    if (state->current_sfpid_frame) {
        my_free(cnx, state->current_sfpid_frame);
    }
    state->current_sfpid_frame = NULL;
    state->current_packet_contains_fpid_frame = false;
    state->current_packet_contains_fec_frame = false;
    state->cancel_sfpid_in_current_packet = false;
    return 0;
}