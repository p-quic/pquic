#include "picoquic_internal.h"
#include "bpf.h"


/**
 * cnx->protoop_inputv[0] = picoquic_path_t *path_x
 * cnx->protoop_inputv[1] = picoquic_packet_t* packet
 * cnx->protoop_inputv[2] = uint64_t current_time
 * cnx->protoop_inputv[3] = uint8_t* send_buffer
 * cnx->protoop_inputv[4] = size_t send_buffer_max
 * cnx->protoop_inputv[5] = size_t send_length
 *
 * Output: error code (int)
 * cnx->protoop_outputv[0] = size_t send_length
 * cnx->protoop_outputv[1] = picoquic_path_t *path_x
 */
protoop_arg_t prepare_packet_ready(picoquic_cnx_t *cnx)
{
    // set the current fpid
    bpf_state *state = get_bpf_state(cnx);
    if (state->current_sfpid_frame) {
        my_free(cnx, state->current_sfpid_frame);
    }
    state->current_sfpid_frame = NULL;
    state->current_packet_contains_fpid_frame = false;
    state->current_packet_contains_fec_frame = false;

    // if no stream data to send, do not protect anything anymore
    void *ret = (void *) run_noparam(cnx, "find_ready_stream", 0, NULL, NULL);
    if (!ret) {
        PROTOOP_PRINTF(cnx, "no stream data to send, do not send SFPID frame\n");
        return 0;
    }

    // reserve a new frame to  send a FEC-protected packet
    reserve_frame_slot_t *slot = (reserve_frame_slot_t *) my_malloc(cnx, sizeof(reserve_frame_slot_t));
    if (!slot)
        return PICOQUIC_ERROR_MEMORY;
    slot->frame_type = SOURCE_FPID_TYPE;
    slot->nb_bytes = 1 + sizeof(source_fpid_frame_t);
    source_fpid_frame_t *f = (source_fpid_frame_t *) my_malloc(cnx, sizeof(source_fpid_frame_t));
    if (!f)
        return PICOQUIC_ERROR_MEMORY;
    slot->frame_ctx = f;

    f->source_fpid.fec_block_number = state->block_fec_framework->current_block_number;
    f->source_fpid.symbol_number = state->block_fec_framework->current_block->current_source_symbols;

    state->current_packet_contains_fec_frame = false;
    state->current_packet_contains_fpid_frame = false;

    size_t reserved_size = reserve_frames(cnx, 1, slot);
    PROTOOP_PRINTF(cnx, "RESERVE SFPID_FRAME %u, size = %d/%d\n", f->source_fpid.raw, reserved_size, slot->nb_bytes);
    if (reserved_size < slot->nb_bytes) {
        PROTOOP_PRINTF(cnx, "Unable to reserve frame slot\n");
        my_free(cnx, f);
        my_free(cnx, slot);
        return 1;
    }

    return 0;
}