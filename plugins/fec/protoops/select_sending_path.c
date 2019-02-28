#include "picoquic_internal.h"
#include "../bpf.h"
#define MIN_BYTES_TO_RETRANSMIT_PROTECT 20

/**
 * Select the path on which the next packet will be sent.
 *
 * \param[in] retransmit_p \b picoquic_packet_t* The packet to be retransmitted, or NULL if none
 * \param[in] from_path \b picoquic_path_t* The path from which the packet originates, or NULL if none
 * \param[in] reason \b char* The reason why packet should be retransmitted, or NULL if none
 *
 * \return \b picoquic_path_t* The path on which the next packet will be sent.
 */
protoop_arg_t select_sending_path(picoquic_cnx_t *cnx)
{
    picoquic_packet_t *retransmit_p = (picoquic_packet_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    // set the current fpid
    bpf_state *state = get_bpf_state(cnx);
    if (state->current_sfpid_frame) {
        my_free(cnx, state->current_sfpid_frame);
    }
    state->current_sfpid_frame = NULL;
    state->current_packet_contains_fpid_frame = false;
    state->current_packet_contains_fec_frame = false;
    state->cancel_sfpid_in_current_packet = false;

    // if no stream data to send, do not protect anything anymore
    void *ret = (void *) run_noparam(cnx, "find_ready_stream", 0, NULL, NULL);
    int is_pure_ack = retransmit_p ? (int) get_pkt(retransmit_p, PKT_AK_IS_PURE_ACK) : 0;
    size_t len = retransmit_p ? (int) get_pkt(retransmit_p, PKT_AK_LENGTH) : 0;
    PROTOOP_PRINTF(cnx, "IS_PURE_ACK = %d, LENGTH = %d, READY STREAM = %p\n", (protoop_arg_t) is_pure_ack, len, (protoop_arg_t) ret);
    if (!ret && (!retransmit_p || is_pure_ack)) {
        PROTOOP_PRINTF(cnx, "no stream data to send nor retransmission, do not send SFPID frame\n");
        state->cancel_sfpid_in_current_packet = true;
        if (!is_pure_ack)
            flush_repair_symbols(cnx);
        return 0;
    }

    if (!state->sfpid_reserved) {    // there is no frame currently reserved, so reserve one to protect this packet
        // we need to reserve a new one
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

        source_fpid_t s;

        protoop_arg_t ret = set_source_fpid(cnx, &s);
        if (ret)
            return ret;

        f->source_fpid.raw = s.raw;

        size_t reserved_size = reserve_frames(cnx, 1, slot);

        PROTOOP_PRINTF(cnx, "RESERVE SFPID_FRAME %u, size = %d/%d\n", f->source_fpid.raw, reserved_size, slot->nb_bytes);
        if (reserved_size < slot->nb_bytes) {
            PROTOOP_PRINTF(cnx, "Unable to reserve frame slot\n");
            my_free(cnx, f);
            my_free(cnx, slot);
            return 1;
        }
        state->sfpid_reserved = true;
    }   // else, an SFPID frame is already reserved, so we keep the frame that is currently reserved

    return 0;
}