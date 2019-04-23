#include "picoquic_internal.h"
#include "../bpf.h"
#define MIN_BYTES_TO_RETRANSMIT_PROTECT 20

static __attribute__((always_inline)) bool is_mtu_probe(picoquic_packet_t *p, picoquic_path_t *path) {
    if (!p || !path) return false;
    // it is mtu if p->length + p->checksum_overhead > send_path->send_mtu
    return get_pkt(p, AK_PKT_LENGTH) + get_pkt(p, AK_PKT_CHECKSUM_OVERHEAD) > get_path(path, AK_PATH_SEND_MTU, 0);
}

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
    picoquic_packet_t *packet = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_packet_t *retransmit_p = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 3);
    picoquic_path_t *retransmit_path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 4);
    picoquic_path_t *chosen_path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_OUTPUT, 0);
    uint32_t length = get_cnx(cnx, AK_CNX_OUTPUT, 1);
    // set the current fpid
    bpf_state *state = get_bpf_state(cnx);


    // protect the source symbol
    uint8_t *data = (uint8_t *) get_pkt(packet, AK_PKT_BYTES);
    picoquic_packet_type_enum packet_type = get_pkt(packet, AK_PKT_TYPE);
//    uint32_t length = get_pkt(packet, AK_PKT_LENGTH);
    uint32_t header_length = get_pkt(packet, AK_PKT_OFFSET);
    PROTOOP_PRINTF(cnx, "PROTECT, LENGTH  %d, OFFSET = %d\n", length, header_length);

    if (state->current_sfpid_frame && (packet_type == picoquic_packet_1rtt_protected_phi0 || packet_type == picoquic_packet_1rtt_protected_phi1)){
        uint8_t *payload_with_pn = my_malloc(cnx, length - header_length + 1 + sizeof(uint64_t));
        // copy the packet payload without the header and put it 8 bytes after the start of the buffer
//        my_memcpy(payload_with_pn + 1 + sizeof(uint64_t), data + header_length, length - header_length);
//        uint64_t seqnum = (uint64_t) get_pkt(packet, AK_PKT_SEQUENCE_NUMBER);
//        encode_u64(seqnum, payload_with_pn + 1);
//        payload_with_pn[0] = FEC_MAGIC_NUMBER;




        protoop_arg_t args[4];
        args[0] = (protoop_arg_t) data + header_length;
        args[1] = (protoop_arg_t) payload_with_pn;
        args[2] = length - header_length;
        args[3] = get_pkt(packet, AK_PKT_SEQUENCE_NUMBER);
        uint32_t symbol_length = (uint32_t) run_noparam(cnx, "packet_payload_to_source_symbol", 4, args, NULL);





        int err = protect_packet(cnx, &state->current_sfpid_frame->source_fpid, payload_with_pn, symbol_length);
        my_free(cnx, payload_with_pn);
        if (err)
            return (protoop_arg_t) err;
    }
    if (state->current_sfpid_frame) {
        my_free(cnx, state->current_sfpid_frame);
        state->current_sfpid_frame = NULL;
    }






    // if no stream data to send, do not protect anything anymore
    void *ret = (void *) run_noparam(cnx, "find_ready_stream", 0, NULL, NULL);
    bool stream_to_send = false;
    if (ret) {
        // there is a stream frame to send only of we're not congestion blocked
        stream_to_send = get_path(chosen_path, AK_PATH_CWIN, 0) >= get_path(chosen_path, AK_PATH_BYTES_IN_TRANSIT, 0);
    }
    int is_pure_ack = is_mtu_probe(retransmit_p, retransmit_path) || (retransmit_p ? (int) get_pkt(retransmit_p, AK_PKT_IS_PURE_ACK) : 0);
    size_t len = retransmit_p ? (int) get_pkt(retransmit_p, AK_PKT_LENGTH) : 0;
    int ptype = retransmit_p ? (int) get_pkt(retransmit_p, AK_PKT_TYPE) : 6;
    int contains_crypto = retransmit_p ? (int) get_pkt(retransmit_p, AK_PKT_CONTAINS_CRYPTO) : 0;
    if (!stream_to_send && (!retransmit_p || is_pure_ack || contains_crypto || (ptype != picoquic_packet_1rtt_protected_phi0 && ptype != picoquic_packet_1rtt_protected_phi1))) {
        PROTOOP_PRINTF(cnx, "no stream data to send nor retransmission, do not send SFPID frame\n");
        state->cancel_sfpid_in_current_packet = true;
        if (!is_pure_ack && !contains_crypto)
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