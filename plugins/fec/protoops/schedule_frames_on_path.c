#include "picoquic.h"
#include "../fec_protoops.h"
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
    uint32_t length = get_cnx(cnx, AK_CNX_OUTPUT, 1);
    // set the current fpid
    bpf_state *state = get_bpf_state(cnx);


    // protect the source symbol
    uint8_t *data = (uint8_t *) get_pkt(packet, AK_PKT_BYTES);
    picoquic_packet_type_enum packet_type = retransmit_p ? get_pkt(retransmit_p, AK_PKT_TYPE) : get_pkt(packet, AK_PKT_TYPE);
    uint32_t header_length = get_pkt(packet, AK_PKT_OFFSET);


    if (state->current_sfpid_frame && (packet_type == picoquic_packet_1rtt_protected_phi0 || packet_type == picoquic_packet_1rtt_protected_phi1)){
        PROTOOP_PRINTF(cnx, "TRY TO PROTECT, LENGTH  %d, OFFSET = %d, retrans = %d\n", length, header_length, retransmit_p != NULL);
        uint8_t *payload_with_pn = my_malloc(cnx, length - header_length + 1 + sizeof(uint64_t));
        // copy the packet payload without the header and put it 8 bytes after the start of the buffer



        protoop_arg_t args[4];
        args[0] = (protoop_arg_t) data + header_length;
        args[1] = (protoop_arg_t) payload_with_pn;
        args[2] = length - header_length;
        args[3] = get_pkt(packet, AK_PKT_SEQUENCE_NUMBER);
        uint32_t symbol_length = (uint32_t) run_noparam(cnx, "packet_payload_to_source_symbol", 4, args, NULL);


        if (symbol_length <= 1 + sizeof(uint64_t) + 1 + sizeof(source_fpid_frame_t)) {
            // this symbol does not need to be protected: undo
            my_memset(state->written_sfpid_frame, 0, 1 + sizeof(source_fpid_frame_t));
            my_free(cnx, state->current_sfpid_frame);
            state->current_sfpid_frame = NULL;
        } else {
            int err = protect_packet(cnx, &state->current_sfpid_frame->source_fpid, payload_with_pn, symbol_length);
            if (err){
                PROTOOP_PRINTF(cnx, "ERROR WHILE PROTECTING\n");
                return (protoop_arg_t) err;
            }
        }

        my_free(cnx, payload_with_pn);
    }
    if (state->current_sfpid_frame) {
        my_free(cnx, state->current_sfpid_frame);
        state->current_sfpid_frame = NULL;

    }

    return 0;
}