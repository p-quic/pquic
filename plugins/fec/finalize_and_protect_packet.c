#include <picoquic_internal.h>
#include <getset.h>
#include "bpf.h"

/**
 * See PROTOOP_NOPARAM_FINALIZE_AND_PROTECT_PACKET
 */
protoop_arg_t finalize_and_protect_packet(picoquic_cnx_t *cnx) {
    picoquic_packet_t *packet = (picoquic_packet_t *) get_cnx(cnx, CNX_AK_INPUT, 0); // packet length including header length, excluding checksum
    uint32_t length = (uint32_t) get_cnx(cnx, CNX_AK_INPUT, 2); // packet length including header length, excluding checksum
    int ret = (int) get_cnx(cnx, CNX_AK_INPUT, 1); // ret
    PROTOOP_PRINTF(cnx, "FINALIZE RET = %d\n", (protoop_arg_t) ret);
    picoquic_packet_type_enum packet_type = get_pkt(packet, PKT_AK_TYPE);
    uint8_t *data = (uint8_t *) get_pkt(packet, PKT_AK_BYTES);
    bpf_state *state = get_bpf_state(cnx);
    if (state->current_sfpid_frame && (packet_type == picoquic_packet_1rtt_protected_phi0 || packet_type == picoquic_packet_1rtt_protected_phi1)){
        int err = protect_packet(cnx, &state->current_sfpid_frame->source_fpid, data, (uint16_t) length);
        if (err)
            return (protoop_arg_t) err;
    }
    if (state->current_sfpid_frame) {
        my_free(cnx, state->current_sfpid_frame);
        state->current_sfpid_frame = NULL;
    }
    return 0;
}