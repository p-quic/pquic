#include <picoquic_internal.h>
#include <getset.h>
#include "bpf.h"




static __attribute__((always_inline)) uint32_t format_connection_id(uint8_t* bytes, size_t bytes_max, picoquic_connection_id_t *cnx_id)
{
    uint32_t copied = (uint32_t) get_cnxid(cnx_id, CNXID_AK_LEN);
    uint8_t *id = (uint8_t *) get_cnxid(cnx_id, CNXID_AK_ID);
    if (copied > bytes_max || copied == 0) {
        copied = 0;
    } else {
        my_memcpy(bytes, id, copied);
    }

    return copied;
}


static __attribute__((always_inline)) void headint_encode_32(uint8_t* bytes, uint64_t sequence_number)
{
    uint8_t* x = bytes;

    *x++ = (uint8_t)(((sequence_number >> 24) | 0xC0) & 0xFF);
    *x++ = (uint8_t)((sequence_number >> 16) & 0xFF);
    *x++ = (uint8_t)((sequence_number >> 8) & 0xFF);
    *x++ = (uint8_t)(sequence_number & 0xFF);
}


static __attribute__((always_inline)) void write_header(picoquic_cnx_t *cnx, picoquic_packet_t *packet, uint8_t *bytes) {
    picoquic_packet_type_enum packet_type = get_pkt(packet, PKT_AK_TYPE);

    picoquic_path_t *path = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);

    picoquic_connection_id_t *dest_cnx_id = (picoquic_connection_id_t *) get_path(path, PATH_AK_REMOTE_CID, 0);


//    picoquic_connection_id_t dest_cnx_id = * (picoquic_connection_id_t*) get_destination_connection_id(cnx, packet_type, cnx->path[0]);

    /* Create a short packet -- using 32 bit sequence numbers for now */
    uint8_t K = (packet_type == picoquic_packet_1rtt_protected_phi0) ? 0 : 0x40;
    const uint8_t C = 0x30;
    uint8_t spin_vec = (uint8_t) get_cnx(cnx, CNX_AK_SPIN_VEC, 0);
    uint8_t spin_bit = (uint8_t) get_cnx(cnx, CNX_AK_CURRENT_SPIN, 0) << 2;
    unsigned int spin_edge = (unsigned int) get_cnx(cnx, CNX_AK_SPIN_EDGE, 0);
    uint64_t spin_last_trigger = (uint64_t) get_cnx(cnx, CNX_AK_SPIN_LAST_TRIGGER, 0);
    uint64_t seqnum = (uint64_t) get_pkt(packet, PKT_AK_SEQUENCE_NUMBER);

    // for a source symbol, spin_bit is set to 0 and the spin_vec is always marked as LATE, to avoid differences between the source symbol and the real packet, because it depends on the clock
    spin_vec = 1;
    spin_bit = 0;

//    if (!spin_edge) spin_vec = 0;
//    else {
//        spin_vec = 1;
//
//
//        spin_edge = 0;
//        uint64_t dt = picoquic_current_time() - spin_last_trigger;
//        if (dt > PICOQUIC_SPIN_VEC_LATE) { // DELAYED
//            spin_vec = 1;
//            // fprintf(stderr, "Delayed Outgoing Spin=%d DT=%ld\n", cnx->current_spin, dt);
//        }
//    }

    uint32_t length = 0;
    bytes[length++] = (K | C | spin_bit | spin_vec);
    length += format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, dest_cnx_id);

    headint_encode_32(&bytes[length], seqnum);
    length += 4;
}


/**
 * See PROTOOP_NOPARAM_FINALIZE_AND_PROTECT_PACKET
 */
protoop_arg_t finalize_and_protect_packet(picoquic_cnx_t *cnx) {
    picoquic_packet_t *packet = (picoquic_packet_t *) get_cnx(cnx, CNX_AK_INPUT, 0); // packet length including header length, excluding checksum
    uint32_t length = (uint32_t) get_cnx(cnx, CNX_AK_INPUT, 2); // packet length including header length, excluding checksum
    int ret = (int) get_cnx(cnx, CNX_AK_INPUT, 1); // ret
    picoquic_packet_type_enum packet_type = get_pkt(packet, PKT_AK_TYPE);
    uint8_t *data = (uint8_t *) get_pkt(packet, PKT_AK_BYTES);
    bpf_state *state = get_bpf_state(cnx);
    if (state->current_sfpid_frame && (packet_type == picoquic_packet_1rtt_protected_phi0 || packet_type == picoquic_packet_1rtt_protected_phi1)){
        uint8_t *data_with_header = my_malloc(cnx, length);
        my_memcpy(data_with_header, data, length);
        write_header(cnx, packet, data_with_header);
        int err = protect_packet(cnx, &state->current_sfpid_frame->source_fpid, data_with_header, (uint16_t) length);
        my_free(cnx, data_with_header);
        if (err)
            return (protoop_arg_t) err;
    }
    if (state->current_sfpid_frame) {
        my_free(cnx, state->current_sfpid_frame);
        state->current_sfpid_frame = NULL;
    }
    return 0;
}