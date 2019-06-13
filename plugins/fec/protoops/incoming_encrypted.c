#include "../fec_protoops.h"

/**
 * uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
 * picoquic_packet_header* ph = (picoquic_packet_header *) cnx->protoop_inputv[1];
 * struct sockaddr* addr_from = (struct sockaddr *) cnx->protoop_inputv[2];
 * uint64_t current_time = (uint64_t) cnx->protoop_inputv[3];
 *
 * Output: return code (int)
 */
protoop_arg_t incoming_encrypted(picoquic_cnx_t *cnx)
{
    uint8_t* bytes_protected = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0); //cnx->protoop_inputv[0];
    picoquic_packet_header* ph = (picoquic_packet_header *) get_cnx(cnx, AK_CNX_INPUT, 1); //cnx->protoop_inputv[1];
    bpf_state *state = get_bpf_state(cnx);
    uint8_t *bytes = my_malloc(cnx, 1 + sizeof(uint64_t) + (uint16_t) get_ph(ph, AK_PH_PAYLOAD_LENGTH));
    if (!bytes) {
        return PICOQUIC_ERROR_MEMORY;
    }
//    my_memcpy(bytes + 1 + sizeof(uint64_t), bytes_protected + (uint16_t) get_ph(ph, AK_PH_OFFSET), (uint16_t) get_ph(ph, AK_PH_PAYLOAD_LENGTH));
//    encode_u64(get_ph(ph, AK_PH_SEQUENCE_NUMBER), bytes + 1);
//    bytes[0] = FEC_MAGIC_NUMBER;

    protoop_arg_t args[4];
    args[0] = (protoop_arg_t) bytes_protected + get_ph(ph, AK_PH_OFFSET);
    args[1] = (protoop_arg_t) bytes;
    args[2] = get_ph(ph, AK_PH_PAYLOAD_LENGTH);
    args[3] = get_ph(ph, AK_PH_SEQUENCE_NUMBER);
    uint32_t symbol_length = (uint32_t) run_noparam(cnx, "packet_payload_to_source_symbol", 4, args, NULL);

    PROTOOP_PRINTF(cnx, "INCOMING, pn = 0x%x, data[9] = 0x%x, PAYLOAD LENGTH = %d, offset = %d\n", bytes[8], bytes[9], (uint16_t) get_ph(ph, AK_PH_PAYLOAD_LENGTH), (uint16_t) get_ph(ph, AK_PH_OFFSET));
    state->current_symbol = bytes;
    state->current_symbol_length = symbol_length;

    void *ret = (void *) run_noparam(cnx, "find_ready_stream", 0, NULL, NULL);
    if (!ret) {
        PROTOOP_PRINTF(cnx, "no stream data to send, do not send SFPID frame\n");
        flush_repair_symbols(cnx);
        return 0;
    }
    return 0;
}