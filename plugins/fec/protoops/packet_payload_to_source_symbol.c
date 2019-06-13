#include "../../helpers.h"
#include "../fec_protoops.h"


// returns the length of the symbol
protoop_arg_t packet_payload_to_source_symbol(picoquic_cnx_t *cnx)
{
    uint8_t* bytes_protected = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    uint8_t *buffer = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    uint32_t payload_length = (uint32_t) get_cnx(cnx, AK_CNX_INPUT, 2);
    uint64_t sequence_number = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 3);
    bpf_state *state = get_bpf_state(cnx);
    state->current_symbol_length = 1 + sizeof(uint64_t) + (uint16_t) payload_length;
    if (!buffer) {
        return PICOQUIC_ERROR_MEMORY;
    }
    encode_u64(sequence_number, buffer + 1);
    buffer[0] = FEC_MAGIC_NUMBER;
    uint32_t offset_in_symbol = 0;
    uint32_t offset_in_packet_payload = 0;
    size_t consumed = 0;
    int pure_ack = 0;
    uint8_t first_byte = 0;

    while(offset_in_packet_payload < payload_length) {
        my_memcpy(&first_byte, bytes_protected + offset_in_packet_payload, 1);
        bool to_ignore = first_byte == picoquic_frame_type_ack || first_byte == picoquic_frame_type_padding || first_byte == picoquic_frame_type_crypto_hs;
        helper_skip_frame(cnx, bytes_protected + offset_in_packet_payload, payload_length - offset_in_packet_payload, &consumed, &pure_ack);
        if (!to_ignore) {
            my_memcpy(buffer + 1 + sizeof(uint64_t) + offset_in_symbol, bytes_protected + offset_in_packet_payload, consumed);
            offset_in_symbol += consumed;
        }
        offset_in_packet_payload += consumed;
    }
    PROTOOP_PRINTF(cnx, "SKIPPED %d BYTES IN SOURCE SYMBOL, SYMBOL SIZE = %d\n", offset_in_packet_payload - offset_in_symbol, 1 + sizeof(uint64_t) + offset_in_symbol);
    return 1 + sizeof(uint64_t) + offset_in_symbol;
}