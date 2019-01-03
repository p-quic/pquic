
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "memory.h"
#include "bpf.h"

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
    uint8_t* bytes_protected = (uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 0); //cnx->protoop_inputv[0];
    picoquic_packet_header* ph = (picoquic_packet_header *) get_cnx(cnx, CNX_AK_INPUT, 1); //cnx->protoop_inputv[1];
    bpf_state *state = get_bpf_state(cnx);
    state->current_packet_length = (uint16_t) get_ph(ph, PH_AK_OFFSET) + (uint16_t) get_ph(ph, PH_AK_PAYLOAD_LENGTH);
    uint8_t *bytes = my_malloc(cnx, state->current_packet_length);
    if (!bytes) {
        return PICOQUIC_ERROR_MEMORY;
    }
    my_memcpy(bytes, bytes_protected, state->current_packet_length);
    state->current_packet = bytes;
    return 0;
}