
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "plugin.h"
#include "memory.h"
#include "../helpers.h"
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
    protoop_arg_t arg[1];
    arg[0] = sizeof(fec_frame_header_t);
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    picoquic_packet_header* ph = (picoquic_packet_header *) cnx->protoop_inputv[1];
    bpf_state *state = get_bpf_state(cnx);
    state->current_packet = bytes + ph->offset;
    state->current_packet_length = ph->payload_length;
    return 0;
}