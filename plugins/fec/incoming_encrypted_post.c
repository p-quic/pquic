
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
    bpf_state *state = get_bpf_state(cnx);
    state->current_packet_length = 0;
    my_free(cnx, state->current_packet);
    state->current_packet = NULL;
    return 0;
}