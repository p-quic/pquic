#include "uniform_redundancy_controller.h"
#include "../fec_protoops.h"

// sets as output the pointer towards the controller's state
protoop_arg_t packet_was_lost(picoquic_cnx_t *cnx)
{
    bpf_state *state = get_bpf_state(cnx);
    if (!state) return PICOQUIC_ERROR_MEMORY;
    uniform_redundancy_controller_t *urc = state->controller;
    urc->total_lost_packets++;
    return 0;
}