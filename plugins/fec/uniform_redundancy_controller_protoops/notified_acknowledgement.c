#include "uniform_redundancy_controller.h"
#include "../fec_protoops.h"

// sets as output the pointer towards the controller's state
protoop_arg_t congestion_alg_notify(picoquic_cnx_t *cnx)
{
    picoquic_congestion_notification_t notification = get_cnx(cnx, AK_CNX_INPUT, 1);

    if (notification == picoquic_congestion_notification_acknowledgement) {
        bpf_state *state = get_bpf_state(cnx);
        if (!state) return PICOQUIC_ERROR_MEMORY;
        uniform_redundancy_controller_t *urc = state->controller;
        urc->total_acknowledged_packets++;
    }
    return 0;
}