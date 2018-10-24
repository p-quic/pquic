#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

protoop_arg_t after_received_segment(picoquic_cnx_t *cnx)
{
    /* We want to send an MP_ACK frame on the selected type */
    picoquic_path_t *path_x = (picoquic_path_t *) cnx->protoop_inputv[1];
    if (path_x != cnx->path[0]) {
        reserve_mp_ack_frame(cnx, path_x, picoquic_packet_context_application);
    }
    return 0;
}