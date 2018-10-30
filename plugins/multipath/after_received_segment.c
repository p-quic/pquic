#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

protoop_arg_t after_received_segment(picoquic_cnx_t *cnx)
{
    /* We want to send an MP_ACK frame on the selected type */
    picoquic_path_t *path_x = (picoquic_path_t *) cnx->protoop_inputv[1];
    if (path_x != cnx->path[0]) {
        bool should_reserve = true;
        bpf_data *bpfd = get_bpf_data(cnx);
        for (int i = 0; i < MAX_PATHS; i++) { /* TODO again, need clean support */
            if (bpfd->ack_ok_paths[i] == path_x) {
                should_reserve = false;
                break;
            }
        }
        if (should_reserve) {
            reserve_mp_ack_frame(cnx, path_x, picoquic_packet_context_application);
            for (int i = 0; i < MAX_PATHS; i++) {
                if (bpfd->ack_ok_paths[i] == NULL) {
                    bpfd->ack_ok_paths[i] = path_x;
                    break;
                }
            }
        }
    }
    return 0;
}