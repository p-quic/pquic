#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

protoop_arg_t after_decoding_frames(picoquic_cnx_t *cnx)
{
    /* We want to send an MP_ACK frame on the selected type */
    picoquic_path_t *path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    int ack_needed = (int) get_cnx(cnx, CNX_AK_INPUT, 1);
    picoquic_path_t *path_0 = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);

    if (path_x != path_0 && ack_needed) {
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