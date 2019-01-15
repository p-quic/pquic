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
        path_data_t *pd = mp_get_path_data(bpfd, path_x);
        if (pd && !pd->doing_ack) {
            reserve_mp_ack_frame(cnx, path_x, picoquic_packet_context_application);
            pd->doing_ack = true;

            /* Initially, we only reserved for the path we received the packet. But we should send MP ACK for ALL paths! */
            for (int i = 0; i < bpfd->nb_proposed; i++) {
                path_data_t *pdtmp = &bpfd->paths[i];
                if (pdtmp != pd && !pdtmp->doing_ack) {
                    reserve_mp_ack_frame(cnx, pdtmp->path, picoquic_packet_context_application);
                    pdtmp->doing_ack = true;
                }
            }
        }
    }
    return 0;
}