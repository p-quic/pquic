#include "bpf.h"


/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_mp_new_connection_id_frame(picoquic_cnx_t *cnx)
{ 
    mp_new_connection_id_frame_t *frame = (mp_new_connection_id_frame_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    uint64_t current_time = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 1);
    bpf_data *bpfd = get_bpf_data(cnx);

    int new_path_index = 0;

    /* Find the path index in the array */
    int path_index = mp_get_path_index(cnx, bpfd, frame->path_id, &new_path_index);

    bpfd->paths[path_index]->path_id = frame->path_id;
    bpfd->paths[path_index]->remote_cnxid.id_len = frame->ncidf.connection_id.id_len;
    my_memcpy(bpfd->paths[path_index]->remote_cnxid.id, frame->ncidf.connection_id.id, frame->ncidf.connection_id.id_len);
    my_memcpy(bpfd->paths[path_index]->reset_secret, frame->ncidf.stateless_reset_token, 16);

    bpfd->nb_proposed_rcv++;

    if (!new_path_index && bpfd->paths[path_index]->local_cnxid.id_len > 0 && bpfd->paths[path_index]->state == path_proposed) {
        mp_path_ready(cnx, bpfd->paths[path_index], current_time);
    } 
    if (new_path_index) {
        bpfd->paths[path_index]->state = path_proposed;
    }

    return 0;
}