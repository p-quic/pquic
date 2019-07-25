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
    int path_index = mp_get_path_index(cnx, bpfd, true, frame->path_id, &new_path_index);

    /* TODO: handle CIDs updates properly */
    path_data_t *sending_path = bpfd->sending_paths[path_index];
    sending_path->is_sending_path = true;
    sending_path->path_id = frame->path_id;
    sending_path->cnxid.id_len = frame->ncidf.connection_id.id_len;
    my_memcpy(sending_path->cnxid.id, frame->ncidf.connection_id.id, frame->ncidf.connection_id.id_len);
    my_memcpy(sending_path->reset_secret, frame->ncidf.stateless_reset_token, 16);

    if (new_path_index) {
        mp_sending_path_ready(cnx, sending_path, current_time);
    }

    return 0;
}