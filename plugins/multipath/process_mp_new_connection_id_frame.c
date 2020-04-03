#include "bpf.h"


/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_mp_new_connection_id_frame(picoquic_cnx_t *cnx)
{ 
    mp_new_connection_id_frame_t *frame = (mp_new_connection_id_frame_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    uint64_t current_time = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 1);
    bpf_data *bpfd = get_bpf_data(cnx);

    int new_uniflow_index = 0;

    /* Find the path index in the array */
    int uniflow_index = mp_get_uniflow_index(cnx, bpfd, true, frame->uniflow_id, &new_uniflow_index);

    /* TODO: handle CIDs updates properly */
    uniflow_data_t *sending_uniflow = bpfd->sending_uniflows[uniflow_index];
    sending_uniflow->uniflow_id = frame->uniflow_id;
    sending_uniflow->cnxid.id_len = frame->ncidf.connection_id.id_len;
    my_memcpy(sending_uniflow->cnxid.id, frame->ncidf.connection_id.id, frame->ncidf.connection_id.id_len);
    my_memcpy(sending_uniflow->reset_secret, frame->ncidf.stateless_reset_token, 16);

    if (new_uniflow_index) {
        mp_sending_uniflow_ready(cnx, sending_uniflow, current_time);
    }

    return 0;
}