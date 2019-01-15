#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"


protoop_arg_t notify_mp_new_connection_id_frame(picoquic_cnx_t *cnx)
{
    /* FIXME make me loss resilient */
    reserve_frame_slot_t *rfs = (reserve_frame_slot_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    int received = (int) get_cnx(cnx, CNX_AK_INPUT, 1);

    mp_new_connection_id_ctx_t *mncic = (mp_new_connection_id_ctx_t *) rfs->frame_ctx;
    
    my_free(cnx, rfs);

    if (!received) {
        PROTOOP_PRINTF(cnx, "Should handle a lost mp new connection id!\n");
        reserve_mp_new_connection_id_frame(cnx, mncic->path_id);
    } else {
        PROTOOP_PRINTF(cnx, "mp new connection id: ok!\n");
        /* If we are the client, start the party! */
        int client_mode = (int) get_cnx(cnx, CNX_AK_CLIENT_MODE, 0);
        if (client_mode) {
            bpf_data *bpfd = get_bpf_data(cnx);
            int new_path_index = 0;
            int path_index = mp_get_path_index(bpfd, mncic->path_id, &new_path_index);
            if (path_index < 0 || new_path_index) {
                PROTOOP_PRINTF(cnx, "This should never happen in notify mp_new_connection_id_frame...\n");
            }
            mp_path_ready(cnx, &bpfd->paths[path_index], picoquic_current_time());
        }
    }

    my_free(cnx, mncic);

    return 0;
}