#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"


protoop_arg_t notify_mp_new_connection_id_frame(picoquic_cnx_t *cnx)
{
    /* FIXME make me loss resilient */
    reserve_frame_slot_t *rfs = (reserve_frame_slot_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    int received = (int) get_cnx(cnx, AK_CNX_INPUT, 1);

    mp_new_connection_id_ctx_t *mncic = (mp_new_connection_id_ctx_t *) rfs->frame_ctx;
    
    my_free(cnx, rfs);

    if (!received) {
        PROTOOP_PRINTF(cnx, "Should handle a lost mp new connection id!\n");
        reserve_mp_new_connection_id_frame(cnx, mncic->uniflow_id);
    } else {
        PROTOOP_PRINTF(cnx, "mp new connection id: ok!\n");
        /* Actually, not much to do! */
    }

    my_free(cnx, mncic);

    return 0;
}