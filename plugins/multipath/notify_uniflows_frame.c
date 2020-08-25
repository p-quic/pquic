#include "bpf.h"

protoop_arg_t notify_uniflows_frame(picoquic_cnx_t *cnx)
{
    reserve_frame_slot_t *rfs = (reserve_frame_slot_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    /* Commented out, can be used if needed */
    int received = (int) get_cnx(cnx, AK_CNX_INPUT, 1);
    if (!received) {
        ((uniflow_data_t *)rfs->frame_ctx)->has_sent_uniflows_frame = false;
    }
    my_free(cnx, rfs);
    return 0;
}