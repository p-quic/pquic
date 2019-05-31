#include "bpf.h"

protoop_arg_t notify_path_update(picoquic_cnx_t *cnx)
{
    reserve_frame_slot_t *rfs = (reserve_frame_slot_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    /* Commented out, can be used if needed */
    /* int received = (int) get_cnx(cnx, AK_CNX_INPUT, 1); */
    my_free(cnx, rfs->frame_ctx);
    my_free(cnx, rfs);
    return 0;
}