#include "../../helpers.h"
#include "../fec_protoops.h"


protoop_arg_t notify_fpid_frame(picoquic_cnx_t *cnx)
{
    reserve_frame_slot_t *rfs = (reserve_frame_slot_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    /* Commented out, can be used if needed */
    /* int received = (int) get_cnx(cnx, AK_CNX_INPUT, 1); */
    my_free(cnx, rfs);
    return 0;
}