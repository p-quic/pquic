#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"


protoop_arg_t notify_datagram_frame(picoquic_cnx_t *cnx)
{
    reserve_frame_slot_t *rfs = (reserve_frame_slot_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    /* Commented out, can be used if needed */
    /* int received = (int) get_cnx(cnx, CNX_AK_INPUT, 1); */
    my_free(cnx, rfs);
    return 0;
}