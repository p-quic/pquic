#include "../../helpers.h"

protoop_arg_t is_sfpid_frame_congestion_controlled(picoquic_cnx_t* cnx)
{
    PROTOOP_PRINTF(cnx, "IS SFPID CC\n");
    return false;
}