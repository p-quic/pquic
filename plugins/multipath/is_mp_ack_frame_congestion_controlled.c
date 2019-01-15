#include "picoquic.h"

#ifdef DATAGRAM_CONGESTION_CONTROLLED
#define DCC true
#else
#define MPACKCC false
#endif

protoop_arg_t is_mp_ack_frame_congestion_controlled(picoquic_cnx_t* cnx)
{
    return MPACKCC;
}