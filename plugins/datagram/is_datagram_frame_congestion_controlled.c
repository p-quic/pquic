#include "picoquic_internal.h"

#ifdef DATAGRAM_CONGESTION_CONTROLLED
#define DCC true
#else
#define DCC false
#endif

protoop_arg_t is_datagram_frame_congestion_controlled(picoquic_cnx_t* cnx)
{
    return DCC;
}