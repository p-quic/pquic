#include "../helpers.h"
#include "bpf.h"

protoop_arg_t get_max_message_size(picoquic_cnx_t* cnx)
{
    return get_max_datagram_size(cnx);
}