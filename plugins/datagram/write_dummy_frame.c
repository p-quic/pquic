#include "../helpers.h"
#include "bpf.h"

protoop_arg_t write_datagram_frame(picoquic_cnx_t* cnx)
{
    size_t consumed = 0;
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) consumed);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) consumed);
    return 0;
}