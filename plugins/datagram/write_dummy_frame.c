#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

protoop_arg_t write_datagram_frame(picoquic_cnx_t* cnx)
{
    size_t consumed = 0;
    set_cnx(cnx, CNX_AK_OUTPUT, 0, (protoop_arg_t) consumed);
    return 0;
}