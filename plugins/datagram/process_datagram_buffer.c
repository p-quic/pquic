#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

protoop_arg_t op_process_datagram_buffer(picoquic_cnx_t* cnx)
{
    process_datagram_buffer(get_datagram_memory(cnx), cnx);
    return 0;
}