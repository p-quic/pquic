#include "../framework/block_framework_sender.h"


protoop_arg_t block_flush_repair_symbols(picoquic_cnx_t *cnx)
{
    block_fec_framework_t *bff = (block_fec_framework_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    return (protoop_arg_t) flush_fec_block(cnx, bff);
}