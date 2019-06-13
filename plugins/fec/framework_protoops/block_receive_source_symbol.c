#include "../framework/block_framework_sender.h"
#include "../framework/block_framework_receiver.h"


protoop_arg_t receive_source_symbol(picoquic_cnx_t *cnx)
{
    bpf_state *state = get_bpf_state(cnx);
    if (!state)
        return PICOQUIC_ERROR_MEMORY;
    return (protoop_arg_t) block_receive_source_symbol(cnx, state, (source_symbol_t *) get_cnx(cnx, AK_CNX_INPUT, 0), (bool) get_cnx(cnx, AK_CNX_INPUT, 1));
}