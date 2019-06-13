#include "../framework/window_framework_sender.h"
#include "../framework/window_framework_receiver.h"


protoop_arg_t receive_source_symbol(picoquic_cnx_t *cnx)
{
    bpf_state *state = get_bpf_state(cnx);
    if (!state)
        return PICOQUIC_ERROR_MEMORY;
    return (protoop_arg_t) window_receive_source_symbol(cnx, state, state->framework_receiver, (source_symbol_t *) get_cnx(cnx, AK_CNX_INPUT, 0), (bool) get_cnx(cnx, AK_CNX_INPUT, 1));
}