#include "../framework/window_framework_sender.c"
#include "../framework/window_framework_receiver.c"


protoop_arg_t receive_repair_symbol(picoquic_cnx_t *cnx)
{
    bpf_state *state = get_bpf_state(cnx);
    if (!state)
        return PICOQUIC_ERROR_MEMORY;
    uint8_t nss = (uint8_t) get_cnx(cnx, CNX_AK_INPUT, 2);
    uint8_t nrs = (uint8_t) get_cnx(cnx, CNX_AK_INPUT, 3);
    return (protoop_arg_t) window_receive_repair_symbol(cnx, (repair_symbol_t *) get_cnx(cnx, CNX_AK_INPUT, 1), nss, nrs);
}