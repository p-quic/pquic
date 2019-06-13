#include "../framework/block_framework_sender.h"
#include "../framework/block_framework_receiver.h"


// returns 0 if false
//         1 if true
// an error code != 0, 1 otherwise
protoop_arg_t receive_repair_symbol(picoquic_cnx_t *cnx)
{
    bpf_state *state = get_bpf_state(cnx);
    if (!state)
        return PICOQUIC_ERROR_MEMORY;
    uint8_t nss = (uint8_t) get_cnx(cnx, AK_CNX_INPUT, 2);
    uint8_t nrs = (uint8_t) get_cnx(cnx, AK_CNX_INPUT, 3);
    PROTOOP_PRINTF(cnx, "BLOCK RECEIVE RS\n");
    return (protoop_arg_t) block_receive_repair_symbol(cnx, (repair_symbol_t *) get_cnx(cnx, AK_CNX_INPUT, 1), nss, nrs);
}