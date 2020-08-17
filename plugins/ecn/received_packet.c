#include "picoquic.h"
#include "plugin.h"
#include "bpf.h"

/**
 * See "received_packet"
 * cnx->protoop_inputv[0] = SOCKET_TYPE socket
 * cnx->protoop_inputv[1] = int tos
 *
 * Output: None
 */
protoop_arg_t received_packet(picoquic_cnx_t *cnx)
{
    int tos = (int) get_cnx(cnx, AK_CNX_INPUT, 1);
    get_bpf_data(cnx)->ecn_val = tos & 0x03;
    return 0;
}