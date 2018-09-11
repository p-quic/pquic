#include "picoquic_internal.h"
#include "plugin.h"
#include "bpf.h"

/**
 * cnx->protoop_inputv[0] = SOCKET_TYPE socket
 * 
 * Output: None
 */
protoop_arg_t received_packet(picoquic_cnx_t *cnx)
{
    /* FIXME only for Linux! */
    int socket = (int) cnx->protoop_inputv[0];
    bpf_data *bpfd = get_bpf_data(cnx);

    /* FIXME what if the socket is IPv6? */
    socklen_t ecn_val_len = sizeof(bpfd->ecn_val);
    getsockopt(socket, IPPROTO_IP, IP_TOS, &(bpfd->ecn_val), &ecn_val_len);

    uint32_t ecn_val = bpfd->ecn_val & 0x03;
    switch (ecn_val) {
    case 1:
        bpfd->ecn_ect0_marked_pkts++;
        break;
    case 2:
        bpfd->ecn_ect1_marked_pkts++;
        break;
    case 3:
        bpfd->ecn_ect_ce_marked_pkts++;
        break;
    default:
        break;
    }

    return 0;
}