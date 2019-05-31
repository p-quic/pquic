#include "picoquic.h"
#include "plugin.h"
#include "bpf.h"

/**
 * See "before_sending_packet"
 * cnx->protoop_inputv[0] = SOCKET_TYPE socket
 * 
 * Output: None
 */
protoop_arg_t before_sending_packet(picoquic_cnx_t *cnx)
{
    /* FIXME only for Linux! */
    int socket = (int) get_cnx(cnx, AK_CNX_INPUT, 0);
    bpf_data *bpfd = get_bpf_data(cnx);

    uint32_t flag = 1 << socket;
    if (bpfd->ecn_sock_flags & flag) {
        /* Already done, don't flood with setsockopt (can drop performance by ~33% otherwise!) */
        return 0;
    }

    int ecn_val = 1;
    int ecn_ip_tos = 1; // For ECT(0)
    // int ecn_ip_tos = 2; // For ECT(1)

    /* FIXME what if the socket is IPv6? */
    setsockopt(socket, IPPROTO_IP, IP_RECVTOS, &ecn_val, sizeof(ecn_val));
    setsockopt(socket, IPPROTO_IP, IP_TOS, &ecn_ip_tos, sizeof(ecn_ip_tos));

    bpfd->ecn_sock_flags |= flag;

    return 0;
}