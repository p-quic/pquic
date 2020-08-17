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

    int read_ecn = 1;
    int ecn_ip_tos = 1; // For ECT(0)
    // int ecn_ip_tos = 2; // For ECT(1)

    setsockopt(socket, IPPROTO_IP, IP_RECVTOS, &read_ecn, sizeof(read_ecn));
    setsockopt(socket, IPPROTO_IP, IP_TOS, &ecn_ip_tos, sizeof(ecn_ip_tos));

    setsockopt(socket, IPPROTO_IPV6, IPV6_RECVTCLASS, &read_ecn, sizeof(read_ecn));
    setsockopt(socket, IPPROTO_IPV6, IPV6_TCLASS, &ecn_ip_tos, sizeof(ecn_ip_tos));

    bpfd->ecn_sock_flags |= flag;

    return 0;
}