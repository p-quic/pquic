#include "../helpers.h"
#include "bpf.h"

/**
 * See PROTOOP_NOPARAM_UPDATE_RTT
 */
protoop_arg_t rtt_updated(picoquic_cnx_t *cnx)
{
    cop2_conn_metrics *metrics = get_cop2_metrics(cnx);
    cop2_path_metrics *path_metrics;
    picoquic_state_enum cnx_state = (picoquic_state_enum) get_cnx(cnx, AK_CNX_STATE, 0);
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) get_cnx(cnx, AK_CNX_INPUT, 3);
    picoquic_path_t *path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 4);
    picoquic_packet_context_t *pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, AK_PATH_PKT_CTX, pc);

    if (cnx_state < picoquic_state_client_ready) {
        path_metrics = &metrics->handshake_metrics;
    } else {
        path_metrics = find_metrics_for_path(cnx, metrics, path_x);
    }

    path_metrics->metrics.smoothed_rtt = (uint64_t) get_path(path_x, AK_PATH_SMOOTHED_RTT, 0);
    path_metrics->metrics.rtt_variance = (uint64_t) get_path(path_x, AK_PATH_RTT_VARIANT, 0);
    path_metrics->metrics.ack_delay = (uint64_t) get_pkt_ctx(pkt_ctx, AK_PKTCTX_ACK_DELAY_LOCAL);
    path_metrics->metrics.max_ack_delay = (uint64_t) get_path(path_x, AK_PATH_MAX_ACK_DELAY, 0);
    return 0;
}