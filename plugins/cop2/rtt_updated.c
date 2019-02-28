#include <picoquic_internal.h>
#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"

/**
 * See PROTOOP_NOPARAM_UPDATE_RTT
 */
protoop_arg_t rtt_updated(picoquic_cnx_t *cnx)
{
    cop2_conn_metrics *metrics = get_cop2_metrics(cnx);
    cop2_path_metrics *path_metrics;
    uint64_t ack_delay = 0;
    picoquic_state_enum cnx_state = (picoquic_state_enum) get_cnx(cnx, CNX_AK_STATE, 0);
    picoquic_path_t *path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_INPUT, 4);
    if (cnx_state < picoquic_state_client_ready) {
        path_metrics = &metrics->handshake_metrics;
        ack_delay = (uint64_t) get_pkt_ctx((picoquic_packet_context_t *) get_path(path_x, PATH_AK_PKT_CTX, picoquic_packet_context_handshake), PKT_CTX_AK_ACK_DELAY_LOCAL);
    } else {
        path_metrics = find_metrics_for_path(cnx, metrics, path_x);
        ack_delay = (uint64_t) get_pkt_ctx((picoquic_packet_context_t *) get_path(path_x, PATH_AK_PKT_CTX, picoquic_packet_context_application), PKT_CTX_AK_ACK_DELAY_LOCAL);
    }
    path_metrics->metrics.smoothed_rtt = (uint64_t) get_path(path_x, PATH_AK_SMOOTHED_RTT, 0);
    path_metrics->metrics.rtt_variance = (uint64_t) get_path(path_x, PATH_AK_RTT_VARIANT, 0);
    path_metrics->metrics.ack_delay = ack_delay;
    path_metrics->metrics.max_ack_delay = (uint64_t) get_path(path_x, PATH_AK_MAX_ACK_DELAY, 0);
    return 0;
}