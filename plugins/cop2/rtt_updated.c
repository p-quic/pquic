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
    if (cnx->cnx_state < picoquic_state_client_ready) {
        path_metrics = &metrics->handshake_metrics;
    } else {
        path_metrics = find_metrics_for_path(cnx, metrics, (picoquic_path_t *) cnx->protoop_inputv[4]);
    }
    path_metrics->metrics.smoothed_rtt = ((picoquic_path_t *)cnx->protoop_inputv[4])->smoothed_rtt;
    path_metrics->metrics.rtt_variance = ((picoquic_path_t *)cnx->protoop_inputv[4])->rtt_variant;
    return 0;
}