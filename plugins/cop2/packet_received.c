#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"

/**
 * cnx->protoop_inputv[0] = size_t len
 * cnx->protoop_inputv[1] = picoquic_path_t *path
 *
 * Output: None
 */
protoop_arg_t packet_received(picoquic_cnx_t *cnx)
{
    cop2_conn_metrics *metrics = get_cop2_metrics(cnx);
    cop2_path_metrics *path_metrics;
    if (cnx->cnx_state < picoquic_state_client_ready) {
        path_metrics = &metrics->handshake_metrics;
    } else {
        path_metrics = find_metrics_for_path(cnx, metrics, (picoquic_path_t *) cnx->protoop_inputv[1]);
    }
    path_metrics->metrics.data_recv += cnx->protoop_inputv[0];
    return 0;
}