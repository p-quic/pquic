#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"

/**
 * cnx->protoop_inputv[0] = picoquic_packet_header *ph
 * cnx->protoop_inputv[1] = picoquic_path_t *path
 * cnx->protoop_inputv[2] = size_t length
 *
 * Output: None
 */
protoop_arg_t packet_received(picoquic_cnx_t *cnx)
{
    cop2_conn_metrics *metrics = get_cop2_metrics(cnx);
    cop2_path_metrics *path_metrics;
    picoquic_path_t *path = (picoquic_path_t *) cnx->protoop_inputv[1];

    if (cnx->cnx_state < picoquic_state_client_ready) {
        path_metrics = &metrics->handshake_metrics;
    } else {
        path_metrics = find_metrics_for_path(cnx, metrics, path);
    }
    path_metrics->metrics.data_recv += cnx->protoop_inputv[2];
    path_metrics->metrics.pkt_recv++;
    if (path_metrics == &metrics->handshake_metrics) {
        complete_path(path_metrics, cnx, path);
    }
    return 0;
}