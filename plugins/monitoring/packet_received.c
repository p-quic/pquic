#include "../helpers.h"
#include "bpf.h"

/**
 * See "header_parsed"
 * cnx->protoop_inputv[0] = picoquic_packet_header *ph
 * cnx->protoop_inputv[1] = picoquic_path_t *path
 * cnx->protoop_inputv[2] = size_t length
 *
 * Output: None
 */
protoop_arg_t packet_received(picoquic_cnx_t *cnx)
{
    monitoring_conn_metrics *metrics = get_monitoring_metrics(cnx);
    monitoring_path_metrics *path_metrics;
    picoquic_packet_header *ph = (picoquic_packet_header *) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_path_t *path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    size_t length = (size_t) get_cnx(cnx, AK_CNX_INPUT, 2);

    int epoch = (int) get_ph(ph, AK_PH_EPOCH);
    if (epoch != 1 && epoch != 3) {
        path_metrics = &metrics->handshake_metrics;
    } else {
        path_metrics = find_metrics_for_path(cnx, metrics, path);
    }
    path_metrics->metrics.data_recv += length;
    path_metrics->metrics.pkt_recv++;
    if (path_metrics == &metrics->handshake_metrics) {
        complete_path(path_metrics, cnx, path);
    }
    uint64_t recv_buf = get_cnx(cnx, AK_CNX_MAXDATA_LOCAL, 0) - get_cnx(cnx, AK_CNX_DATA_RECEIVED, 0);
    uint64_t peer_recv_buf = get_cnx(cnx, AK_CNX_MAXDATA_REMOTE, 0) - get_cnx(cnx, AK_CNX_DATA_SENT, 0);
    metrics->quic_metrics.max_recv_buf = recv_buf > metrics->quic_metrics.max_recv_buf ? recv_buf : metrics->quic_metrics.max_recv_buf;
    metrics->quic_metrics.peer_max_recv_buf = peer_recv_buf > metrics->quic_metrics.peer_max_recv_buf ? peer_recv_buf : metrics->quic_metrics.peer_max_recv_buf;
    return 0;
}