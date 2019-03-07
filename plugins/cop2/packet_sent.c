#include "picoquic_internal.h"
#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"

/**
 * See "before_sending"
 * cnx->protoop_inputv[0] = picoquic_packet_header *ph
 * cnx->protoop_inputv[1] = picoquic_path_t *path
 * cnx->protoop_inputv[2] = picoquic_packet_t *packet
 * cnx->protoop_inputv[3] = size_t length
 *
 * Output: None
 */
protoop_arg_t packet_sent(picoquic_cnx_t *cnx)
{
    cop2_conn_metrics *metrics = get_cop2_metrics(cnx);
    cop2_path_metrics *path_metrics;
    picoquic_packet_header *ph = (picoquic_packet_header *) get_cnx(cnx, CNX_AK_INPUT, 0);
    picoquic_path_t *path = (picoquic_path_t *) get_cnx(cnx, CNX_AK_INPUT, 1);
    picoquic_packet_t *packet = (picoquic_packet_t *) get_cnx(cnx, CNX_AK_INPUT, 2);
    size_t length = (size_t) get_cnx(cnx, CNX_AK_INPUT, 3);

    uint64_t plen = get_pkt(packet, PKT_AK_LENGTH);
    if (plen == 0 || plen <= get_pkt(packet, PKT_AK_OFFSET)) {
        return 0; // This packet is empty
    }

    int epoch = (int) get_ph(ph, PH_AK_EPOCH);
    if (epoch != 1 && epoch != 3) {
        path_metrics = &metrics->handshake_metrics;
    } else {
        path_metrics = find_metrics_for_path(cnx, metrics, path);
    }
    path_metrics->metrics.data_sent += length;
    path_metrics->metrics.pkt_sent++;
    if (get_pkt(packet, PKT_AK_IS_PURE_ACK)) {
        path_metrics->metrics.pkt_pure_ack_sent++;
    }
    if (path_metrics == &metrics->handshake_metrics) {
        complete_path(path_metrics, cnx, path);
    }
    uint64_t recv_buf = get_cnx(cnx, CNX_AK_MAXDATA_LOCAL, 0) - get_cnx(cnx, CNX_AK_DATA_RECEIVED, 0);
    uint64_t peer_recv_buf = get_cnx(cnx, CNX_AK_MAXDATA_REMOTE, 0) - get_cnx(cnx, CNX_AK_DATA_SENT, 0);
    metrics->quic_metrics.max_recv_buf = recv_buf > metrics->quic_metrics.max_recv_buf ? recv_buf : metrics->quic_metrics.max_recv_buf;
    metrics->quic_metrics.peer_max_recv_buf = peer_recv_buf > metrics->quic_metrics.peer_max_recv_buf ? peer_recv_buf : metrics->quic_metrics.peer_max_recv_buf;
    return 0;
}