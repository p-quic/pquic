#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"

/**
 * cnx->protoop_inputv[0] = picoquic_packet_t* packet
 * cnx->protoop_inputv[1] = picoquic_path_t *path
 *
 * Output: None
 */
protoop_arg_t packet_lost(picoquic_cnx_t *cnx)
{
    cop2_conn_metrics *metrics = get_cop2_metrics(cnx);
    cop2_path_metrics *path_metrics = find_metrics_for_path(cnx, metrics, (picoquic_path_t *) cnx->protoop_inputv[1]);

    picoquic_packet_t* packet = (picoquic_packet_t *) cnx->protoop_inputv[0];
    path_metrics->metrics.data_lost = (packet->length + packet->checksum_overhead);
    path_metrics->metrics.pkt_lost++;
    return 0;
}