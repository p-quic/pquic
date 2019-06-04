#include "../helpers.h"
#include "bpf.h"

/**
 * See PROTOOP_NOPARAM_PACKET_WAS_LOST
 */
protoop_arg_t packet_lost(picoquic_cnx_t *cnx)
{
    cop2_conn_metrics *metrics = get_cop2_metrics(cnx);
    picoquic_packet_t* packet = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_path_t *path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 1);

    cop2_path_metrics *path_metrics = find_metrics_for_path(cnx, metrics, path);
    path_metrics->metrics.data_lost = (get_pkt(packet, AK_PKT_LENGTH) + get_pkt(packet, AK_PKT_CHECKSUM_OVERHEAD));
    path_metrics->metrics.pkt_lost++;
    return 0;
}