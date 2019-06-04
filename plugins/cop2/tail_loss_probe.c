#include "../helpers.h"
#include "bpf.h"


/**
 * See PROTOOP_NOPARAM_TAIL_LOSS_PROBE
 */
protoop_arg_t tail_loss_probe(picoquic_cnx_t *cnx)
{
    picoquic_packet_t *p = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_path_t *path = (picoquic_path_t *) get_pkt(p, AK_PKT_SEND_PATH);
    cop2_path_metrics *path_metrics = find_metrics_for_path(cnx, get_cop2_metrics(cnx), path);
    path_metrics->metrics.tlp_fired++;
    return 0;
}