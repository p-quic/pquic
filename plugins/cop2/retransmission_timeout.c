#include "picoquic.h"
#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"


/**
 * See PROTOOP_NOPARAM_RETRANSMISSION_TIMEOUT
 */
protoop_arg_t retransmission_timeout(picoquic_cnx_t *cnx)
{
    picoquic_packet_t *p = (picoquic_packet_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    picoquic_path_t *path = (picoquic_path_t *) get_pkt(p, PKT_AK_SEND_PATH);
    cop2_path_metrics *path_metrics = find_metrics_for_path(cnx, get_cop2_metrics(cnx), path);
    path_metrics->metrics.rto_fired++;
    return 0;
}