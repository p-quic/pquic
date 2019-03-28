#include "picoquic.h"
#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"


/**
 * See PROTOOP_NOPARAM_FAST_RETRANSMIT
 */
protoop_arg_t fast_retransmit(picoquic_cnx_t *cnx)
{
    picoquic_packet_t *p = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    PROTOOP_PRINTF(cnx, "FRT fired %p\n", (protoop_arg_t) p);
    picoquic_path_t *path = (picoquic_path_t *) get_pkt(p, AK_PKT_SEND_PATH);
    cop2_path_metrics *path_metrics = find_metrics_for_path(cnx, get_cop2_metrics(cnx), path);
    path_metrics->metrics.frt_fired++;
    return 0;
}