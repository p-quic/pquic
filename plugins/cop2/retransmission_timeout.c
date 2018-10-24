#include "picoquic_internal.h"
#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"


/**
 * See PROTOOP_NOPARAM_RETRANSMISSION_TIMEOUT
 *
 * cnx->protoop_inputv[0] = picoquic_packet_t *p NOT NULL
 * cnx->protoop_inputv[1] = uint64_t current_time
 * cnx->protoop_inputv[2] = int timer_based
 */
protoop_arg_t retransmission_timeout(picoquic_cnx_t *cnx)
{
    picoquic_path_t *path = ((picoquic_packet_t *)cnx->protoop_inputv[0])->send_path;
    cop2_path_metrics *path_metrics = find_metrics_for_path(cnx, get_cop2_metrics(cnx), path);
    path_metrics->metrics.rto_fired++;
    return 0;
}