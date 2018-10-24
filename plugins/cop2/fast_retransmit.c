#include "picoquic_internal.h"
#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"


/**
 * See PROTOOP_NOPARAM_FAST_RETRANSMIT
 *
 * cnx->protoop_inputv[0] = picoquic_packet_t *p NOT NULL
 * cnx->protoop_inputv[1] = uint64_t current_time
 * cnx->protoop_inputv[2] = int timer_based
 */
protoop_arg_t fast_retransmit(picoquic_cnx_t *cnx)
{
    PROTOOP_PRINTF(cnx, "FRT fired %p\n", (protoop_arg_t) cnx->protoop_inputv[0]);
    picoquic_path_t *path = ((picoquic_packet_t *)cnx->protoop_inputv[0])->send_path;
    cop2_path_metrics *path_metrics = find_metrics_for_path(cnx, get_cop2_metrics(cnx), path);
    path_metrics->metrics.frt_fired++;
    return 0;
}