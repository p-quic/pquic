#include "plugin.h"
#include "util.h"
#include "../helpers.h"
#include "bpf.h"

/**
 * See PROTOOP_NOPARAM_UPDATE_RTT
 */
protoop_arg_t rtt_updated(picoquic_cnx_t *cnx)
{
    cop2_conn_metrics *metrics = get_cop2_metrics(cnx);
    cop2_path_metrics *path_metrics;
    picoquic_state_enum cnx_state = (picoquic_state_enum) get_cnx(cnx, CNX_AK_STATE, 0);
    picoquic_path_t *path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_INPUT, 4);
    if (cnx_state < picoquic_state_client_ready) {
        path_metrics = &metrics->handshake_metrics;
    } else {
        path_metrics = find_metrics_for_path(cnx, metrics, path_x);
    }
    path_metrics->metrics.smoothed_rtt = path_x->smoothed_rtt;
    path_metrics->metrics.rtt_variance = path_x->rtt_variant;
    return 0;
}