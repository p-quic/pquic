#include "../helpers.h"
#include "bpf.h"

/**
 * Input: None
 *
 * Output: None
 */
protoop_arg_t state_changed(picoquic_cnx_t *cnx)
{
    cop2_conn_metrics *metrics = get_cop2_metrics(cnx);
    picoquic_state_enum cnx_state = (picoquic_state_enum) get_cnx(cnx, AK_CNX_STATE, 0);
    if (cnx_state == picoquic_state_client_ready || cnx_state == picoquic_state_server_ready) {
        clock_gettime(CLOCK_MONOTONIC, &metrics->handshake_metrics.t_end);
        send_path_metrics_to_exporter(cnx, &metrics->handshake_metrics, FLOW_STATE_NEW, FLOW_STATE_ESTABLISHED);  // TODO: Send it once we dropped all handshake keys
    } else if (cnx_state == picoquic_state_handshake_failure) {
        send_path_metrics_to_exporter(cnx, &metrics->handshake_metrics, FLOW_STATE_NEW, FLOW_STATE_BROKEN); // TODO: How to distinguish a unreachable peer ?
    } else if (cnx_state == picoquic_state_disconnected) {
        int limit = metrics->n_established_paths; // T2 oddity
        for (int i = 0; i < limit; i++) {
            //TODO: complete the path  // An event should exist for path creation/deletion
            clock_gettime(CLOCK_MONOTONIC, &(metrics->established_metrics + i)->t_end);
            send_path_metrics_to_exporter(cnx, metrics->established_metrics + i, FLOW_STATE_ESTABLISHED, FLOW_STATE_FINISHED); // TODO: Distinguish graceful from abortful closure
        }
    }
    return 0;
}