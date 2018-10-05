#include "plugin.h"
#include "util.h"
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
    if (cnx->cnx_state == picoquic_state_client_ready || cnx->cnx_state == picoquic_state_server_ready) {
        clock_gettime(CLOCK_MONOTONIC, &metrics->handshake_metrics.t_end);
        // Send it somewhere
    } else if (cnx->cnx_state == picoquic_state_closing) {
        cop2_path_metrics *path = metrics->established_metrics;
        while(path != NULL) {
            // Send it somewhere
            //TODO: complete the path  // An event should exist for path creation/deletion
            clock_gettime(CLOCK_MONOTONIC, &path->t_end);
            path = path->next;
        }
        dump_metrics(cnx, metrics);
    }
    return 0;
}