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
    picoquic_state_enum cnx_state = (picoquic_state_enum) get_cnx(cnx, CNX_AK_STATE, 0);
    if (cnx_state == picoquic_state_client_ready || cnx_state == picoquic_state_server_ready) {
        clock_gettime(CLOCK_MONOTONIC, &metrics->handshake_metrics.t_end);
        // Send it somewhere
    } else if (cnx_state == picoquic_state_disconnected) {
        int limit = metrics->n_established_paths; // T2 oddity
        for (int i = 0; i < limit; i++) {
            //TODO: complete the path  // An event should exist for path creation/deletion
            clock_gettime(CLOCK_MONOTONIC, &(metrics->established_metrics + i)->t_end);
        }
        dump_metrics(cnx, metrics);
    }
    return 0;
}