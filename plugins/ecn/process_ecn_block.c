#include "bpf.h"

protoop_arg_t process_ecn_block(picoquic_cnx_t *cnx) {
    ecn_block_t *block = (ecn_block_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_packet_context_t *pkt_ctx = (picoquic_packet_context_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    picoquic_path_t *path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 2);

    ecn_counters_t *cnts = (ecn_counters_t *) get_pkt_ctx_metadata(cnx, pkt_ctx, META_PKT_CTX_ECN_COUNTERS);
    if (cnts == NULL) {
        cnts = my_malloc(cnx, sizeof(ecn_counters_t));
        if (cnts)
            my_memset(cnts, 0, sizeof(ecn_counters_t));
        set_pkt_ctx_metadata(cnx, pkt_ctx, META_PKT_CTX_ECN_COUNTERS, (protoop_arg_t) cnts);
    }

    if (cnts && cnts->ecn_ect0_remote_pkts <= block->ect0 && cnts->ecn_ect1_remote_pkts <= block->ect1 && cnts->ecn_ect_ce_remote_pkts <= block->ectce) {
        cnts->ecn_ect0_remote_pkts = block->ect0;
        cnts->ecn_ect1_remote_pkts = block->ect1;
        if (block->ectce > cnts->ecn_ect_ce_remote_pkts) {
            helper_congestion_algorithm_notify(cnx, path, picoquic_congestion_notification_congestion_experienced, 0, 0, 0, picoquic_current_time());
        }
        cnts->ecn_ect_ce_remote_pkts = block->ectce;
    }

    if (block) {
        my_free(cnx, block);
    }

    return 0;
}