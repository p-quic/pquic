#include "picoquic.h"
#include "picoquic_internal.h"
#include "../helpers.h"
#include "bpf.h"

protoop_arg_t update_ack_delay (picoquic_cnx_t *cnx) {
    picoquic_packet_context_t* pkt_ctx = (picoquic_packet_context_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_path_t* old_path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    int64_t rtt_estimate = (int64_t) get_cnx(cnx, AK_CNX_INPUT, 2);
    bool first_estimate = (bool) get_cnx(cnx, AK_CNX_INPUT, 3);

    uint64_t rtt_min = get_path(old_path, AK_PATH_RTT_MIN, 0);
    uint64_t ack_delay_local = (rtt_min * ACK_DELAY_MULT) / ACK_DELAY_DIV;
    PROTOOP_PRINTF(cnx, "old_path->rtt_min / 4 = %" PRIu64 "\n", ack_delay_local);
    if (ack_delay_local < 1000) {
        ack_delay_local = 1000;
    } else if (!first_estimate && ack_delay_local > rtt_min) {
        ack_delay_local = rtt_min;
    }
    set_pkt_ctx(pkt_ctx, AK_PKTCTX_ACK_DELAY_LOCAL, ack_delay_local);
    PROTOOP_PRINTF(cnx, "pkt_ctx->ack_delay_local = %" PRIu64 "\n", ack_delay_local);
    return 0;
}