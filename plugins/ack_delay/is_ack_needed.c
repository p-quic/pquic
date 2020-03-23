#include "picoquic.h"
#include "picoquic_internal.h"
#include "../helpers.h"
#include "bpf.h"

protoop_arg_t is_ack_needed(picoquic_cnx_t *cnx) {
    uint64_t current_time = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) get_cnx(cnx, AK_CNX_INPUT, 1);
    picoquic_path_t* path_x = (picoquic_path_t*) get_cnx(cnx, AK_CNX_INPUT, 2);

    int ret = 0;
    picoquic_packet_context_t * pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, AK_PATH_PKT_CTX, pc);
    PROTOOP_PRINTF(cnx, "pkt_ctx = %p, pc = %d\n", (protoop_arg_t) pkt_ctx, pc);

    int ack_threshold = get_pkt_ctx(pkt_ctx, AK_PKTCTX_HIGHEST_ACK_SENT) + ACK_THRESHOLD <= get_sack_item(((picoquic_sack_item_t*) get_pkt_ctx(pkt_ctx, AK_PKTCTX_FIRST_SACK_ITEM)), AK_SACKITEM_END_RANGE);
    int ack_time = get_pkt_ctx(pkt_ctx, AK_PKTCTX_HIGHEST_ACK_TIME) + get_pkt_ctx(pkt_ctx, AK_PKTCTX_ACK_DELAY_LOCAL) <= current_time;
    if (ack_threshold) {
        PROTOOP_PRINTF(cnx, "ack_threshold %d <= %d\n", get_pkt_ctx(pkt_ctx, AK_PKTCTX_HIGHEST_ACK_SENT) + ACK_THRESHOLD, get_sack_item(((picoquic_sack_item_t*) get_pkt_ctx(pkt_ctx, AK_PKTCTX_FIRST_SACK_ITEM)), AK_SACKITEM_END_RANGE));
    }
    if (ack_time) {
        PROTOOP_PRINTF(cnx, "ack_time %" PRIx64 " <= %" PRIx64 "\n", get_pkt_ctx(pkt_ctx, AK_PKTCTX_HIGHEST_ACK_TIME) + get_pkt_ctx(pkt_ctx, AK_PKTCTX_ACK_DELAY_LOCAL), current_time);
    }
    if (ack_threshold || ack_time) {
        ret = (int) get_pkt_ctx(pkt_ctx, AK_PKTCTX_ACK_NEEDED);
    }
    if (ret) {
        PROTOOP_PRINTF(cnx, "ack_needed\n");
    }

    return (protoop_arg_t) ret;
}