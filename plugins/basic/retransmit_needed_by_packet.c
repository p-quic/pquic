#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"

/**
 * See PROTOOP_NOPARAM_RETRANSMIT_NEEDED_BY_PACKET
 */
protoop_arg_t retransmit_needed_by_packet(picoquic_cnx_t *cnx)
{
    picoquic_packet_t *p = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    uint64_t current_time = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 1);
    int timer_based = (int) get_cnx(cnx, AK_CNX_INPUT, 2);

    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) get_pkt(p, AK_PKT_CONTEXT);
    picoquic_path_t* send_path = (picoquic_path_t *) get_pkt(p, AK_PKT_SEND_PATH);
    picoquic_packet_context_t *pkt_ctx = (picoquic_packet_context_t *) get_path(send_path, AK_PATH_PKT_CTX, pc);
    uint64_t highest_acknowledged = get_pkt_ctx(pkt_ctx, AK_PKTCTX_HIGHEST_ACKNOWLEDGED);
    int64_t delta_seq = highest_acknowledged - get_pkt(p, AK_PKT_SEQUENCE_NUMBER);
    int should_retransmit = 0;
    char *reason = NULL;
    uint64_t retransmit_timer = 0;

    if (delta_seq > 3) {
        /*
         * SACK Logic.
         * more than N packets were seen at the receiver after this one.
         */
        should_retransmit = 1;
        reason = PROTOOPID_NOPARAM_FAST_RETRANSMIT;
    } else {
        uint64_t latest_time_acknowledged = (uint64_t) get_pkt_ctx(pkt_ctx, AK_PKTCTX_LATEST_TIME_ACKNOWLEDGED);
        uint64_t send_time = (uint64_t) get_pkt(p, AK_PKT_SEND_TIME);
        int64_t delta_t = latest_time_acknowledged - send_time;

        /* TODO: out of order delivery time ought to be dynamic */
        picoquic_packet_type_enum ptype = (picoquic_packet_type_enum) get_pkt(p, AK_PKT_TYPE);
        if (delta_t > PICOQUIC_RACK_DELAY && ptype != picoquic_packet_0rtt_protected) {
            /*
             * RACK logic.
             * The latest acknowledged was sent more than X ms after this one.
             */
            should_retransmit = 1;
        } else if (delta_t > 0) {
            /* If the delta-t is larger than zero, add the time since the
            * last ACK was received. If that is larger than the inter packet
            * time, consider that there is a loss */
            uint64_t time_from_last_ack = current_time - latest_time_acknowledged + delta_t;

            if (time_from_last_ack > 10000) {
                should_retransmit = 1;
            }
        }

        if (should_retransmit == 0) {
            /* Don't fire yet, because of possible out of order delivery */
            int64_t time_out = current_time - send_time;
            uint64_t nb_retransmit = (uint64_t) get_pkt_ctx(pkt_ctx, AK_PKTCTX_NB_RETRANSMIT);
            retransmit_timer = (nb_retransmit == 0) ?
                (uint64_t) get_path(send_path, AK_PATH_RETRANSMIT_TIMER, 0) : (1000000ull << (nb_retransmit - 1));

            if ((uint64_t)time_out < retransmit_timer) {
                /* Do not retransmit if the timer has not yet elapsed */
                should_retransmit = 0;
            } else {
                should_retransmit = 1;
                timer_based = 1;
                reason = PROTOOPID_NOPARAM_RETRANSMISSION_TIMEOUT;
            }
        }
    }

    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) timer_based);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) reason);
    set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) retransmit_timer);

    return (protoop_arg_t) should_retransmit;
}