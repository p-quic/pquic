#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"

/**
 * See PROTOOP_NOPARAM_RETRANSMIT_NEEDED_BY_PACKET
 */
protoop_arg_t retransmit_needed_by_packet(picoquic_cnx_t *cnx)
{
    picoquic_packet_t *p = (picoquic_packet_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    uint64_t current_time = (uint64_t) get_cnx(cnx, CNX_AK_INPUT, 1);
    int timer_based = (int) get_cnx(cnx, CNX_AK_INPUT, 2);

    picoquic_packet_context_enum pc = p->pc;
    picoquic_path_t* send_path = p->send_path;
    int64_t delta_seq = send_path->pkt_ctx[pc].highest_acknowledged - p->sequence_number;
    int should_retransmit = 0;
    protoop_id_t reason = NULL;

    if (delta_seq > 3) {
        /*
         * SACK Logic.
         * more than N packets were seen at the receiver after this one.
         */
        should_retransmit = 1;
        reason = PROTOOP_NOPARAM_FAST_RETRANSMIT;
    } else {
        int64_t delta_t = send_path->pkt_ctx[pc].latest_time_acknowledged - p->send_time;

        /* TODO: out of order delivery time ought to be dynamic */
        if (delta_t > PICOQUIC_RACK_DELAY && p->ptype != picoquic_packet_0rtt_protected) {
            /*
             * RACK logic.
             * The latest acknowledged was sent more than X ms after this one.
             */
            should_retransmit = 1;
        } else if (delta_t > 0) {
            /* If the delta-t is larger than zero, add the time since the
            * last ACK was received. If that is larger than the inter packet
            * time, consider that there is a loss */
            uint64_t time_from_last_ack = current_time - send_path->pkt_ctx[pc].latest_time_acknowledged + delta_t;

            if (time_from_last_ack > 10000) {
                should_retransmit = 1;
            }
        }

        if (should_retransmit == 0) {
            /* Don't fire yet, because of possible out of order delivery */
            int64_t time_out = current_time - p->send_time;
            uint64_t retransmit_timer = (send_path->pkt_ctx[pc].nb_retransmit == 0) ?
                send_path->retransmit_timer : (1000000ull << (send_path->pkt_ctx[pc].nb_retransmit - 1));

            if ((uint64_t)time_out < retransmit_timer) {
                /* Do not retransmit if the timer has not yet elapsed */
                should_retransmit = 0;
            } else {
                should_retransmit = 1;
                timer_based = 1;
                reason = PROTOOP_NOPARAM_RETRANSMISSION_TIMEOUT;
            }
        }
    }

    set_cnx(cnx, CNX_AK_OUTPUT, 0, (protoop_arg_t) timer_based);
    set_cnx(cnx, CNX_AK_OUTPUT, 1, (protoop_arg_t) reason);

    return (protoop_arg_t) should_retransmit;
}