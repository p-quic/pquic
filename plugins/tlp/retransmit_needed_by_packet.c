#include "picoquic_internal.h"
#include "plugin.h"
#include "bpf.h"

static void dbg_print(picoquic_cnx_t *cnx, uint64_t val1, uint64_t val2, uint64_t val3)
{
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) val1;
    args[1] = (protoop_arg_t) val2;
    args[2] = (protoop_arg_t) val3;
    bpf_data *bpfd = (bpf_data *) cnx->opaque;
    //if (bpfd->print) plugin_run_protoop(cnx, PROTOOPID_PRINTF, 3, args, NULL);
}


/**
 * cnx->protoop_inputv[0] = picoquic_packet *p NOT NULL
 * cnx->protoop_inputv[1] = uint64_t current_time
 * cnx->protoop_inputv[2] = int timer_based
 * 
 * Output: should retransmit (int)
 * cnx->protoop_outputv[0] = int timer_based
 */
protoop_arg_t retransmit_needed_by_packet(picoquic_cnx_t *cnx)
{
    picoquic_packet_t *p = (picoquic_packet_t *) cnx->protoop_inputv[0];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[1];
    int timer_based = (int) cnx->protoop_inputv[2];
    bpf_data *bpfd = (bpf_data *)cnx->opaque;

    picoquic_packet_context_enum pc = p->pc;
    int64_t delta_seq = cnx->pkt_ctx[pc].highest_acknowledged - p->sequence_number;
    int should_retransmit = 0;

    dbg_print(cnx, 0, delta_seq, 3);

    if (delta_seq > 3) {
        /*
         * SACK Logic.
         * more than N packets were seen at the receiver after this one.
         */
        should_retransmit = 1;
    } else {
        int64_t delta_t = cnx->pkt_ctx[pc].latest_time_acknowledged - p->send_time;

        dbg_print(cnx, 1, delta_t, PICOQUIC_RACK_DELAY);
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
            uint64_t time_from_last_ack = current_time - cnx->pkt_ctx[pc].latest_time_acknowledged + delta_t;
            dbg_print(cnx, 2, time_from_last_ack, 10000);
            if (time_from_last_ack > 10000) {
                should_retransmit = 1;
            }
        }

        if (should_retransmit == 0) {
            /* Don't fire yet, because of possible out of order delivery */
            int64_t time_out = current_time - p->send_time;
            uint64_t retransmit_timer = (cnx->pkt_ctx[pc].nb_retransmit == 0) ?
                cnx->path[0]->retransmit_timer : (1000000ull << (cnx->pkt_ctx[pc].nb_retransmit - 1));

            dbg_print(cnx, 3, time_out, retransmit_timer);
            if ((uint64_t)time_out < retransmit_timer) {
                /* Do not retransmit if the timer has not yet elapsed */
                should_retransmit = 0;
            } else {
                should_retransmit = 1;
                timer_based = 1;
            }
        }

        /* Ok, no timeout so far, buf what about the last packet for the TLP probe? */
        if (should_retransmit == 0 && bpfd->tlp_nb < 3 && bpfd->tlp_time > 0) {
            if (current_time > bpfd->tlp_time && bpfd->tlp_last_asked != current_time && pc == picoquic_packet_context_application) {
                /* Only retransmit the newest packet (indicated by should retransmit being 2) */
                should_retransmit = 2;
                bpfd->tlp_last_asked = current_time;
            }
        } else {
            bpfd->tlp_time = 0;
            bpfd->tlp_nb = 0;
        }
    }

    cnx->protoop_outputv[0] = (protoop_arg_t) timer_based;
    cnx->protoop_outputc_callee = 1;

    return (protoop_arg_t) should_retransmit;
}