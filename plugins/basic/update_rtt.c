#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"

/**
 * uint64_t largest = cnx->protoop_inputv[0]
 * uint64_t current_time = cnx->protoop_inputv[1]
 * uint64_t ack_delay = cnx->protoop_inputv[2]
 * picoquic_packet_context_enum pc = cnx->protoop_inputv[3]
 * picoquic_path_t* path_x = cnx->protoop_inputv[4]
 *
 * Output: picoquic_packet_t* packet
 */
protoop_arg_t update_rtt(picoquic_cnx_t *cnx)
{
    uint64_t largest = (uint64_t) cnx->protoop_inputv[0];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[1];
    uint64_t ack_delay = (uint64_t) cnx->protoop_inputv[2];
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) cnx->protoop_inputv[3];
    picoquic_path_t *path_x = (picoquic_path_t *) cnx->protoop_inputv[4];

    picoquic_packet_context_t * pkt_ctx = &path_x->pkt_ctx[pc];
    picoquic_packet_t* packet = pkt_ctx->retransmit_newest;

    /* Check whether this is a new acknowledgement */
    if (largest > pkt_ctx->highest_acknowledged || pkt_ctx->first_sack_item.start_of_sack_range == (uint64_t)((int64_t)-1)) {
        pkt_ctx->highest_acknowledged = largest;

        if (ack_delay < PICOQUIC_ACK_DELAY_MAX) {
            /* if the ACK is reasonably recent, use it to update the RTT */
            /* find the stored copy of the largest acknowledged packet */

            while (packet != NULL && packet->sequence_number > largest) {
                packet = packet->next_packet;
            }

            if (packet == NULL || packet->sequence_number < largest) {
                /* There is no copy of this packet in store. It may have
                 * been deleted because too old, or maybe already
                 * retransmitted */
            } else {
                uint64_t acknowledged_time = current_time - ack_delay;
                int64_t rtt_estimate = acknowledged_time - packet->send_time;

                if (pkt_ctx->latest_time_acknowledged < packet->send_time) {
                    pkt_ctx->latest_time_acknowledged = packet->send_time;
                }
                cnx->latest_progress_time = current_time;

                if (rtt_estimate > 0) {
                    picoquic_path_t * old_path = packet->send_path;

                    if (ack_delay > old_path->max_ack_delay) {
                        old_path->max_ack_delay = ack_delay;
                    }

                    if (old_path->smoothed_rtt == PICOQUIC_INITIAL_RTT && old_path->rtt_variant == 0) {
                        old_path->smoothed_rtt = rtt_estimate;
                        old_path->rtt_variant = rtt_estimate / 2;
                        old_path->rtt_min = rtt_estimate;
                        old_path->retransmit_timer = 3 * rtt_estimate + old_path->max_ack_delay;
                        pkt_ctx->ack_delay_local = old_path->rtt_min / 4;
                        if (pkt_ctx->ack_delay_local < 1000) {
                            pkt_ctx->ack_delay_local = 1000;
                        }
                    } else {
                        /* Computation per RFC 6298 */
                        int64_t delta_rtt = rtt_estimate - old_path->smoothed_rtt;
                        int64_t delta_rtt_average = 0;
                        old_path->smoothed_rtt += delta_rtt / 8;

                        if (delta_rtt < 0) {
                            delta_rtt_average = (-delta_rtt) - old_path->rtt_variant;
                        } else {
                            delta_rtt_average = delta_rtt - old_path->rtt_variant;
                        }
                        old_path->rtt_variant += delta_rtt_average / 4;

                        if (rtt_estimate < (int64_t)old_path->rtt_min) {
                            old_path->rtt_min = rtt_estimate;

                            pkt_ctx->ack_delay_local = old_path->rtt_min / 4;
                            if (pkt_ctx->ack_delay_local < 1000) {
                                pkt_ctx->ack_delay_local = 1000;
                            } else if (pkt_ctx->ack_delay_local > 10000) {
                                pkt_ctx->ack_delay_local = 10000;
                            }
                        }

                        if (4 * old_path->rtt_variant < old_path->rtt_min) {
                            old_path->rtt_variant = old_path->rtt_min / 4;
                        }

                        old_path->retransmit_timer = old_path->smoothed_rtt + 4 * old_path->rtt_variant + old_path->max_ack_delay;
                    }

                    if (PICOQUIC_MIN_RETRANSMIT_TIMER > old_path->retransmit_timer) {
                        old_path->retransmit_timer = PICOQUIC_MIN_RETRANSMIT_TIMER;
                    }

                    if (cnx->congestion_alg != NULL) {
                        helper_congestion_algorithm_notify(cnx, old_path,
                            picoquic_congestion_notification_rtt_measurement,
                            rtt_estimate, 0, 0, current_time);
                    }
                }
            }
        }
    }

    return (protoop_arg_t) packet;
}