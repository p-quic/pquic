#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"

/**
 * See PROTOOP_NOPARAM_UPDATE_RTT
 */
protoop_arg_t update_rtt(picoquic_cnx_t *cnx)
{
    uint64_t largest = (uint64_t) get_cnx(cnx, CNX_AK_INPUT, 0);
    uint64_t current_time = (uint64_t) get_cnx(cnx, CNX_AK_INPUT, 1);
    uint64_t ack_delay = (uint64_t) get_cnx(cnx, CNX_AK_INPUT, 2);
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) get_cnx(cnx, CNX_AK_INPUT, 3);
    picoquic_path_t *path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_INPUT, 4);

    picoquic_packet_context_t * pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, PATH_AK_PKT_CTX, pc);
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
                set_cnx(cnx, CNX_AK_LATEST_PROGRESS_TIME, 0, current_time);

                if (rtt_estimate > 0) {
                    picoquic_path_t * old_path = packet->send_path;
                    uint64_t old_max_ack_delay = (uint64_t) get_path(old_path, PATH_AK_MAX_ACK_DELAY, 0);

                    if (ack_delay > old_max_ack_delay) {
                        set_path(old_path, PATH_AK_MAX_ACK_DELAY, 0, ack_delay);
                    }

                    uint64_t old_smoothed_rtt = (uint64_t) get_path(old_path, PATH_AK_SMOOTHED_RTT, 0);
                    uint64_t old_rtt_variant = (uint64_t) get_path(old_path, PATH_AK_RTT_VARIANT, 0);
                    if (old_smoothed_rtt == PICOQUIC_INITIAL_RTT && old_rtt_variant == 0) {
                        set_path(old_path, PATH_AK_SMOOTHED_RTT, 0, rtt_estimate);
                        set_path(old_path, PATH_AK_RTT_VARIANT, 0, rtt_estimate / 2);
                        set_path(old_path, PATH_AK_RTT_MIN, 0, rtt_estimate);
                        set_path(old_path, PATH_AK_RETRANSMIT_TIMER, 0, 3 * rtt_estimate + old_max_ack_delay);
                        pkt_ctx->ack_delay_local = get_path(old_path, PATH_AK_RTT_MIN, 0) / 4;
                        if (pkt_ctx->ack_delay_local < 1000) {
                            pkt_ctx->ack_delay_local = 1000;
                        }
                    } else {
                        /* Computation per RFC 6298 */
                        int64_t delta_rtt = rtt_estimate - old_smoothed_rtt;
                        int64_t delta_rtt_average = 0;
                        set_path(old_path, PATH_AK_SMOOTHED_RTT, 0, old_smoothed_rtt + (delta_rtt) / 8);

                        if (delta_rtt < 0) {
                            delta_rtt_average = (-delta_rtt) - old_rtt_variant;
                        } else {
                            delta_rtt_average = delta_rtt - old_rtt_variant;
                        }
                        set_path(old_path, PATH_AK_RTT_VARIANT, 0, old_rtt_variant + (delta_rtt_average) / 4);

                        uint64_t old_rtt_min = get_path(old_path, PATH_AK_RTT_MIN, 0);
                        if (rtt_estimate < (int64_t)old_rtt_min) {
                            set_path(old_path, PATH_AK_RTT_MIN, 0, rtt_estimate);

                            pkt_ctx->ack_delay_local = get_path(old_path, PATH_AK_RTT_MIN, 0) / 4;
                            if (pkt_ctx->ack_delay_local < 1000) {
                                pkt_ctx->ack_delay_local = 1000;
                            } else if (pkt_ctx->ack_delay_local > 10000) {
                                pkt_ctx->ack_delay_local = 10000;
                            }
                        }

                        old_rtt_variant = (uint64_t) get_path(old_path, PATH_AK_RTT_VARIANT, 0);
                        old_rtt_min = (uint64_t) get_path(old_path, PATH_AK_RTT_MIN, 0);
                        if (4 * old_rtt_variant < old_rtt_min) {
                            set_path(old_path, PATH_AK_RTT_VARIANT, 0, old_rtt_min / 4);
                        }

                        old_max_ack_delay = (uint64_t) get_path(old_path, PATH_AK_MAX_ACK_DELAY, 0);
                        old_rtt_variant = (uint64_t) get_path(old_path, PATH_AK_RTT_VARIANT, 0);
                        old_smoothed_rtt = (uint64_t) get_path(old_path, PATH_AK_SMOOTHED_RTT, 0);
                        set_path(old_path, PATH_AK_RETRANSMIT_TIMER, 0, old_smoothed_rtt + 4 * old_rtt_variant + old_max_ack_delay);
                    }

                    uint64_t old_retransmit_timer = (uint64_t) get_path(old_path, PATH_AK_RETRANSMIT_TIMER, 0);
                    if (PICOQUIC_MIN_RETRANSMIT_TIMER > old_retransmit_timer) {
                        set_path(old_path, PATH_AK_RETRANSMIT_TIMER, 0, PICOQUIC_MIN_RETRANSMIT_TIMER);
                    }

                    picoquic_congestion_algorithm_t *congestion_alg = (picoquic_congestion_algorithm_t *) get_cnx(cnx, CNX_AK_CONGESTION_CONTROL_ALGORITHM, 0);
                    if (congestion_alg != NULL) {
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