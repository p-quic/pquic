
#include <picoquic.h>
#include <getset.h>
#include "westwood.h"





/**
 * See PROTOOP_NOPARAM_CONGESTION_ALGORITHM_NOTIFY
 */
protoop_arg_t congestion_algorithm_notify(picoquic_cnx_t *cnx)
{
    picoquic_path_t* path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 0); //(picoquic_path_t*) cnx->protoop_inputv[0];
    picoquic_congestion_notification_t notification = (picoquic_congestion_notification_t) get_cnx(cnx, AK_CNX_INPUT, 1);
    uint64_t rtt_measurement = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 2);
    uint64_t nb_bytes_acknowledged = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 3);
    uint64_t lost_packet_number = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 4);
    uint64_t current_time = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 5);

    westwood_state_t* westwood_state = (westwood_state_t*) get_westwood_state_t(cnx, current_time);

    uint64_t cwin = get_path(path_x, AK_PATH_CWIN, 0);
    uint64_t bytes_in_transit = get_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0);
    int64_t send_mtu = get_path(path_x, AK_PATH_SEND_MTU, 0);
    int64_t smoothed_rtt = get_path(path_x, AK_PATH_SMOOTHED_RTT, 0);

    if (westwood_state != NULL) {
        switch (notification) {
            case picoquic_congestion_notification_acknowledgement: {
                if ((int64_t) current_time - (int64_t) westwood_state->last_rtt_timestamp > smoothed_rtt) {
                    // we're in a new round
                    westwood_state->bytes_acknowledged_during_previous_round = westwood_state->bytes_acknowledged_since_last_rtt;
                    westwood_state->bytes_acknowledged_since_last_rtt = 0;
                    westwood_state->last_rtt_timestamp = current_time;
                    westwood_state->last_rtt_value = smoothed_rtt;
                }
                westwood_state->bytes_acknowledged_since_last_rtt += nb_bytes_acknowledged;
                switch (westwood_state->alg_state) {
                    case westwood_alg_slow_start:
                        /* Only increase when the app is CWIN limited */
                        if (picoquic_cc_was_cwin_blocked(path_x, westwood_state->last_sequence_blocked)) {
                            cwin += nb_bytes_acknowledged;
                            /* if cnx->cwin exceeds SSTHRESH, exit and go to CA */
                            if (cwin >= westwood_state->ssthresh) {
                                westwood_state->alg_state = westwood_alg_congestion_avoidance;
                            }
                        }
                        break;
                    case westwood_alg_congestion_avoidance:
                    default: {
                        // we increase the cwin by nb_bytes_acknowledged per RTT
                        uint64_t complete_delta = nb_bytes_acknowledged * send_mtu + westwood_state->residual_ack;
                        westwood_state->residual_ack = complete_delta % (uint64_t) cwin;
                        cwin += complete_delta / (uint64_t) cwin;
                        break;
                    }
                }
                break;
            }
            case picoquic_congestion_notification_repeat:
            case picoquic_congestion_notification_timeout:
                /* enter recovery */
                if (current_time - westwood_state->recovery_start > smoothed_rtt) {
                    westwood_enter_recovery(cnx, path_x, notification, westwood_state, current_time, &cwin);
                }
                break;
            case picoquic_congestion_notification_spurious_repeat:
                if (current_time - westwood_state->recovery_start < smoothed_rtt) {
                    /*
                     * If spurious repeat of initial loss detected,
                     * exit recovery and reset threshold to pre-entry cwin.
                     */

                    if (cwin < westwood_state->cwin_before_recovery_start) {
                        cwin = westwood_state->cwin_before_recovery_start;
                        westwood_state->alg_state = westwood_alg_congestion_avoidance;
                    }

                    /*
                     * Reno was doing this (reset the cwin to the state before recovery) :
                     */
//                    if (cwin < 2 * westwood_state->ssthresh) {
//                        cwin = 2 * westwood_state->ssthresh;
//                        westwood_state->alg_state = westwood_alg_congestion_avoidance;
//                    }
                }
                break;
            case picoquic_congestion_notification_rtt_measurement:
                /* Using RTT increases as signal to get out of initial slow start */
                if (westwood_state->alg_state == westwood_alg_slow_start &&
                    westwood_state->ssthresh == (uint64_t) ((int64_t)-1)) {
                    uint64_t rolling_min;
                    uint64_t delta_rtt;

                    if (rtt_measurement < westwood_state->min_rtt || westwood_state->min_rtt == 0) {
                        westwood_state->min_rtt = rtt_measurement;
                    }

                    if (westwood_state->nb_rtt > NB_RTT_WESTWOOD) {
                        westwood_state->nb_rtt = 0;
                    }

                    westwood_state->last_rtt[westwood_state->nb_rtt] = rtt_measurement;
                    westwood_state->nb_rtt++;

                    rolling_min = westwood_state->last_rtt[0];

                    for (int i = 1; i < NB_RTT_WESTWOOD; i++) {
                        if (westwood_state->last_rtt[i] == 0) {
                            break;
                        }
                        else if (westwood_state->last_rtt[i] < rolling_min) {
                            rolling_min = westwood_state->last_rtt[i];
                        }
                    }

                    delta_rtt = rolling_min - westwood_state->min_rtt;
                    if (delta_rtt * 4 > westwood_state->min_rtt) {
                        /* RTT increased too much, get out of slow start! */
                        westwood_state->alg_state = westwood_alg_congestion_avoidance;
                    }
                }
                break;
            case picoquic_congestion_notification_cwin_blocked:
                westwood_state->last_sequence_blocked = picoquic_cc_get_sequence_number(path_x);
                break;
            default:
                /* ignore */
                break;
        }
    }

    /* Compute pacing data */
    picoquic_update_pacing_data(path_x);
    set_path(path_x, AK_PATH_CWIN, 0, cwin);
    set_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0, bytes_in_transit);
    return 0;
}
