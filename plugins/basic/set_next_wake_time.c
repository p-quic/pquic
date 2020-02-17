#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"

/* Special wake up decision logic in initial state */
/* TODO: tie with per path scheduling */
static void cnx_set_next_wake_time_init(picoquic_cnx_t* cnx, uint64_t current_time)
{
    uint64_t start_time = (uint64_t) get_cnx(cnx, AK_CNX_START_TIME, 0);
    uint64_t next_time = start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX;
    picoquic_stream_head* stream = NULL;
    int timer_based = 0;
    int blocked = 1;
    int pacing = 0;
    picoquic_path_t * path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
    picoquic_packet_context_t *pkt_ctx;
    int pc_ready_flag = 1 << picoquic_packet_context_initial;
    picoquic_stream_head *tls_stream_0 = (picoquic_stream_head *) get_cnx(cnx, AK_CNX_TLS_STREAM, 0);

    picoquic_crypto_context_t *crypto_context_1 = (picoquic_crypto_context_t *) get_cnx(cnx, AK_CNX_CRYPTO_CONTEXT, 1);
    picoquic_crypto_context_t *crypto_context_2 = (picoquic_crypto_context_t *) get_cnx(cnx, AK_CNX_CRYPTO_CONTEXT, 2);
    int nb_paths = (int) get_cnx(cnx, AK_CNX_NB_PATHS, 0);
    void *crypto_context_1_aead_encrypt = (void *) get_crypto_context(crypto_context_1, AK_CRYPTOCONTEXT_AEAD_ENCRYPTION);

    picoquic_stream_data *tls_stream_0_send_queue = (picoquic_stream_data *) get_stream_head(tls_stream_0, AK_STREAMHEAD_SEND_QUEUE);

    if (tls_stream_0_send_queue == NULL) {
        picoquic_stream_head *tls_stream_1 = (picoquic_stream_head *) get_cnx(cnx, AK_CNX_TLS_STREAM, 1);
        picoquic_stream_data *tls_stream_1_send_queue = (picoquic_stream_data *) get_stream_head(tls_stream_1, AK_STREAMHEAD_SEND_QUEUE);
        void *crypto_context_2_aead_encrypt = (void *) get_crypto_context(crypto_context_2, AK_CRYPTOCONTEXT_AEAD_ENCRYPTION);
        if (crypto_context_1_aead_encrypt != NULL &&
            tls_stream_1_send_queue != NULL) {
            pc_ready_flag |= 1 << picoquic_packet_context_application;
        }
        else if (crypto_context_2_aead_encrypt != NULL &&
            tls_stream_1_send_queue == NULL) {
            pc_ready_flag |= 1 << picoquic_packet_context_handshake;
        }
    }

    if (next_time < current_time)
    {
        next_time = current_time;
        blocked = 0;
    }
    else
    {
        for (picoquic_packet_context_enum pc = 0; blocked == 0 && pc < picoquic_nb_packet_context; pc++) {
            for (int i = 0; blocked == 0 && i < nb_paths; i++) {
                path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, i);
                pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, AK_PATH_PKT_CTX, pc);
                picoquic_packet_t* p = (picoquic_packet_t *) get_pkt_ctx(pkt_ctx, AK_PKTCTX_RETRANSMIT_OLDEST);

                if ((pc_ready_flag & (1 << pc)) == 0) {
                    continue;
                }

                while (p != NULL)
                {
                    picoquic_packet_type_enum ptype = (picoquic_packet_type_enum) get_pkt(p, AK_PKT_TYPE);
                    if (ptype < picoquic_packet_0rtt_protected) {
                        if (helper_retransmit_needed_by_packet(cnx, p, current_time, &timer_based, NULL, NULL)) {
                            blocked = 0;
                        }
                        break;
                    }
                    p = (picoquic_packet_t *) get_pkt(p, AK_PKT_NEXT_PACKET);
                }

                if (blocked != 0)
                {
                    if (helper_is_ack_needed(cnx, current_time, pc, path_x)) {
                        blocked = 0;
                    }
                }
            }
        }

        if (blocked != 0)
        {
            for (int i = 0; blocked != 0 && pacing == 0 && i < nb_paths; i++) {
                path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, i);
                uint64_t cwin_x = (uint64_t) get_path(path_x, AK_PATH_CWIN, 0);
                uint64_t bytes_in_transit_x = (uint64_t) get_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0);
                int challenge_verified_x = (int) get_path(path_x, AK_PATH_CHALLENGE_VERIFIED, 0);
                if (cwin_x > bytes_in_transit_x && challenge_verified_x == 1) {
                    if (helper_should_send_max_data(cnx) ||
                        helper_is_tls_stream_ready(cnx) ||
                        (crypto_context_1_aead_encrypt != NULL && (stream = helper_find_ready_stream(cnx)) != NULL)) {
                        if (picoquic_is_sending_authorized_by_pacing(path_x, current_time, &next_time)) {
                            blocked = 0;
                        } else {
                            pacing = 1;
                        }
                    }
                }
            }
        }

        if (blocked == 0) {
            next_time = current_time;
        } else if (pacing == 0) {
            for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
                for (int i = 0; i < nb_paths; i++) {
                    path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, i);
                    pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, AK_PATH_PKT_CTX, pc);
                    picoquic_packet_t* p = (picoquic_packet_t *) get_pkt_ctx(pkt_ctx, AK_PKTCTX_RETRANSMIT_OLDEST);
                    
                    if ((pc_ready_flag & (1 << pc)) == 0) {
                        continue;
                    }
                    
                    /* Consider delayed ACK */
                    int ack_needed = (int) get_pkt_ctx(pkt_ctx, AK_PKTCTX_ACK_NEEDED);
                    if (ack_needed) {
                        next_time = get_pkt_ctx(pkt_ctx, AK_PKTCTX_HIGHEST_ACK_TIME) + get_pkt_ctx(pkt_ctx, AK_PKTCTX_ACK_DELAY_LOCAL);
                    }

                    if (p != NULL) {
                        picoquic_packet_type_enum ptype = (picoquic_packet_type_enum) get_pkt(p, AK_PKT_TYPE);
                        int pcontains_crypto = (int) get_pkt(p, AK_PKT_CONTAINS_CRYPTO); 

                        while (p != NULL &&
                            ptype == picoquic_packet_0rtt_protected &&
                            pcontains_crypto == 0) {
                            p = (picoquic_packet_t *) get_pkt(p, AK_PKT_NEXT_PACKET);
                            if (p != NULL) {
                                ptype = (picoquic_packet_type_enum) get_pkt(p, AK_PKT_TYPE);
                                pcontains_crypto = (int) get_pkt(p, AK_PKT_CONTAINS_CRYPTO); 
                            }
                        }
                    }    

                    if (p != NULL) {
                        uint64_t nb_retransmit = (uint64_t) get_pkt_ctx(pkt_ctx, AK_PKTCTX_NB_RETRANSMIT);
                        uint64_t send_time = (uint64_t) get_pkt(p, AK_PKT_SEND_TIME);
                        if (nb_retransmit == 0) {
                            uint64_t retransmit_timer_x = (uint64_t) get_path(path_x, AK_PATH_RETRANSMIT_TIMER, 0);
                            if (send_time + retransmit_timer_x < next_time) {
                                next_time = send_time + retransmit_timer_x;
                            }
                        }
                        else {
                            if (send_time + (1000000ull << (nb_retransmit - 1)) < next_time) {
                                next_time = send_time + (1000000ull << (nb_retransmit - 1));
                            }
                        }
                    }
                }
            }
        }
    }

    /* Consider path challenges */
    for (int i = 0; i < nb_paths; i++) {
        path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, i);
        int challenge_verified_x = (int) get_path(path_x, AK_PATH_CHALLENGE_VERIFIED, 0);
        if (blocked != 0 && challenge_verified_x == 0) {
            uint64_t challenge_time_x = (uint64_t) get_path(path_x, AK_PATH_CHALLENGE_TIME, 0);
            uint64_t retransmit_timer_x = (uint64_t) get_path(path_x, AK_PATH_RETRANSMIT_TIMER, 0);
            uint64_t next_challenge_time = challenge_time_x + retransmit_timer_x;
            if (next_challenge_time <= current_time) {
                next_time = current_time;
            } else if (next_challenge_time < next_time) {
                next_time = next_challenge_time;
            }
        }
    }

    /* reset the connection at its new logical position */
    picoquic_reinsert_cnx_by_wake_time(cnx, next_time);
}

/**
 * See PROTOOP_NOPARAM_SET_NEXT_WAKE_TIME
 */
protoop_arg_t set_next_wake_time(picoquic_cnx_t *cnx)
{
    uint64_t current_time = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 0);
    uint32_t last_pkt_length = (uint32_t) get_cnx(cnx, AK_CNX_INPUT, 1);
    int client_mode = (int) get_cnx(cnx, AK_CNX_CLIENT_MODE, 0);
    uint64_t latest_progress_time = (uint64_t) get_cnx(cnx, AK_CNX_LATEST_PROGRESS_TIME, 0);
    uint64_t next_time = latest_progress_time + PICOQUIC_MICROSEC_SILENCE_MAX * (2 - client_mode);
    picoquic_stream_head* stream = NULL;
    int timer_based = 0;
    int blocked = 1;
    int pacing = 0;
    int ret = 0;
    picoquic_state_enum cnx_state = (picoquic_state_enum) get_cnx(cnx, AK_CNX_STATE, 0);


    if (cnx_state < picoquic_state_client_ready)
    {
        cnx_set_next_wake_time_init(cnx, current_time);
        return 0;
    }

    int wake_now = get_cnx(cnx, AK_CNX_WAKE_NOW, 0);

    if (cnx_state == picoquic_state_disconnecting || cnx_state == picoquic_state_handshake_failure || cnx_state == picoquic_state_closing_received) {
        blocked = 0;
    }

    int nb_paths = (int) get_cnx(cnx, AK_CNX_NB_PATHS, 0);

    for (int i = 0; last_pkt_length > 0 && blocked != 0 && i < nb_paths; i++) {
        picoquic_path_t * path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, i);
        uint64_t cwin_x = (uint64_t) get_path(path_x, AK_PATH_CWIN, 0);
        uint64_t bytes_in_transit_x = (uint64_t) get_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0);
        if (cwin_x > bytes_in_transit_x && helper_is_mtu_probe_needed(cnx, path_x)) {
            blocked = 0;
        }
        if (cwin_x > bytes_in_transit_x && picoquic_has_booked_plugin_frames(cnx)) {
            blocked = 0;
        }
    }

    picoquic_path_t * path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
    picoquic_packet_context_t *pkt_ctx;
    if (blocked != 0) {
        for (int i = 0; blocked != 0 && pacing == 0 && i < nb_paths; i++) {
            path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, i);
            for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
                pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, AK_PATH_PKT_CTX, pc);
                picoquic_packet_t* p = (picoquic_packet_t *) get_pkt_ctx(pkt_ctx, AK_PKTCTX_RETRANSMIT_OLDEST);

                if (p != NULL && ret == 0 && helper_retransmit_needed_by_packet(cnx, p, current_time, &timer_based, NULL, NULL)) {
                    blocked = 0;
                }
                else if (helper_is_ack_needed(cnx, current_time, pc, path_x)) {
                    blocked = 0;
                }
            }

            if (blocked != 0) {
                uint64_t cwin_x = (uint64_t) get_path(path_x, AK_PATH_CWIN, 0);
                uint64_t bytes_in_transit_x = (uint64_t) get_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0);
                if (cwin_x > bytes_in_transit_x) {
                    if (helper_should_send_max_data(cnx) ||
                        helper_is_tls_stream_ready(cnx) ||
                        ((cnx_state == picoquic_state_client_ready || cnx_state == picoquic_state_server_ready) &&
                        ((stream = helper_find_ready_stream(cnx)) != NULL || run_noparam(cnx, PROTOOPID_NOPARAM_HAS_CONGESTION_CONTROLLED_PLUGIN_FRAMEMS_TO_SEND, 0, NULL, NULL)))) {
                        if (picoquic_is_sending_authorized_by_pacing(path_x, current_time, &next_time)) {
                            blocked = 0;
                        } else {
                            pacing = 1;
                        }
                    }
                }
            }
        }
    }

    if (blocked == 0 || (wake_now && pacing == 0)) {
        next_time = current_time;
    } else if (pacing == 0) {
        for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
            for (int i = 0; i < nb_paths; i++) {
                path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, i);
                pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, AK_PATH_PKT_CTX, pc);
                picoquic_packet_t* p = (picoquic_packet_t *) get_pkt_ctx(pkt_ctx, AK_PKTCTX_RETRANSMIT_OLDEST);
                /* Consider delayed ACK */
                int ack_needed = (int) get_pkt_ctx(pkt_ctx, AK_PKTCTX_ACK_NEEDED);
                if (ack_needed) {
                    uint64_t ack_time = get_pkt_ctx(pkt_ctx, AK_PKTCTX_HIGHEST_ACK_TIME) + get_pkt_ctx(pkt_ctx, AK_PKTCTX_ACK_DELAY_LOCAL);

                    if (ack_time < next_time) {
                        next_time = ack_time;
                    }
                }

                /* Consider delayed RACK */
                if (p != NULL) {
                    int64_t delta_seq = get_pkt_ctx(pkt_ctx, AK_PKTCTX_HIGHEST_ACKNOWLEDGED) - get_pkt(p, AK_PKT_SEQUENCE_NUMBER);
                    uint64_t latest_time_acknowledged = (uint64_t) get_pkt_ctx(pkt_ctx, AK_PKTCTX_LATEST_TIME_ACKNOWLEDGED); // time at which the latest acknowledged packet was sent
                    uint64_t send_time = (uint64_t) get_pkt(p, AK_PKT_SEND_TIME);
                    uint64_t smoothed_rtt = get_path(path_x, AK_PATH_SMOOTHED_RTT, 0);
                    picoquic_packet_type_enum ptype = (picoquic_packet_type_enum) get_pkt(p, AK_PKT_TYPE);
                    if (latest_time_acknowledged > send_time    // we already received an acknowledgement for an older packet, so there is a hole. Identical to checking delta_seq > 0
                        && send_time + smoothed_rtt + (smoothed_rtt >> 3) < next_time
                        && ptype != picoquic_packet_0rtt_protected) {
                        next_time = send_time + smoothed_rtt + (smoothed_rtt >> 3); // we retransmit the packet after at least 9/8*rtt
                        /* RACK logic fails when the smoothed RTT is too small, in which case we
                         * rely on dupack logic possible, or on a safe estimate of the RACK delay if it
                         * is not */
                        if (delta_seq < 3) {
                            uint64_t rack_timer_min = latest_time_acknowledged + PICOQUIC_RACK_DELAY; // ensure at least a safe delay of PICOQUIC_RACK_DELAY
                            if (next_time < rack_timer_min)
                                next_time = rack_timer_min;
                        }
                    }

                    uint64_t nb_retransmit = (uint64_t) get_pkt_ctx(pkt_ctx, AK_PKTCTX_NB_RETRANSMIT);
                    if (nb_retransmit == 0) {
                        uint64_t retransmit_timer_x = (uint64_t) get_path(path_x, AK_PATH_RETRANSMIT_TIMER, 0);
                        if (send_time + retransmit_timer_x < next_time) {
                            next_time = send_time + retransmit_timer_x;
                        }
                    }
                    else {
                        if (send_time + (1000000ull << (nb_retransmit - 1)) < next_time) {
                            next_time = send_time + (1000000ull << (nb_retransmit - 1));
                        }
                    }
                }
            }
        }

        for (int i = 0; i < nb_paths; i++) {
            path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, i);
            int challenge_verified_x = (int) get_path(path_x, AK_PATH_CHALLENGE_VERIFIED, 0);
            /* Consider path challenges */
            if (challenge_verified_x == 0) {
                uint64_t challenge_time_x = (uint64_t) get_path(path_x, AK_PATH_CHALLENGE_TIME, 0);
                uint64_t retransmit_timer_x = (uint64_t) get_path(path_x, AK_PATH_RETRANSMIT_TIMER, 0);
                uint64_t next_challenge_time = challenge_time_x + retransmit_timer_x;
                if (current_time < next_challenge_time) {
                    if (next_time > next_challenge_time) {
                        next_time = next_challenge_time;
                    }
                }
            }

            /* Consider keep alive */
            uint64_t keep_alive_interval = (uint64_t) get_cnx(cnx, AK_CNX_KEEP_ALIVE_INTERVAL, 0);
            if (keep_alive_interval != 0 && next_time > (latest_progress_time + keep_alive_interval)) {
                next_time = latest_progress_time + keep_alive_interval;
            }
        }
    }

    set_cnx(cnx, AK_CNX_WAKE_NOW, 0, 0);

    /* reset the connection at its new logical position */
    picoquic_reinsert_cnx_by_wake_time(cnx, next_time);

    return 0;
}