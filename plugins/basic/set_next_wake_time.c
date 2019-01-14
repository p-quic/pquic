#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"

/* Special wake up decision logic in initial state */
/* TODO: tie with per path scheduling */
static void cnx_set_next_wake_time_init(picoquic_cnx_t* cnx, uint64_t current_time)
{
    uint64_t start_time = (uint64_t) get_cnx(cnx, CNX_AK_START_TIME, 0);
    uint64_t next_time = start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX;
    picoquic_stream_head* stream = NULL;
    int timer_based = 0;
    int blocked = 1;
    int pacing = 0;
    picoquic_path_t * path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);
    picoquic_packet_context_t *pkt_ctx;
    int pc_ready_flag = 1 << picoquic_packet_context_initial;
    picoquic_stream_head *tls_stream_0 = (picoquic_stream_head *) get_cnx(cnx, CNX_AK_TLS_STREAM, 0);

    picoquic_crypto_context_t *crypto_context_1 = (picoquic_crypto_context_t *) get_cnx(cnx, CNX_AK_CRYPTO_CONTEXT, 1);
    picoquic_crypto_context_t *crypto_context_2 = (picoquic_crypto_context_t *) get_cnx(cnx, CNX_AK_CRYPTO_CONTEXT, 2);
    int nb_paths = (int) get_cnx(cnx, CNX_AK_NB_PATHS, 0);
    void *crypto_context_1_aead_encrypt = (void *) get_crypto_context(crypto_context_1, CRYPTO_CONTEXT_AK_AEAD_ENCRYPTION);

    picoquic_stream_data *tls_stream_0_send_queue = (picoquic_stream_data *) get_stream_head(tls_stream_0, STREAM_HEAD_AK_SEND_QUEUE);

    if (tls_stream_0_send_queue == NULL) {
        picoquic_stream_head *tls_stream_1 = (picoquic_stream_head *) get_cnx(cnx, CNX_AK_TLS_STREAM, 1);
        picoquic_stream_data *tls_stream_1_send_queue = (picoquic_stream_data *) get_stream_head(tls_stream_1, STREAM_HEAD_AK_SEND_QUEUE);
        void *crypto_context_2_aead_encrypt = (void *) get_crypto_context(crypto_context_2, CRYPTO_CONTEXT_AK_AEAD_ENCRYPTION);
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
                path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
                pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, PATH_AK_PKT_CTX, pc);
                picoquic_packet_t* p = (picoquic_packet_t *) get_pkt_ctx(pkt_ctx, PKT_CTX_AK_RETRANSMIT_OLDEST);

                if ((pc_ready_flag & (1 << pc)) == 0) {
                    continue;
                }

                while (p != NULL)
                {
                    picoquic_packet_type_enum ptype = (picoquic_packet_type_enum) get_pkt(p, PKT_AK_TYPE);
                    if (ptype < picoquic_packet_0rtt_protected) {
                        if (helper_retransmit_needed_by_packet(cnx, p, current_time, &timer_based, NULL)) {
                            blocked = 0;
                        }
                        break;
                    }
                    p = (picoquic_packet_t *) get_pkt(p, PKT_AK_NEXT_PACKET);
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
                path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
                uint64_t cwin_x = (uint64_t) get_path(path_x, PATH_AK_CWIN, 0);
                uint64_t bytes_in_transit_x = (uint64_t) get_path(path_x, PATH_AK_BYTES_IN_TRANSIT, 0);
                int challenge_verified_x = (int) get_path(path_x, PATH_AK_CHALLENGE_VERIFIED, 0);
                if (cwin_x > bytes_in_transit_x && challenge_verified_x == 1) {
                    if (helper_should_send_max_data(cnx) ||
                        helper_is_tls_stream_ready(cnx) ||
                        (crypto_context_1_aead_encrypt != NULL && (stream = helper_find_ready_stream(cnx)) != NULL)) {
                        uint64_t next_pacing_time_x = (uint64_t) get_path(path_x, PATH_AK_NEXT_PACING_TIME, 0);
                        uint64_t pacing_margin_micros_x = (uint64_t) get_path(path_x, PATH_AK_PACING_MARGIN_MICROS, 0);
                        if (next_pacing_time_x < current_time + pacing_margin_micros_x) {
                            blocked = 0;
                        }
                        else {
                            pacing = 1;
                        }
                    }
                }
            }
        }

        if (blocked == 0) {
            next_time = current_time;
        }
        else if (pacing != 0) {
            next_time = (uint64_t) get_path(path_x, PATH_AK_NEXT_PACING_TIME, 0);
        }
        else {
            for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
                for (int i = 0; i < nb_paths; i++) {
                    path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
                    pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, PATH_AK_PKT_CTX, pc);
                    picoquic_packet_t* p = (picoquic_packet_t *) get_pkt_ctx(pkt_ctx, PKT_CTX_AK_RETRANSMIT_OLDEST);
                    
                    if ((pc_ready_flag & (1 << pc)) == 0) {
                        continue;
                    }
                    
                    /* Consider delayed ACK */
                    int ack_needed = (int) get_pkt_ctx(pkt_ctx, PKT_CTX_AK_ACK_NEEDED);
                    if (ack_needed) {
                        next_time = get_pkt_ctx(pkt_ctx, PKT_CTX_AK_HIGHEST_ACK_TIME) + get_pkt_ctx(pkt_ctx, PKT_CTX_AK_ACK_DELAY_LOCAL);
                    }

                    if (p != NULL) {
                        picoquic_packet_type_enum ptype = (picoquic_packet_type_enum) get_pkt(p, PKT_AK_TYPE);
                        int pis_evaluated = (int) get_pkt(p, PKT_AK_IS_EVALUATED);
                        int pcontains_crypto = (int) get_pkt(p, PKT_AK_CONTAINS_CRYPTO); 

                        while (p != NULL &&
                            ptype == picoquic_packet_0rtt_protected &&
                            pis_evaluated == 1 &&
                            pcontains_crypto == 0) {
                            p = (picoquic_packet_t *) get_pkt(p, PKT_AK_NEXT_PACKET);
                            if (p != NULL) {
                                ptype = (picoquic_packet_type_enum) get_pkt(p, PKT_AK_TYPE);
                                pis_evaluated = (int) get_pkt(p, PKT_AK_IS_EVALUATED);
                                pcontains_crypto = (int) get_pkt(p, PKT_AK_CONTAINS_CRYPTO); 
                            }
                        }
                    }    

                    if (p != NULL) {
                        uint64_t nb_retransmit = (uint64_t) get_pkt_ctx(pkt_ctx, PKT_CTX_AK_NB_RETRANSMIT);
                        uint64_t send_time = (uint64_t) get_pkt(p, PKT_AK_SEND_TIME);
                        if (nb_retransmit == 0) {
                            uint64_t retransmit_timer_x = (uint64_t) get_path(path_x, PATH_AK_RETRANSMIT_TIMER, 0);
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
        path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
        int challenge_verified_x = (int) get_path(path_x, PATH_AK_CHALLENGE_VERIFIED, 0);
        if (blocked != 0 && challenge_verified_x == 0) {
            uint64_t challenge_time_x = (uint64_t) get_path(path_x, PATH_AK_CHALLENGE_TIME, 0);
            uint64_t retransmit_timer_x = (uint64_t) get_path(path_x, PATH_AK_RETRANSMIT_TIMER, 0);
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
    uint64_t current_time = (uint64_t) get_cnx(cnx, CNX_AK_INPUT, 0);
    int client_mode = (int) get_cnx(cnx, CNX_AK_CLIENT_MODE, 0);
    uint64_t latest_progress_time = (uint64_t) get_cnx(cnx, CNX_AK_LATEST_PROGRESS_TIME, 0);
    uint64_t next_time = latest_progress_time + PICOQUIC_MICROSEC_SILENCE_MAX * (2 - client_mode);
    picoquic_stream_head* stream = NULL;
    int timer_based = 0;
    int blocked = 1;
    int pacing = 0;
    int ret = 0;
    picoquic_state_enum cnx_state = (picoquic_state_enum) get_cnx(cnx, CNX_AK_STATE, 0);


    if (cnx_state < picoquic_state_client_ready)
    {
        cnx_set_next_wake_time_init(cnx, current_time);
        return 0;
    }

    int wake_now = get_cnx(cnx, CNX_AK_WAKE_NOW, 0);

    if (wake_now) {
        blocked = 0;
        set_cnx(cnx, CNX_AK_WAKE_NOW, 0, 0);
    }

    if (cnx_state == picoquic_state_disconnecting || cnx_state == picoquic_state_handshake_failure || cnx_state == picoquic_state_closing_received) {
        blocked = 0;
    }

    int nb_paths = (int) get_cnx(cnx, CNX_AK_NB_PATHS, 0);

    for (int i = 0; blocked != 0 && i < nb_paths; i++) {
        picoquic_path_t * path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
        uint64_t cwin_x = (uint64_t) get_path(path_x, PATH_AK_CWIN, 0);
        uint64_t bytes_in_transit_x = (uint64_t) get_path(path_x, PATH_AK_BYTES_IN_TRANSIT, 0);
        if (cwin_x > bytes_in_transit_x && helper_is_mtu_probe_needed(cnx, path_x)) {
            blocked = 0;
        }
        if (cwin_x > bytes_in_transit_x && picoquic_has_booked_plugin_frames(cnx)) {
            blocked = 0;
        }
    }

    picoquic_path_t * path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);
    picoquic_packet_context_t *pkt_ctx;
    if (blocked != 0) {
        for (int i = 0; blocked != 0 && pacing == 0 && i < nb_paths; i++) {
            path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
            for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
                pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, PATH_AK_PKT_CTX, pc);
                picoquic_packet_t* p = (picoquic_packet_t *) get_pkt_ctx(pkt_ctx, PKT_CTX_AK_RETRANSMIT_OLDEST);

                if (p != NULL && ret == 0 && helper_retransmit_needed_by_packet(cnx, p, current_time, &timer_based, NULL)) {
                    blocked = 0;
                }
                else if (helper_is_ack_needed(cnx, current_time, pc, path_x)) {
                    blocked = 0;
                }
            }

            if (blocked != 0) {
                uint64_t cwin_x = (uint64_t) get_path(path_x, PATH_AK_CWIN, 0);
                uint64_t bytes_in_transit_x = (uint64_t) get_path(path_x, PATH_AK_BYTES_IN_TRANSIT, 0);
                if (cwin_x > bytes_in_transit_x) {
                    if (helper_should_send_max_data(cnx) ||
                        helper_is_tls_stream_ready(cnx) ||
                        ((cnx_state == picoquic_state_client_ready || cnx_state == picoquic_state_server_ready) &&
                        (stream = helper_find_ready_stream(cnx)) != NULL)) {
                        uint64_t next_pacing_time_x = (uint64_t) get_path(path_x, PATH_AK_NEXT_PACING_TIME, 0);
                        uint64_t pacing_margin_micros_x = (uint64_t) get_path(path_x, PATH_AK_PACING_MARGIN_MICROS, 0);
                        if (next_pacing_time_x < current_time + pacing_margin_micros_x) {
                            blocked = 0;
                        }
                        else {
                            pacing = 1;
                        }
                    }
                }
            }
        }
    }

    if (blocked == 0) {
        next_time = current_time;
    } else if (pacing != 0) {
        next_time = (uint64_t) get_path(path_x, PATH_AK_NEXT_PACING_TIME, 0);
    } else {
        for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
            for (int i = 0; i < nb_paths; i++) {
                path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
                pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, PATH_AK_PKT_CTX, pc);
                picoquic_packet_t* p = (picoquic_packet_t *) get_pkt_ctx(pkt_ctx, PKT_CTX_AK_RETRANSMIT_OLDEST);
                /* Consider delayed ACK */
                int ack_needed = (int) get_pkt_ctx(pkt_ctx, PKT_CTX_AK_ACK_NEEDED);
                if (ack_needed) {
                    uint64_t ack_time = get_pkt_ctx(pkt_ctx, PKT_CTX_AK_HIGHEST_ACK_TIME) + get_pkt_ctx(pkt_ctx, PKT_CTX_AK_ACK_DELAY_LOCAL);

                    if (ack_time < next_time) {
                        next_time = ack_time;
                    }
                }

                /* Consider delayed RACK */
                if (p != NULL) {
                    uint64_t latest_time_acknowledged = (uint64_t) get_pkt_ctx(pkt_ctx, PKT_CTX_AK_LATEST_TIME_ACKNOWLEDGED);
                    uint64_t send_time = (uint64_t) get_pkt(p, PKT_AK_SEND_TIME);
                    picoquic_packet_type_enum ptype = (picoquic_packet_type_enum) get_pkt(p, PKT_AK_TYPE);
                    if (latest_time_acknowledged > send_time
                        && send_time + PICOQUIC_RACK_DELAY < next_time
                        && ptype != picoquic_packet_0rtt_protected) {
                        next_time = send_time + PICOQUIC_RACK_DELAY;
                    }

                    uint64_t nb_retransmit = (uint64_t) get_pkt_ctx(pkt_ctx, PKT_CTX_AK_NB_RETRANSMIT);
                    if (nb_retransmit == 0) {
                        uint64_t retransmit_timer_x = (uint64_t) get_path(path_x, PATH_AK_RETRANSMIT_TIMER, 0);
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
            path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
            int challenge_verified_x = (int) get_path(path_x, PATH_AK_CHALLENGE_VERIFIED, 0);
            /* Consider path challenges */
            if (challenge_verified_x == 0) {
                uint64_t challenge_time_x = (uint64_t) get_path(path_x, PATH_AK_CHALLENGE_TIME, 0);
                uint64_t retransmit_timer_x = (uint64_t) get_path(path_x, PATH_AK_RETRANSMIT_TIMER, 0);
                uint64_t next_challenge_time = challenge_time_x + retransmit_timer_x;
                if (current_time < next_challenge_time) {
                    if (next_time > next_challenge_time) {
                        next_time = next_challenge_time;
                    }
                }
            }

            /* Consider keep alive */
            uint64_t keep_alive_interval = (uint64_t) get_cnx(cnx, CNX_AK_KEEP_ALIVE_INTERVAL, 0);
            if (keep_alive_interval != 0 && next_time > (latest_progress_time + keep_alive_interval)) {
                next_time = latest_progress_time + keep_alive_interval;
            }
        }
    }

    /* reset the connection at its new logical position */
    picoquic_reinsert_cnx_by_wake_time(cnx, next_time);

    return 0;
}