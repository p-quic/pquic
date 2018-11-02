#include "picoquic_internal.h"
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
    int pc_ready_flag = 1 << picoquic_packet_context_initial;
    picoquic_stream_head *tls_stream_0 = (picoquic_stream_head *) get_cnx(cnx, CNX_AK_TLS_STREAM, 0);

    picoquic_crypto_context_t *crypto_context_1 = (picoquic_crypto_context_t *) get_cnx(cnx, CNX_AK_CRYPTO_CONTEXT, 1);
    picoquic_crypto_context_t *crypto_context_2 = (picoquic_crypto_context_t *) get_cnx(cnx, CNX_AK_CRYPTO_CONTEXT, 2);
    int nb_paths = (int) get_cnx(cnx, CNX_AK_NB_PATHS, 0);

    if (tls_stream_0->send_queue == NULL) {
        picoquic_stream_head *tls_stream_1 = (picoquic_stream_head *) get_cnx(cnx, CNX_AK_TLS_STREAM, 1);
        if (crypto_context_1->aead_encrypt != NULL &&
            tls_stream_1->send_queue != NULL) {
            pc_ready_flag |= 1 << picoquic_packet_context_application;
        }
        else if (crypto_context_2->aead_encrypt != NULL &&
            tls_stream_1->send_queue == NULL) {
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
                picoquic_packet_t* p = path_x->pkt_ctx[pc].retransmit_oldest;

                if ((pc_ready_flag & (1 << pc)) == 0) {
                    continue;
                }

                while (p != NULL)
                {
                    if (p->ptype < picoquic_packet_0rtt_protected) {
                        if (helper_retransmit_needed_by_packet(cnx, p, current_time, &timer_based, NULL)) {
                            blocked = 0;
                        }
                        break;
                    }
                    p = p->next_packet;
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
                if (path_x->cwin > path_x->bytes_in_transit && path_x->challenge_verified == 1) {
                    if (helper_should_send_max_data(cnx) ||
                        helper_is_tls_stream_ready(cnx) ||
                        (crypto_context_1->aead_encrypt != NULL && (stream = helper_find_ready_stream(cnx)) != NULL)) {
                        if (path_x->next_pacing_time < current_time + path_x->pacing_margin_micros) {
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
            next_time = path_x->next_pacing_time;
        }
        else {
            for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
                for (int i = 0; i < nb_paths; i++) {
                    path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
                    picoquic_packet_t* p = path_x->pkt_ctx[pc].retransmit_oldest;
                    
                    if ((pc_ready_flag & (1 << pc)) == 0) {
                        continue;
                    }
                    
                    /* Consider delayed ACK */
                    if (path_x->pkt_ctx[pc].ack_needed) {
                        next_time = path_x->pkt_ctx[pc].highest_ack_time + path_x->pkt_ctx[pc].ack_delay_local;
                    }

                    while (p != NULL &&
                        p->ptype == picoquic_packet_0rtt_protected &&
                        p->is_evaluated == 1 &&
                        p->contains_crypto == 0) {
                        p = p->next_packet;
                    }

                    if (p != NULL) {
                        if (path_x->pkt_ctx[pc].nb_retransmit == 0) {
                            if (p->send_time + path_x->retransmit_timer < next_time) {
                                next_time = p->send_time + path_x->retransmit_timer;
                            }
                        }
                        else {
                            if (p->send_time + (1000000ull << (path_x->pkt_ctx[pc].nb_retransmit - 1)) < next_time) {
                                next_time = p->send_time + (1000000ull << (path_x->pkt_ctx[pc].nb_retransmit - 1));
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
        if (blocked != 0 && path_x->challenge_verified == 0) {
            uint64_t next_challenge_time = path_x->challenge_time + path_x->retransmit_timer;
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
 * cnx->protoop_inputv[0] = uint64_t current_time
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

    if (cnx_state == picoquic_state_disconnecting || cnx_state == picoquic_state_handshake_failure || cnx_state == picoquic_state_closing_received) {
        blocked = 0;
    }

    int nb_paths = (int) get_cnx(cnx, CNX_AK_NB_PATHS, 0);

    for (int i = 0; blocked != 0 && i < nb_paths; i++) {
        picoquic_path_t * path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
        if (path_x->cwin > path_x->bytes_in_transit && helper_is_mtu_probe_needed(cnx, path_x)) {
            blocked = 0;
        }
    }

    picoquic_path_t * path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);
    if (blocked != 0) {
        for (int i = 0; blocked != 0 && pacing == 0 && i < nb_paths; i++) {
            path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
            for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
                picoquic_packet_t* p = path_x->pkt_ctx[pc].retransmit_oldest;

                if (p != NULL && ret == 0 && helper_retransmit_needed_by_packet(cnx, p, current_time, &timer_based, NULL)) {
                    blocked = 0;
                }
                else if (helper_is_ack_needed(cnx, current_time, pc, path_x)) {
                    blocked = 0;
                }
            }

            if (blocked != 0) {
                if (path_x->cwin > path_x->bytes_in_transit) {
                    if (helper_should_send_max_data(cnx) ||
                        helper_is_tls_stream_ready(cnx) ||
                        ((cnx_state == picoquic_state_client_ready || cnx_state == picoquic_state_server_ready) &&
                        (stream = helper_find_ready_stream(cnx)) != NULL)) {
                        if (path_x->next_pacing_time < current_time + path_x->pacing_margin_micros) {
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
        next_time = path_x->next_pacing_time;
    } else {
        for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
            for (int i = 0; i < nb_paths; i++) {
                path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
                picoquic_packet_t* p = path_x->pkt_ctx[pc].retransmit_oldest;
                /* Consider delayed ACK */
                if (path_x->pkt_ctx[pc].ack_needed) {
                    uint64_t ack_time = path_x->pkt_ctx[pc].highest_ack_time + path_x->pkt_ctx[pc].ack_delay_local;

                    if (ack_time < next_time) {
                        next_time = ack_time;
                    }
                }

                /* Consider delayed RACK */
                if (p != NULL) {
                    if (path_x->pkt_ctx[pc].latest_time_acknowledged > p->send_time
                        && p->send_time + PICOQUIC_RACK_DELAY < next_time
                        && p->ptype != picoquic_packet_0rtt_protected) {
                        next_time = p->send_time + PICOQUIC_RACK_DELAY;
                    }

                    if (path_x->pkt_ctx[pc].nb_retransmit == 0) {
                        if (p->send_time + path_x->retransmit_timer < next_time) {
                            next_time = p->send_time + path_x->retransmit_timer;
                        }
                    }
                    else {
                        if (p->send_time + (1000000ull << (path_x->pkt_ctx[pc].nb_retransmit - 1)) < next_time) {
                            next_time = p->send_time + (1000000ull << (path_x->pkt_ctx[pc].nb_retransmit - 1));
                        }
                    }
                }
            }
        }

        for (int i = 0; i < nb_paths; i++) {
            path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
            /* Consider path challenges */
            if (path_x->challenge_verified == 0) {
                uint64_t next_challenge_time = path_x->challenge_time + path_x->retransmit_timer;
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