#include "picoquic_internal.h"
#include "plugin.h"
#include "bpf.h"
#include "../helpers.h"

/* Special wake up decision logic in initial state */
/* TODO: tie with per path scheduling */
static void cnx_set_next_wake_time_init(picoquic_cnx_t* cnx, uint64_t current_time)
{
    uint64_t next_time = cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX;
    picoquic_stream_head* stream = NULL;
    int timer_based = 0;
    int blocked = 1;
    int pacing = 0;
    picoquic_path_t * path_x = cnx->path[0];
    int pc_ready_flag = 1 << picoquic_packet_context_initial;

    if (cnx->tls_stream[0].send_queue == NULL) {
        if (cnx->crypto_context[1].aead_encrypt != NULL &&
            cnx->tls_stream[1].send_queue != NULL) {
            pc_ready_flag |= 1 << picoquic_packet_context_application;
        }
        else if (cnx->crypto_context[2].aead_encrypt != NULL &&
            cnx->tls_stream[1].send_queue == NULL) {
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
            for (int i = 0; blocked == 0 && i < cnx->nb_paths; i++) {
                path_x = cnx->path[i];
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
            for (int i = 0; blocked != 0 && pacing == 0 && i < cnx->nb_paths; i++) {
                path_x = cnx->path[i];
                if (path_x->cwin > path_x->bytes_in_transit && path_x->challenge_verified == 1) {
                    if (helper_should_send_max_data(cnx) ||
                        helper_is_tls_stream_ready(cnx) ||
                        (cnx->crypto_context[1].aead_encrypt != NULL && (stream = helper_find_ready_stream(cnx)) != NULL)) {
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
                for (int i = 0; i < cnx->nb_paths; i++) {
                    path_x = cnx->path[i];
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
    for (int i = 0; i < cnx->nb_paths; i++) {
        path_x = cnx->path[i];
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
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[0];
    uint64_t next_time = cnx->latest_progress_time + PICOQUIC_MICROSEC_SILENCE_MAX * (2 - cnx->client_mode);
    picoquic_stream_head* stream = NULL;
    int timer_based = 0;
    int blocked = 1;
    int pacing = 0;
    int ret = 0;


    if (cnx->cnx_state < picoquic_state_client_ready)
    {
        cnx_set_next_wake_time_init(cnx, current_time);
        return 0;
    }

    if (cnx->cnx_state == picoquic_state_disconnecting || cnx->cnx_state == picoquic_state_handshake_failure || cnx->cnx_state == picoquic_state_closing_received) {
        blocked = 0;
    }

    for (int i = 0; blocked != 0 && i < cnx->nb_paths; i++) {
        picoquic_path_t * path_x = cnx->path[i];
        if (path_x->cwin > path_x->bytes_in_transit && helper_is_mtu_probe_needed(cnx, path_x)) {
            blocked = 0;
        }
    }

    picoquic_path_t * path_x = cnx->path[0];
    if (blocked != 0) {
        for (int i = 0; blocked != 0 && pacing == 0 && i < cnx->nb_paths; i++) {
            path_x = cnx->path[i];
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
                        ((cnx->cnx_state == picoquic_state_client_ready || cnx->cnx_state == picoquic_state_server_ready) &&
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
            for (int i = 0; i < cnx->nb_paths; i++) {
                path_x = cnx->path[i];
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

                    /* Begin TLP code */
                    bpf_data *bpfd = (bpf_data *) get_bpf_data(cnx);
                    picoquic_packet_t *p_last = path_x->pkt_ctx[pc].retransmit_newest;
                    
                    if (bpfd->tlp_nb < 3 && bpfd->tlp_time > 0) {
                        /* Does it have multiple outstanding packets? */
                        if (p != p_last) {
                            /* max(2*SRTT, 10ms) */
                            
                            bpfd->tlp_time = p_last->send_time + 2 * path_x->smoothed_rtt;
                            if (p_last->send_time + 10000 > bpfd->tlp_time) {
                                bpfd->tlp_time = p_last->send_time + 10000;
                            }
                        } else {
                            /* max(2 * SRTT, 1.5 * SRTT + WCDelAckT) */
                            bpfd->tlp_time = p_last->send_time + 2 * path_x->smoothed_rtt;
                            if (p_last->send_time + path_x->smoothed_rtt * 3 / 2 + path_x->max_ack_delay > bpfd->tlp_time) {
                                bpfd->tlp_time = p_last->send_time + path_x->smoothed_rtt * 3 / 2 + path_x->max_ack_delay;
                            }
                        }
                        if (bpfd->tlp_time < next_time) {
                            next_time = bpfd->tlp_time;
                            if (p_last->send_time > bpfd->tlp_packet_send_time) {
                                bpfd->tlp_packet_send_time = p_last->send_time;
                            }
                        } else {
                            bpfd->tlp_time = 0;
                        }
                    }
                    /* End TLP code */
                    
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

        for (int i = 0; i < cnx->nb_paths; i++) {
            path_x = cnx->path[i];
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
            if (cnx->keep_alive_interval != 0 && next_time > (cnx->latest_progress_time + cnx->keep_alive_interval)) {
                next_time = cnx->latest_progress_time + cnx->keep_alive_interval;
            }
        }
    }

    /* reset the connection at its new logical position */
    picoquic_reinsert_cnx_by_wake_time(cnx, next_time);

    return 0;
}