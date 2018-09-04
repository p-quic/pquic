#include "picoquic_internal.h"
#include "plugin.h"
#include "bpf.h"

/* Decide whether MAX data need to be sent or not */
static int should_send_max_data(picoquic_cnx_t* cnx)
{
    int ret = 0;

    if (2 * cnx->data_received > cnx->maxdata_local)
        ret = 1;

    return ret;
}

/* Decide whether to send an MTU probe */
static int is_mtu_probe_needed(picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{
    int ret = 0;

    if ((cnx->cnx_state == picoquic_state_client_ready || cnx->cnx_state == picoquic_state_server_ready) && path_x->mtu_probe_sent == 0 && (path_x->send_mtu_max_tried == 0 || (path_x->send_mtu + 10) < path_x->send_mtu_max_tried)) {
        ret = 1;
    }

    return ret;
}

static picoquic_stream_head *find_ready_stream(picoquic_cnx_t *cnx)
{
    return (picoquic_stream_head *) plugin_run_protoop(cnx, PROTOOPID_FIND_READY_STREAM, 0, NULL, NULL);
}

static int is_ack_needed(picoquic_cnx_t *cnx, uint64_t current_time, picoquic_packet_context_enum pc)
{
    protoop_arg_t args[2];
    args[0] = (protoop_arg_t) current_time;
    args[1] = (protoop_arg_t) pc;
    return (int) plugin_run_protoop(cnx, PROTOOPID_FIND_READY_STREAM, 2, args, NULL);
}

static int is_tls_stream_ready(picoquic_cnx_t *cnx)
{
    return (int) plugin_run_protoop(cnx, PROTOOPID_IS_TLS_STREAM_READY, 0, NULL, NULL);
}

/* For a very strange reason, we absolutely need to put calls into static functions, otherwise clang might bug... o_O */
static int retransmit_needed_by_packet(picoquic_cnx_t *cnx, picoquic_packet_t *p, uint64_t current_time, int *timer_based)
{
    protoop_arg_t args[3], outs[PROTOOPARGS_MAX];
    args[0] = (protoop_arg_t) p;
    args[1] = (protoop_arg_t) current_time;
    args[2] = (protoop_arg_t) *timer_based;
    int ret = (int) plugin_run_protoop(cnx, PROTOOPID_RETRANSMIT_NEEDED_BY_PACKET, 3, args, outs);
    *timer_based = (int) outs[0];
    return (int) ret;
}


static void dbg_print(picoquic_cnx_t *cnx, uint64_t val1, uint64_t val2)
{
    protoop_arg_t args[2];
    args[0] = (protoop_arg_t) val1;
    args[1] = (protoop_arg_t) val2;
    bpf_data *bpfd = (bpf_data *) cnx->opaque;
    //if (bpfd->print) plugin_run_protoop(cnx, PROTOOPID_PRINTF, 2, args, NULL);
}

/* Special wake up decision logic in initial state */
/* TODO: tie with per path scheduling */
static void cnx_set_next_wake_time_init(picoquic_cnx_t* cnx, uint64_t current_time)
{
    uint64_t next_time = cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX;
    picoquic_stream_head* stream = NULL;
    int timer_based = 0;
    int blocked = 1;
    int pacing = 0;
    int retransmit_needed = 0;
    protoop_arg_t outs[PROTOOPARGS_MAX], args[PROTOOPARGS_MAX];
    picoquic_path_t * path_x = cnx->path[0];

    if (next_time < current_time)
    {
        next_time = current_time;
        blocked = 0;
    }
    else
    {
        for (picoquic_packet_context_enum pc = 0; blocked == 0 && pc < picoquic_nb_packet_context; pc++) {
            picoquic_packet_t* p = cnx->pkt_ctx[pc].retransmit_oldest;

            while (p != NULL)
            {
                if (p->ptype < picoquic_packet_0rtt_protected) {
                    if (retransmit_needed_by_packet(cnx, p, current_time, &timer_based)) {
                        blocked = 0;
                    }
                    break;
                }
                p = p->next_packet;
            }

            if (blocked != 0)
            {
                if (is_ack_needed(cnx, current_time, pc)) {
                    blocked = 0;
                }
            }
        }

        if (blocked != 0)
        {
            if (path_x->cwin > path_x->bytes_in_transit && path_x->challenge_verified == 1) {
                if (should_send_max_data(cnx) ||
                    is_tls_stream_ready(cnx) ||
                    (cnx->crypto_context[1].aead_encrypt != NULL && (stream = find_ready_stream(cnx)) != NULL)) {
                    if (path_x->next_pacing_time < current_time + path_x->pacing_margin_micros) {
                        blocked = 0;
                    }
                    else {
                        pacing = 1;
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
                picoquic_packet_t* p = cnx->pkt_ctx[pc].retransmit_oldest;
                /* Consider delayed ACK */
                if (cnx->pkt_ctx[pc].ack_needed) {
                    next_time = cnx->pkt_ctx[pc].highest_ack_time + cnx->pkt_ctx[pc].ack_delay_local;
                }

                if (p != NULL) {
                    if (cnx->pkt_ctx[pc].nb_retransmit == 0) {
                        if (p->send_time + path_x->retransmit_timer < next_time) {
                            next_time = p->send_time + path_x->retransmit_timer;
                        }
                    }
                    else {
                        if (p->send_time + (1000000ull << (cnx->pkt_ctx[pc].nb_retransmit - 1)) < next_time) {
                            next_time = p->send_time + (1000000ull << (cnx->pkt_ctx[pc].nb_retransmit - 1));
                        }
                    }
                }
            }
        }
    }

    /* Consider path challenges */
    if (path_x->challenge_verified == 0) {
        uint64_t next_challenge_time = path_x->challenge_time + path_x->retransmit_timer;
        if (next_challenge_time <= current_time) {
            next_time = current_time;
        } else if (next_challenge_time < next_time) {
            next_time = next_challenge_time;
        }
    }

    /* reset the connection at its new logical position */
    picoquic_reinsert_by_wake_time(cnx->quic, cnx, next_time);
}

/**
 * cnx->protoop_inputv[0] = uint64_t current_time
 */
protoop_arg_t set_nxt_wake_time(picoquic_cnx_t *cnx)
{
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[0];
    uint64_t next_time = cnx->latest_progress_time + PICOQUIC_MICROSEC_SILENCE_MAX * (2 - cnx->client_mode);
    picoquic_stream_head* stream = NULL;
    int timer_based = 0;
    int blocked = 1;
    int pacing = 0;
    picoquic_path_t * path_x = cnx->path[0];
    int ret = 0;
    int retransmit_needed = 0;
    protoop_arg_t outs[PROTOOPARGS_MAX], args[PROTOOPARGS_MAX];


    if (cnx->cnx_state < picoquic_state_client_ready)
    {
        cnx_set_next_wake_time_init(cnx, current_time);
        return 0;
    }

    if (cnx->cnx_state == picoquic_state_disconnecting || cnx->cnx_state == picoquic_state_handshake_failure || cnx->cnx_state == picoquic_state_closing_received) {
        blocked = 0;
    }
    else if (path_x->cwin > path_x->bytes_in_transit && is_mtu_probe_needed(cnx, path_x)) {
        blocked = 0;
    }
    else {
        for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
            picoquic_packet_t* p = cnx->pkt_ctx[pc].retransmit_oldest;

            if (p != NULL && ret == 0 && retransmit_needed_by_packet(cnx, p, current_time, &timer_based)) {
                blocked = 0;
            }
            else if (is_ack_needed(cnx, current_time, pc)) {
                blocked = 0;
            }
        }

        if (blocked != 0) {
            if (path_x->cwin > path_x->bytes_in_transit) {
                if (should_send_max_data(cnx) ||
                    is_tls_stream_ready(cnx) ||
                    ((cnx->cnx_state == picoquic_state_client_ready || cnx->cnx_state == picoquic_state_server_ready) &&
                    (stream = find_ready_stream(cnx)) != NULL)) {
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
    } else if (pacing != 0) {
        next_time = path_x->next_pacing_time;
    } else {
        for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
            picoquic_packet_t* p = cnx->pkt_ctx[pc].retransmit_oldest;
            /* Consider delayed ACK */
            if (cnx->pkt_ctx[pc].ack_needed) {
                uint64_t ack_time = cnx->pkt_ctx[pc].highest_ack_time + cnx->pkt_ctx[pc].ack_delay_local;

                if (ack_time < next_time) {
                    next_time = ack_time;
                }
            }

            /* Consider delayed RACK */
            if (p != NULL) {
                if (cnx->pkt_ctx[pc].latest_time_acknowledged > p->send_time
                    && p->send_time + PICOQUIC_RACK_DELAY < next_time
                    && p->ptype != picoquic_packet_0rtt_protected) {
                    next_time = p->send_time + PICOQUIC_RACK_DELAY;
                }

                /* Begin TLP code */
                bpf_data *bpfd = (bpf_data *) cnx->opaque;
                picoquic_packet_t *p_last = cnx->pkt_ctx[pc].retransmit_newest;
                
                if (bpfd->tlp_nb < 3) {
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
                        if (p_last->send_time + 3 / 2 * path_x->smoothed_rtt + path_x->max_ack_delay > bpfd->tlp_time) {
                            bpfd->tlp_time = p_last->send_time + 3 / 2 * path_x->smoothed_rtt + path_x->max_ack_delay;
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
                
                if (cnx->pkt_ctx[pc].nb_retransmit == 0) {
                    if (p->send_time + path_x->retransmit_timer < next_time) {
                        next_time = p->send_time + path_x->retransmit_timer;
                    }
                }
                else {
                    if (p->send_time + (1000000ull << (cnx->pkt_ctx[pc].nb_retransmit - 1)) < next_time) {
                        next_time = p->send_time + (1000000ull << (cnx->pkt_ctx[pc].nb_retransmit - 1));
                    }
                }
            }
        }

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

    dbg_print(cnx, current_time, next_time);

    /* reset the connection at its new logical position */
    picoquic_reinsert_by_wake_time(cnx->quic, cnx, next_time);

    return 0;
}