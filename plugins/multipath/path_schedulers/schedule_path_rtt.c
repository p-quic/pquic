#include "../bpf.h"

protoop_arg_t schedule_path_rtt(picoquic_cnx_t *cnx) {
    picoquic_packet_t *retransmit_p  = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_path_t *from_path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    char *reason = (char *) get_cnx(cnx, AK_CNX_INPUT, 2);
    int change_path = (int) get_cnx(cnx, AK_CNX_INPUT, 3);
    char *path_reason = "";

    if (retransmit_p && from_path && reason) {
        if (strncmp(PROTOOPID_NOPARAM_RETRANSMISSION_TIMEOUT, reason, 23) != 0) {
            /* Fast retransmit or TLP, stay on the same path! */
            return (protoop_arg_t) from_path;
        }
    }

    picoquic_path_t *path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0); /* We should NEVER return NULL */
    picoquic_path_t *path_0 = path_x;
    picoquic_path_t *path_c = NULL;
    bpf_data *bpfd = get_bpf_data(cnx);
    path_data_t *pd = NULL;
    uint8_t selected_path_index = 255;
    manage_paths(cnx);
    uint64_t smoothed_rtt_x = 0;
    uint64_t now = picoquic_current_time();
    int valid = 0;
    picoquic_stream_head *stream = helper_find_ready_stream(cnx);
    int tls_ready = helper_is_tls_stream_ready(cnx);
    for (uint8_t i = 0; i < bpfd->nb_proposed; i++) {
        pd = bpfd->paths[i];
        /* Lowest RTT-based scheduler */
        if (pd->state == path_active) {
            path_c = pd->path;
            int challenge_verified_c = (int) get_path(path_c, AK_PATH_CHALLENGE_VERIFIED, 0);
            uint64_t challenge_time_c = (uint64_t) get_path(path_c, AK_PATH_CHALLENGE_TIME, 0);
            uint64_t retransmit_timer_c = (uint64_t) get_path(path_c, AK_PATH_RETRANSMIT_TIMER, 0);
            uint8_t challenge_repeat_count_c = (uint8_t) get_path(path_c, AK_PATH_CHALLENGE_REPEAT_COUNT, 0);

            if (!challenge_verified_c && challenge_time_c + retransmit_timer_c < now && challenge_repeat_count_c < PICOQUIC_CHALLENGE_REPEAT_MAX) {
                /* Start the challenge! */
                path_x = path_c;
                selected_path_index = i;
                valid = 0;
                path_reason = "CHALLENGE_REQUEST";
                break;
            }

            int challenge_response_to_send_c = (int) get_path(path_c, AK_PATH_CHALLENGE_RESPONSE_TO_SEND, 0);
            if (challenge_response_to_send_c) {
                /* Reply as soon as possible! */
                path_x = path_c;
                selected_path_index = i;
                valid = 0;
                path_reason = "CHALLENGE_RESPONSE";
                break;
            }

            /* At this point, this means path 0 should NEVER be reused anymore! */
            if (challenge_verified_c && path_x == path_0) {
                path_x = path_c;
                selected_path_index = i;
                smoothed_rtt_x = (uint64_t) get_path(path_c, AK_PATH_SMOOTHED_RTT, 0);
                valid = 0;
                path_reason = "AVOID_PATH_0";
            }

            /* If we want another path, ask for it now */
            if (change_path && i != bpfd->last_path_index_sent) {
                path_x = path_c;
                selected_path_index = i;
                smoothed_rtt_x = (uint64_t) get_path(path_c, AK_PATH_SMOOTHED_RTT, 0);
                valid = 0;
                path_reason = "PATH_CHANGE";
                break;
            }

            /* Very important: don't go further if the cwin is exceeded! */
            uint64_t cwin_c = (uint64_t) get_path(path_c, AK_PATH_CWIN, 0);
            uint64_t bytes_in_transit_c = (uint64_t) get_path(path_c, AK_PATH_BYTES_IN_TRANSIT, 0);
            if (cwin_c <= bytes_in_transit_c) {
                continue;
            }

            int ping_received_c = (int) get_path(path_c, AK_PATH_PING_RECEIVED, 0);
            if (ping_received_c) {
                /* We need some action from the path! */
                path_x = path_c;
                selected_path_index = i;
                valid = 0;
                path_reason = "PONG";
                break;
            }

            int mtu_needed = (int) helper_is_mtu_probe_needed(cnx, path_c);
            if (stream == NULL && tls_ready == 0 && mtu_needed) {
                path_x = path_c;
                selected_path_index = i;
                valid = 0;
                path_reason = "MTU_DISCOVERY";
                break;
            }

            /* Stupid heuristic, but needed: we require to retransmit the packet from the given path */
            /* FIXME */
            if (path_c == from_path) {
                path_x = path_c;
                selected_path_index = i;
                valid = 0;
                path_reason = "RETRANSMISSION";
                break;
            }

            /* Don't consider invalid paths */
            if (!challenge_verified_c) {
                continue;
            }

            /* If we require ACK, favour the path! */
            int is_ack_needed = helper_is_ack_needed(cnx, now, picoquic_packet_context_application, path_x);
            if (is_ack_needed) {
                path_x = path_c;
                selected_path_index = i;
                valid = 0;
                path_reason = "ACK_NEEDED";
                break;
            }

            uint64_t smoothed_rtt_c = (uint64_t) get_path(path_c, AK_PATH_SMOOTHED_RTT, 0);
            if (path_c != path_0) {
// TODO: Fix RTT probes
#ifdef ENABLE_RTT_PROBE
                uint64_t current_time = picoquic_current_time();
                uint32_t send_mtu = (uint32_t) get_path(path_c, AK_PATH_SEND_MTU, 0);
                /* ALWAYS AVOID PROBING A PATH IF ITS CWIN IS NEARLY FULL!!! */
                if (bytes_in_transit_c * 2 <= cwin_c && pd->last_rtt_probe + smoothed_rtt_c + RTT_PROBE_INTERVAL < current_time && !pd->rtt_probe_ready) {  // Prepares a RTT probe
                    pd->last_rtt_probe = current_time;
                    pd->rtt_probe_tries = 0;
                    reserve_frame_slot_t *slot = (reserve_frame_slot_t *) my_malloc(cnx, sizeof(reserve_frame_slot_t));
                    if (slot == NULL) {
                        continue;
                    }
                    my_memset(slot, 0, sizeof(reserve_frame_slot_t));
                    slot->nb_bytes = send_mtu / 20;
                    slot->frame_type = RTT_PROBE_TYPE;
                    slot->frame_ctx = (void *)(uint64_t) i;
                    size_t ret = reserve_frames(cnx, 1, slot);
                }

                if (pd->rtt_probe_ready) {  // Sends the RTT probe in the retry queue
                    path_x = path_c;
                    selected_path_index = i;
                    valid = 0;
                    path_reason = "RTT_PROBE";
                    break;
                }
#endif

                /* Set the default path to be this one */
                if (path_x == path_0) {
                    path_x = path_c;
                    selected_path_index = i;
                    smoothed_rtt_x = (uint64_t) get_path(path_c, AK_PATH_SMOOTHED_RTT, 0);
                    valid = 0;
                    continue;
                }
            }
            if (path_x && valid && smoothed_rtt_x < smoothed_rtt_c) {
                continue;
            }
            path_x = path_c;
            selected_path_index = i;
            smoothed_rtt_x = smoothed_rtt_c;
            valid = 1;
            path_reason = "BEST_RTT";
        }
    }

    bpfd->last_path_index_sent = selected_path_index;
    LOG {
        size_t path_reason_len = strlen(path_reason) + 1;
        char *p_path_reason = my_malloc(cnx, path_reason_len);
        my_memcpy(p_path_reason, path_reason, path_reason_len);
        LOG_EVENT(cnx, "MULTIPATH", "SCHEDULE_PATH", p_path_reason, "{\"path\": \"%p\"}", (protoop_arg_t) path_x);
        my_free(cnx, p_path_reason);
    }
    return (protoop_arg_t) path_x;
}
