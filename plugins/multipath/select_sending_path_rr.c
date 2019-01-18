#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

protoop_arg_t select_sending_path(picoquic_cnx_t *cnx)
{
    picoquic_path_t *path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);
    picoquic_path_t *path_0 = path_x;
    picoquic_path_t *path_c = NULL;
    bpf_data *bpfd = get_bpf_data(cnx);
    path_data_t *pd = NULL;
    uint8_t selected_path_index = 255;
    start_using_path_if_possible(cnx);
    uint64_t now = picoquic_current_time();
    for (int i = 0; i < bpfd->nb_proposed; i++) {
        pd = &bpfd->paths[i];

        /* A (very) simple round-robin */
        if (pd->state == 2) {
            path_c = pd->path;
            int challenge_verified_c = (int) get_path(path_c, PATH_AK_CHALLENGE_VERIFIED, 0);
            uint64_t challenge_time_c = (uint64_t) get_path(path_c, PATH_AK_CHALLENGE_TIME, 0);
            uint64_t retransmit_timer_c = (uint64_t) get_path(path_c, PATH_AK_RETRANSMIT_TIMER, 0);
            uint8_t challenge_repeat_count_c = (uint8_t) get_path(path_c, PATH_AK_CHALLENGE_REPEAT_COUNT, 0);

            if (!challenge_verified_c && challenge_time_c + retransmit_timer_c < now && challenge_repeat_count_c < PICOQUIC_CHALLENGE_REPEAT_MAX) {
                /* Start the challenge! */
                path_x = path_c;
                selected_path_index = i;
                break;
            }

            int challenge_response_to_send_c = (int) get_path(path_c, PATH_AK_CHALLENGE_RESPONSE_TO_SEND, 0);
            if (challenge_response_to_send_c) {
                /* Reply as soon as possible! */
                path_x = path_c;
                selected_path_index = i;
                break;
            }

            /* At this point, this means path 0 should NEVER be reused anymore! */
            if (challenge_verified_c && path_x == path_0) {
                path_x = path_c;
                selected_path_index = i;
            }

            /* Very important: don't go further if the cwin is exceeded! */
            uint64_t cwin_c = (uint64_t) get_path(path_c, PATH_AK_CWIN, 0);
            uint64_t bytes_in_transit_c = (uint64_t) get_path(path_c, PATH_AK_BYTES_IN_TRANSIT, 0);
            if (cwin_c <= bytes_in_transit_c) {
                continue;
            }

            int ping_received_c = (int) get_path(path_c, PATH_AK_PING_RECEIVED, 0);
            if (ping_received_c) {
                /* We need some action from the path! */
                path_x = path_c;
                selected_path_index = i;
                break;
            }

            int mtu_needed = (int) helper_is_mtu_probe_needed(cnx, path_c);
            if (mtu_needed) {
                path_x = path_c;
                selected_path_index = i;
                break;
            }

            /* Don't consider invalid paths */
            if (!challenge_verified_c) {
                continue;
            }

            if (path_x == path_0) {
                path_x = pd->path;
                selected_path_index = i;
            } else if (bpfd->last_path_index_sent != i) {
                path_x = pd->path;
                selected_path_index = i;
            }
        }
    }
    bpfd->last_path_index_sent = selected_path_index;
    if (selected_path_index < 255) {
        pd = &bpfd->paths[selected_path_index];

        if (pd->sent_pkt_non_ack >= 10 && !pd->doing_ack) {
            pd->sent_pkt_non_ack = 10;
            reserve_mp_ack_frame(cnx, path_x, picoquic_packet_context_application);
            pd->doing_ack = true;
        } else {
            pd->sent_pkt_non_ack++;
        }
    }

    return (protoop_arg_t) path_x;
}