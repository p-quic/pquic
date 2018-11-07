#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

protoop_arg_t select_sending_path(picoquic_cnx_t *cnx)
{
    picoquic_path_t *path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0); /* We should NEVER return NULL */
    picoquic_path_t *path_0 = path_x;
    picoquic_path_t *path_c = NULL;
    bpf_data *bpfd = get_bpf_data(cnx);
    path_data_t *pd = NULL;
    uint8_t selected_path_index = 255;
    bool has_multiple_paths = false;
    start_using_path_if_possible(cnx);
    uint64_t smoothed_rtt_x = 0;
    for (int i = 0; i < bpfd->nb_proposed; i++) {
        pd = &bpfd->paths[i];
        /* Lowest RTT-based scheduler */
        if (pd->state == 2) {
            path_c = pd->path;
            int challenge_verified_c = (int) get_path(path_c, PATH_AK_CHALLENGE_VERIFIED, 0);
            uint64_t challenge_time_c = (uint64_t) get_path(path_c, PATH_AK_CHALLENGE_TIME, 0);
            uint64_t retransmit_timer_c = (uint64_t) get_path(path_c, PATH_AK_RETRANSMIT_TIMER, 0);
            uint8_t challenge_repeat_count_c = (uint8_t) get_path(path_c, PATH_AK_CHALLENGE_REPEAT_COUNT, 0);

            if (!challenge_verified_c && challenge_time_c + retransmit_timer_c < picoquic_current_time() && challenge_repeat_count_c < PICOQUIC_CHALLENGE_REPEAT_MAX) {
                /* Start the challenge! */
                return (protoop_arg_t) path_c;
            }

            int challenge_response_to_send_c = (int) get_path(path_c, PATH_AK_CHALLENGE_RESPONSE_TO_SEND, 0);
            if (challenge_response_to_send_c) {
                /* Reply as soon as possible! */
                return (protoop_arg_t) path_c;
            }

            int ping_received_c = (int) get_path(path_c, PATH_AK_PING_RECEIVED, 0);
            if (ping_received_c) {
                /* We need some action from the path! */
                return (protoop_arg_t) path_c;
            }

            /* Don't consider invalid paths */
            if (!challenge_verified_c) {
                continue;
            }

            if (path_c != path_0) {
                has_multiple_paths = true;
                /* Set the default path to be this one */
                if (path_x == path_0) {
                    path_x = path_c;
                    continue;
                }
            }
            uint64_t cwin_c = (uint64_t) get_path(path_c, PATH_AK_CWIN, 0);
            uint64_t bytes_in_transit_c = (uint64_t) get_path(path_c, PATH_AK_BYTES_IN_TRANSIT, 0);
            if (cwin_c <= bytes_in_transit_c) {
                continue;
            }
            uint64_t smoothed_rtt_c = (uint64_t) get_path(path_c, PATH_AK_SMOOTHED_RTT, 0);
            if (path_x && path_x->smoothed_rtt < path_c->smoothed_rtt) {
                continue;
            }
            path_x = path_c;
            smoothed_rtt_x = smoothed_rtt_c;
        }
    }

    bpfd->last_path_index_sent = selected_path_index;

    return (protoop_arg_t) path_x;
}