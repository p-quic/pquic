#include "../bpf.h"

static uint64_t find_smooth_rtt(bpf_data *bpfd, bpf_tuple_data *bpftd, int sending_index) {
    /* Instead of finding the smallest RTT, just weight them by the number of packets */
    uint64_t srtt = 0;
    uint64_t nb_updates = 0;
    for (int i = 0; i < bpfd->nb_receiving_proposed; i++) {
        srtt += bpftd->tuple_stats[i][sending_index].smoothed_rtt * bpftd->tuple_stats[i][sending_index].nb_updates;
        nb_updates += bpftd->tuple_stats[i][sending_index].nb_updates;
    }
    if (nb_updates == 0) return 1; /* Give a chance to be used */
    return srtt / nb_updates;
}

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

    picoquic_path_t *sending_path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0); /* We should NEVER return NULL */
    picoquic_path_t *path_c = sending_path;
    bpf_data *bpfd = get_bpf_data(cnx);
    bpf_tuple_data *bpftd = get_bpf_tuple_data(cnx);
    uniflow_data_t *ud = NULL;
    uint8_t selected_uniflow_index = 255;
    uint64_t smoothed_rtt_x = 0;
    int valid = 0;

    for (uint8_t i = 0; i < bpfd->nb_sending_proposed; i++) {
        ud = bpfd->sending_uniflows[i];
        /* Lowest RTT-based scheduler */
        if (ud->state == uniflow_active) {
            path_c = ud->path;
            int challenge_verified_c = (int) get_path(path_c, AK_PATH_CHALLENGE_VERIFIED, 0);

            /* If we want another path, ask for it now */
            if (change_path && i != bpfd->last_uniflow_index_sent) {
                sending_path = path_c;
                selected_uniflow_index = i;
                smoothed_rtt_x = find_smooth_rtt(bpfd, bpftd, i);
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

            /* Stupid heuristic, but needed: we require to retransmit the packet from the given path */
            /* FIXME */
            if (path_c == from_path) {
                sending_path = path_c;
                selected_uniflow_index = i;
                valid = 0;
                path_reason = "RETRANSMISSION";
                break;
            }

            /* Don't consider invalid paths */
            if (!challenge_verified_c) {
                continue;
            }

            uint64_t smoothed_rtt_c = find_smooth_rtt(bpfd, bpftd, i);
            if (sending_path && valid && smoothed_rtt_x < smoothed_rtt_c) {
                continue;
            }
            sending_path = path_c;
            selected_uniflow_index = i;
            smoothed_rtt_x = smoothed_rtt_c;
            valid = 1;
            path_reason = "BEST_RTT";
        }
    }

    bpfd->last_uniflow_index_sent = selected_uniflow_index;
    LOG {
        size_t path_reason_len = strlen(path_reason) + 1;
        char *p_path_reason = my_malloc(cnx, path_reason_len);
        my_memcpy(p_path_reason, path_reason, path_reason_len);
        LOG_EVENT(cnx, "multipath", "schedule_path", p_path_reason, "{\"sending path\": \"%p\"}", (protoop_arg_t) sending_path);
        my_free(cnx, p_path_reason);
    }
    return (protoop_arg_t) sending_path;
}
