#include "../bpf.h"

protoop_arg_t schedule_path_rr(picoquic_cnx_t *cnx) {
    picoquic_packet_t *retransmit_p  = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_path_t *from_path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    char *reason = (char *) get_cnx(cnx, AK_CNX_INPUT, 2);

    if (retransmit_p && from_path && reason) {
        if (strncmp(PROTOOPID_NOPARAM_RETRANSMISSION_TIMEOUT, reason, 23) != 0) {
            /* Fast retransmit or TLP, stay on the same path! */
            return (protoop_arg_t) from_path;
        }
    }

    picoquic_path_t *sending_path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
    picoquic_path_t *path_c = sending_path;
    bpf_data *bpfd = get_bpf_data(cnx);
    uniflow_data_t *ud = NULL;
    uint8_t selected_uniflow_index = 255;
    uint64_t selected_sent_pkt = get_path(sending_path, AK_PATH_NB_PKT_SENT, 0);
    uint64_t cwin_c = (uint64_t) get_path(path_c, AK_PATH_CWIN, 0);
    uint64_t bytes_in_transit_c = (uint64_t) get_path(path_c, AK_PATH_BYTES_IN_TRANSIT, 0);
    int selected_cwin_limited = cwin_c <= bytes_in_transit_c;
    char *path_reason = "";

    for (int i = 0; i < bpfd->nb_sending_proposed; i++) {
        ud = bpfd->sending_uniflows[i];

        /* A (very) simple round-robin */
        if (ud->state == uniflow_active) {
            path_c = ud->path;
            int challenge_verified_c = (int) get_path(path_c, AK_PATH_CHALLENGE_VERIFIED, 0);

            /* Very important: don't go further if the cwin is exceeded! */
            cwin_c = (uint64_t) get_path(path_c, AK_PATH_CWIN, 0);
            bytes_in_transit_c = (uint64_t) get_path(path_c, AK_PATH_BYTES_IN_TRANSIT, 0);
            if (cwin_c <= bytes_in_transit_c) {
                if (sending_path == path_c)
                    selected_cwin_limited = 1;
                continue;
            }

            /* Don't consider invalid paths */
            if (!challenge_verified_c) {
                continue;
            }

            uint64_t pkt_sent_c = (uint64_t) get_path(path_c, AK_PATH_NB_PKT_SENT, 0);
            if (pkt_sent_c < selected_sent_pkt || selected_cwin_limited) {
                sending_path = ud->path;
                selected_uniflow_index = i;
                selected_sent_pkt = pkt_sent_c;
                path_reason = "ROUND_ROBIN";
            }
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