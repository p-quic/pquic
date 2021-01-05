#include "bpf.h"

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_uniflows_frame(picoquic_cnx_t *cnx) {
    uniflows_frame_t *frame = (uniflows_frame_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    bpf_data *bpfd = get_bpf_data(cnx);

    // Iterates over the sending uniflows and set our Remote Address ID according to the Local Address ID encoded
    for (int i = 0; i < frame->active_sending_uniflows; i++) {
        int new_uniflow = 0;
        uniflow_data_t *ud = bpfd->receiving_uniflows[mp_get_uniflow_index(cnx, bpfd, false, frame->sending_uniflow_infos[i].uniflow_id, &new_uniflow)];

        if (new_uniflow) {
            PROTOOP_PRINTF(cnx, "UNIFLOWS frame contained a sending uniflow ID that doesn't match an existing receiving uniflow\n");
            continue;
        }

        uint8_t addr_id = frame->sending_uniflow_infos[i].local_address_id;
        if (bpfd->rem_addrs[addr_id].sa) {
            ud->rem_addr_id = addr_id;
            size_t rem_addr_len = bpfd->rem_addrs[ud->rem_addr_id].is_v6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
            my_memcpy((void *) get_path(ud->path, AK_PATH_PEER_ADDR, 0), bpfd->rem_addrs[ud->rem_addr_id].sa, rem_addr_len);
            set_path(ud->path, AK_PATH_PEER_ADDR_LEN, 0, rem_addr_len);
        } else {
            PROTOOP_PRINTF(cnx, "UNIFLOWS frame referenced unknown remote address id %d\n", addr_id);
        }
    }

    for (int i = 0; i < bpfd->nb_receiving_proposed; i++) {
        uniflow_data_t *ud = bpfd->receiving_uniflows[i];
        if (ud && ud->rem_addr_id > 0 && bpfd->rem_addrs[ud->rem_addr_id].sa) {
            struct sockaddr *t = (struct sockaddr *) get_path(ud->path, AK_PATH_PEER_ADDR, 0);
            size_t path_addr_len = (size_t) get_path(ud->path, AK_PATH_PEER_ADDR_LEN, 0);
            struct sockaddr_storage a;
            struct sockaddr *path_addr = (struct sockaddr *) &a;
            my_memcpy(path_addr, t, path_addr_len);

            int known_addr = 0;
            for (int j = 0; j < bpfd->nb_rem_addrs; j++) {
                addr_data_t *addr = bpfd->rem_addrs + j;
                if (addr->sa && picoquic_compare_addr(path_addr, addr->sa) == 0) {
                    if (addr->id != ud->rem_addr_id) {
                        uint8_t old_addr_id = ud->rem_addr_id;
                        LOG_EVENT(cnx, "multipath", "uniflow_migrated", "uniflows_processed", "{\"uniflow_id\": \"%" PRIu64 "\", \"old_remote_address_id\": %d, \"new_remote_address_id\": %d}", ud->uniflow_id, old_addr_id, ud->rem_addr_id);
                        ud->rem_addr_id = addr->id;
                    }
                    known_addr = 1;
                }
            }

            if (!known_addr) {
                addr_data_t *addr = &bpfd->rem_addrs[ud->rem_addr_id];
                char old[INET6_ADDRSTRLEN] = {0};
                char new[INET6_ADDRSTRLEN] = {0};
                inet_ntop(addr->sa->sa_family, addr->sa->sa_family == AF_INET
                                               ? (struct sockaddr *) &((struct sockaddr_in *) addr->sa)->sin_addr
                                               : (struct sockaddr *) &((struct sockaddr_in6 *) addr->sa)->sin6_addr,
                          old, sizeof(old));
                inet_ntop(path_addr->sa_family, path_addr->sa_family == AF_INET
                                                ? (const void *) &((struct sockaddr_in *) path_addr)->sin_addr
                                                : (const void *) &((struct sockaddr_in6 *) path_addr)->sin6_addr,
                          new, sizeof(new));
                LOG_EVENT(cnx, "multipath", "address_updated", "uniflows_processed", "{\"remote_address_id\": %d, \"old_address\": \"%s\", \"new_address\": \"%s\"}", ud->uniflow_id, (protoop_arg_t) old, (protoop_arg_t) new);
                my_memcpy(addr->sa, path_addr, path_addr_len);
                addr->is_v6 = path_addr->sa_family == AF_INET6;

                for (int j = 0; j < bpfd->nb_sending_proposed; j++) {
                    uniflow_data_t *tud = bpfd->sending_uniflows[j];
                    if (tud && tud->rem_addr_id == ud->rem_addr_id) { // This uniflow is also affected by the translation
                        my_memcpy((struct sockaddr_storage *) get_path(tud->path, AK_PATH_PEER_ADDR, 0), addr->sa, path_addr_len);
                        set_path(tud->path, AK_PATH_PEER_ADDR_LEN, 0, path_addr_len);
                    }
                }

                for (int j = 0; j < bpfd->nb_receiving_proposed; j++) {
                    uniflow_data_t *tud = bpfd->receiving_uniflows[j];
                    if (tud && tud->rem_addr_id == ud->rem_addr_id) { // This uniflow is also affected by the translation
                        my_memcpy((struct sockaddr_storage *) get_path(tud->path, AK_PATH_PEER_ADDR, 0), addr->sa, path_addr_len);
                        set_path(tud->path, AK_PATH_PEER_ADDR_LEN, 0, path_addr_len);
                    }
                }
            }
        }
    }

    return 0;
}