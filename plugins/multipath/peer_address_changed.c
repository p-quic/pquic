#include "bpf.h"

protoop_arg_t peer_address_changed(picoquic_cnx_t *cnx)
{
    picoquic_path_t *path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    struct sockaddr *t = (struct sockaddr *) get_path(path_x, AK_PATH_PEER_ADDR, 0);
    struct sockaddr_storage a;
    struct sockaddr* new_addr = (struct sockaddr *) &a;
    size_t new_addr_len = (size_t) get_path(path_x, AK_PATH_PEER_ADDR_LEN, 0);
    my_memcpy(new_addr, t, new_addr_len);

    bpf_data *bpfd = get_bpf_data(cnx);
    uniflow_data_t *ud = mp_get_receiving_uniflow_data(bpfd, path_x);

    if (!ud) {
        return 0;
    }

    PROTOOP_PRINTF(cnx, "Peer address changed for UID %" PRIu64 "\n", ud->uniflow_id);

    int it_is_migration = 0;
    addr_data_t *addr = NULL;
    for (int i = 0; i < bpfd->nb_rem_addrs; i++) {
        if (picoquic_compare_addr(bpfd->rem_addrs[i].sa, new_addr) == 0) {
            it_is_migration = 1;
            uint8_t old_addr_id = ud->rem_addr_id;
            ud->rem_addr_id = bpfd->rem_addrs[i].id;
            LOG_EVENT(cnx, "multipath", "uniflow_migrated", "peer_address_changed", "{\"uniflow_id\": \"%" PRIu64 "\", \"old_remote_address_id\": %d, \"new_remote_address_id\": %d}", ud->uniflow_id, old_addr_id, ud->rem_addr_id);
        }
        if (bpfd->rem_addrs[i].id == ud->rem_addr_id) {
            addr = bpfd->rem_addrs + i;
        }
    }

    if (!it_is_migration && addr) { // It's a NATed address then
        char old[INET6_ADDRSTRLEN] = { 0 };
        char new[INET6_ADDRSTRLEN] = { 0 };
        inet_ntop(addr->sa->sa_family, addr->sa->sa_family == AF_INET ? (struct sockaddr *) &((struct sockaddr_in *)addr->sa)->sin_addr : (struct sockaddr *) &((struct sockaddr_in6 *)addr->sa)->sin6_addr, old, sizeof(old));
        inet_ntop(new_addr->sa_family, new_addr->sa_family == AF_INET ? (struct sockaddr *) &((struct sockaddr_in *)new_addr)->sin_addr : (struct sockaddr *) &((struct sockaddr_in6 *)new_addr)->sin6_addr, new, sizeof(new));
        LOG_EVENT(cnx, "multipath", "address_updated", "peer_address_changed", "{\"remote_address_id\": %d, \"old_address\": \"%s\", \"new_address\": \"%s\"}", ud->uniflow_id, (protoop_arg_t) old, (protoop_arg_t) new);
        my_memcpy(addr->sa, new_addr, new_addr_len);
        addr->is_v6 = new_addr->sa_family == AF_INET6;
        addr->is_v4_mapped_in_v6 = is_v4_mapped_in_v6(new_addr);

        for (int i = 0; i < bpfd->nb_sending_proposed; i++) {
            uniflow_data_t *tud = bpfd->sending_uniflows[i];
            if (tud && tud->rem_addr_id == ud->rem_addr_id) { // This uniflow is also affected by the translation
                my_memcpy((struct sockaddr_storage *) get_path(tud->path, AK_PATH_PEER_ADDR, 0), addr->sa, new_addr_len);
                set_path(tud->path, AK_PATH_PEER_ADDR_LEN, 0, new_addr_len);
            }
        }

        for (int i = 0; i < bpfd->nb_receiving_proposed; i++) {
            uniflow_data_t *tud = bpfd->receiving_uniflows[i];
            if (tud && tud->rem_addr_id == ud->rem_addr_id) { // This uniflow is also affected by the translation
                my_memcpy((struct sockaddr_storage *) get_path(tud->path, AK_PATH_PEER_ADDR, 0), addr->sa, new_addr_len);
                set_path(tud->path, AK_PATH_PEER_ADDR_LEN, 0, new_addr_len);
            }
        }
    }

    return 0;
}