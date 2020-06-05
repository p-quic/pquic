#include "bpf.h"

#define UNUSABLE_RTT_COEF 8
#define COOLDOWN_RTT_COEF 8

protoop_arg_t path_manager(picoquic_cnx_t* cnx) {
    /* Now, even the server MUST itself setup its sending paths */
    bpf_data *bpfd = get_bpf_data(cnx);
    uniflow_data_t *ud = NULL;

    /* Don't go further if the address exchange is not complete! */
    if (!bpfd->nb_sending_proposed || !bpfd->nb_receiving_proposed || !(get_cnx(cnx, AK_CNX_HANDSHAKE_DONE, 0) && (get_cnx(cnx, AK_CNX_CLIENT_MODE, 0) || get_cnx(cnx, AK_CNX_HANDSHAKE_DONE_ACKED, 0)))) {
        PROTOOP_PRINTF(cnx, "Address exchange is not complete\n");
        return 0;
    }

    /* FIXME this is not really an issue per-se, but we need to prioritize then on which addresses we will create paths */
    if (bpfd->nb_loc_addrs * bpfd->nb_rem_addrs > MAX_SENDING_UNIFLOWS) {
        PROTOOP_PRINTF(cnx, "%d max paths is not enough for a full mesh between %d loc and %d rem addrs\n", MAX_SENDING_UNIFLOWS, bpfd->nb_loc_addrs, bpfd->nb_rem_addrs);
        // Do not return, it will never use uniflows otherwise...
    }

    if (bpfd->nb_sending_active >= N_SENDING_UNIFLOWS || bpfd->nb_sending_active >= bpfd->nb_rem_addrs) {
        return 0;
    }

    for (int loc = 0; loc < bpfd->nb_loc_addrs; loc++) {
        addr_data_t *adl = &bpfd->loc_addrs[loc];
        for (int rem = 0; adl->sa && rem < bpfd->nb_rem_addrs; rem++) {
            addr_data_t *adr = &bpfd->rem_addrs[rem];

            for (int uniflow_idx = 0; adr->sa && uniflow_idx < bpfd->nb_sending_proposed; uniflow_idx++) {
                ud = bpfd->sending_uniflows[uniflow_idx];
                if (ud->state == uniflow_unused && bpfd->nb_sending_active < N_SENDING_UNIFLOWS) {
                    ud->state = uniflow_active;
                    ud->loc_addr_id = (uint8_t) (loc + 1);
                    ud->rem_addr_id = (uint8_t) (rem + 1);
                    set_path(ud->path, AK_PATH_LOCAL_ADDR_LEN, 0, (adl->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
                    my_memcpy((struct sockaddr_storage *) get_path(ud->path, AK_PATH_LOCAL_ADDR, 0), adl->sa, (adl->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
                    set_path(ud->path, AK_PATH_IF_INDEX_LOCAL, 0, (unsigned long) adl->if_index);
                    set_path(ud->path, AK_PATH_PEER_ADDR_LEN, 0, (adr->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
                    my_memcpy((struct sockaddr_storage *) get_path(ud->path, AK_PATH_PEER_ADDR, 0), adr->sa, (adr->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
                    bpfd->nb_sending_active++;

                    LOG {
                        char from[48], to[48];
                        LOG_EVENT(cnx, "multipath", "uniflow_activated", "",
                                  "{\"uniflow_id\": %" PRIu64 ", \"path\": \"%p\", \"loc_addr\": \"%s\", \"rem_addr\": \"%s\"}",
                                  ud->uniflow_id, (protoop_arg_t) ud->path,
                                  (protoop_arg_t) inet_ntop(adl->sa->sa_family, (adl->sa->sa_family == AF_INET)
                                                                                ? (void *) &(((struct sockaddr_in *) adl->sa)->sin_addr)
                                                                                : (void *) &(((struct sockaddr_in6 *) adl->sa)->sin6_addr),
                                                            from, sizeof(from)),
                                  (protoop_arg_t) inet_ntop(adr->sa->sa_family, (adr->sa->sa_family == AF_INET)
                                                                                ? (void *) &(((struct sockaddr_in *) adr->sa)->sin_addr)
                                                                                : (void *) &(((struct sockaddr_in6 *) adr->sa)->sin6_addr),
                                                            to, sizeof(to))
                        );
                    }
                    break;
                } else if ((ud->state == uniflow_active) &&
                           (picoquic_compare_addr((struct sockaddr *) get_path(ud->path, AK_PATH_PEER_ADDR, 0), bpfd->rem_addrs[rem].sa) == 0 &&
                            picoquic_compare_addr((struct sockaddr *) get_path(ud->path, AK_PATH_LOCAL_ADDR, 0), bpfd->loc_addrs[loc].sa) == 0)) {
                    break;
                }
            }
        }
    }

    return 0;
}