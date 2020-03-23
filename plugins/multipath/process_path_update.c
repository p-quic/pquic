#include "bpf.h"

protoop_arg_t process_path_update(picoquic_cnx_t *cnx)
{
    path_update_t *frame = (path_update_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    uint64_t current_time = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 1);
    bpf_data *bpfd = get_bpf_data(cnx);

    for (int i = 0; i < bpfd->nb_receive_proposed; i++) {
        path_data_t *pd = bpfd->receive_paths[i];
        if (pd->path_id == frame->closed_path_id) {
            pd->state = path_closed;

            LOG {
                char from[48], to[48];
                struct sockaddr *laddr = bpfd->loc_addrs[pd->loc_addr_id - 1].sa;
                struct sockaddr *raddr = bpfd->rem_addrs[pd->rem_addr_id - 1].sa;
                LOG_EVENT(cnx, "multipath", "path_closed", "path_update",
                            "{\"path_id\": %" PRIu64 ", \"path\": \"%p\", \"loc_addr\": \"%s\", \"rem_addr\": \"%s\"}",
                            pd->path_id, (protoop_arg_t) pd->path,
                            (protoop_arg_t) inet_ntop(laddr->sa_family, (laddr->sa_family == AF_INET)
                                                                        ? (void *) &(((struct sockaddr_in *) laddr)->sin_addr)
                                                                        : (void *) &(((struct sockaddr_in6 *) laddr)->sin6_addr),
                                                    from, sizeof(from)),
                            (protoop_arg_t) inet_ntop(raddr->sa_family, (raddr->sa_family == AF_INET)
                                                                        ? (void *) &(((struct sockaddr_in *) raddr)->sin_addr)
                                                                        : (void *) &(((struct sockaddr_in6 *) raddr)->sin6_addr),
                                                    to, sizeof(to))
                );
                break;
            }
        }
    }

    if (frame->proposed_path_id < bpfd->nb_receive_proposed) {
        // TODO
    }

    return 0;
}