#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

protoop_arg_t select_sending_path(picoquic_cnx_t *cnx)
{
    picoquic_path_t *path_x = cnx->path[0]; /* We should NEVER return NULL */
    picoquic_path_t *path_c = NULL;
    bpf_data *bpfd = get_bpf_data(cnx);
    path_data_t *pd = NULL;
    uint8_t selected_path_index = 255;
    bool has_multiple_paths = false;
    for (int i = 0; i < bpfd->nb_proposed; i++) {
        pd = &bpfd->paths[i];
        /* If we are the client, activate the path */
        /* FIXME hardcoded */
        if (cnx->client_mode && pd->state == 1 && pd->path_id % 2 == 0) {
            pd->state = 2;
            addr_data_t *adl = NULL;
            addr_data_t *adr = NULL;
            if (pd->path_id == 2) {
                pd->loc_addr_id = 1;
                adl = &bpfd->loc_addrs[0];
                pd->path->local_addr_len = (adl->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                my_memcpy(&pd->path->local_addr, adl->sa, pd->path->local_addr_len);
                pd->path->if_index_local = (unsigned long) adl->if_index;
                pd->rem_addr_id = 1;
                adr = &bpfd->rem_addrs[0];
                pd->path->peer_addr_len = (adr->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                my_memcpy(&pd->path->peer_addr, adr->sa, pd->path->peer_addr_len);
            } else {
                // Path id is 4
                pd->loc_addr_id = 2;
                adl = &bpfd->loc_addrs[1];
                pd->path->local_addr_len = (adl->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                my_memcpy(&pd->path->local_addr, adl->sa, pd->path->local_addr_len);
                pd->path->if_index_local = (unsigned long) adl->if_index;
                pd->rem_addr_id = 1;
                adr = &bpfd->rem_addrs[0];
                pd->path->peer_addr_len = (adr->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                my_memcpy(&pd->path->peer_addr, adr->sa, pd->path->peer_addr_len);
            }
        }

        /* Lowest RTT-based scheduler */
        if (pd->state == 2) {
            path_c = pd->path;

            if (!path_c->challenge_verified && path_c->challenge_time == 0) {
                /* Start the challenge! */
                return (protoop_arg_t) path_c;
            }

            /* Don't consider invalid paths */
            if (!path_c->challenge_verified) {
                continue;
            }

            if (path_c != cnx->path[0]) {
                has_multiple_paths = true;
                /* Set the default path to be this one */
                if (path_x == cnx->path[0]) {
                    path_x = path_c;
                    continue;
                }
            }
            if (path_c->cwin <= path_c->bytes_in_transit) {
                continue;
            }
            if (path_x && path_c->challenge_verified && path_x->smoothed_rtt < path_c->smoothed_rtt) {
                continue;
            }
            path_x = path_c;
        }
    }

    bpfd->last_path_index_sent = selected_path_index;

    return (protoop_arg_t) path_x;
}