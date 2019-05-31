#include "bpf.h"

/**
 * See PROTOOP_NOPARAM_GET_INCOMING_PATH
 */
protoop_arg_t get_incoming_path(picoquic_cnx_t* cnx)
{
    picoquic_packet_header* ph = (picoquic_packet_header*) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_path_t* path_from = NULL;
    picoquic_path_t* path_0 = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);

    picoquic_connection_id_t *initial_cnxid = (picoquic_connection_id_t *) get_cnx(cnx, AK_CNX_INITIAL_CID, 0);
    picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_path(path_0, AK_PATH_LOCAL_CID, 0);
    picoquic_connection_id_t *destination_cnxid = (picoquic_connection_id_t *) get_ph(ph, AK_PH_DESTINATION_CNXID);

    if (picoquic_compare_connection_id(destination_cnxid, initial_cnxid) == 0 ||
        picoquic_compare_connection_id(destination_cnxid, local_cnxid) == 0) {
        path_from = path_0;
    } else {
        int nb_paths = (int) get_cnx(cnx, AK_CNX_NB_PATHS, 0);
        bpf_data *bpfd = get_bpf_data(cnx);
        for (int i = 1; i < nb_paths; i++) {
            picoquic_path_t *path_i = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, i);
            picoquic_connection_id_t *local_cnxid_x = (picoquic_connection_id_t *) get_path(path_i, AK_PATH_LOCAL_CID, 0);
            if (picoquic_compare_connection_id(destination_cnxid, local_cnxid_x) == 0) {
                path_from = path_i;
                path_data_t *pd = mp_get_path_data(bpfd, path_i);
                if (pd && pd->state == path_ready) {
                    pd->state = path_active;
                    struct sockaddr_storage *peer_addr = (struct sockaddr_storage *) get_path(path_from, AK_PATH_PEER_ADDR, 0);
                    struct sockaddr_storage *loc_addr = (struct sockaddr_storage *) get_path(path_from, AK_PATH_LOCAL_ADDR, 0);

                    struct sockaddr_storage *paddr = (struct sockaddr_storage *) my_malloc(cnx, get_path(path_from, AK_PATH_PEER_ADDR_LEN, 0));
                    struct sockaddr_storage *laddr = (struct sockaddr_storage *) my_malloc(cnx, get_path(path_from, AK_PATH_LOCAL_ADDR_LEN, 0));
                    my_memcpy(paddr, peer_addr, get_path(path_from, AK_PATH_PEER_ADDR_LEN, 0));
                    my_memcpy(laddr, loc_addr, get_path(path_from, AK_PATH_LOCAL_ADDR_LEN, 0));

                    LOG {
                        char from[48], to[48];
                        LOG_EVENT(cnx, "MULTIPATH", "PATH_ACTIVATED", "",
                                  "{\"path_id\": %lu, \"path\": \"%p\", \"loc_addr\": \"%s\", \"rem_addr\": \"%s\"}",
                                  pd->path_id, (protoop_arg_t) pd->path,
                                  (protoop_arg_t) inet_ntop(laddr->ss_family, (laddr->ss_family == AF_INET)
                                                                                ? (void *) &(((struct sockaddr_in *) &laddr)->sin_addr)
                                                                                : (void *) &(((struct sockaddr_in6 *) &laddr)->sin6_addr),
                                                            from, sizeof(from)),
                                  (protoop_arg_t) inet_ntop(paddr->ss_family, (paddr->ss_family == AF_INET)
                                                                                ? (void *) &(((struct sockaddr_in *) &paddr)->sin_addr)
                                                                                : (void *) &(((struct sockaddr_in6 *) &paddr)->sin6_addr),
                                                            to, sizeof(to))
                        );
                    }

                    my_free(cnx, paddr);
                    my_free(cnx, laddr);
                }
                
                break;
            }
        }
    }

    if (path_from == NULL) {
        /* Avoid crashing fuzzing tests, just return path 0*/
        path_from = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
    }

    return (protoop_arg_t) path_from;
}