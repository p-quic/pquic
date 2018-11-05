#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

/**
 * See PROTOOP_NOPARAM_GET_INCOMING_PATH
 */
protoop_arg_t get_incoming_path(picoquic_cnx_t* cnx)
{
    picoquic_packet_header* ph = (picoquic_packet_header*) get_cnx(cnx, CNX_AK_INPUT, 0);
    picoquic_path_t* path_from = NULL;

    picoquic_connection_id_t *initial_cnxid = (picoquic_connection_id_t *) get_cnx(cnx, CNX_AK_INITIAL_CID, 0);
    picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_cnx(cnx, CNX_AK_LOCAL_CID, 0);

    if (picoquic_compare_connection_id(&ph->dest_cnx_id, initial_cnxid) == 0 ||
        picoquic_compare_connection_id(&ph->dest_cnx_id, local_cnxid) == 0) {
        path_from = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);
    } else {
        bpf_data *bpfd = get_bpf_data(cnx);
        for (int i = 0; i < bpfd->nb_proposed; i++) {
            if (picoquic_compare_connection_id(&ph->dest_cnx_id, &bpfd->paths[i].local_cnxid) == 0) {
                path_from = bpfd->paths[i].path;
                /* We received a packet on it, the path can be now used */
                /* TODO: cope with client/server situation with path ID eveness */
                if (bpfd->paths[i].state == 1) {
                    bpfd->paths[i].state = 2;
                }
                break;
            }
        }

    }

    if (path_from == NULL) {
        /* Avoid crashing fuzzing tests, just return path 0*/
        path_from = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);
    }

    return (protoop_arg_t) path_from;
}