#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

/**
 * picoquic_packet_header* ph = cnx->protoop_inputv[0]
 *
 * Output: picoquic_path_t* path
 */
protoop_arg_t get_incoming_path(picoquic_cnx_t* cnx)
{
    picoquic_packet_header* ph = (picoquic_packet_header*) cnx->protoop_inputv[0];
    picoquic_path_t* path_from = NULL;

    if (picoquic_compare_connection_id(&ph->dest_cnx_id, &cnx->local_cnxid) == 0) {
        path_from = cnx->path[0];
    } else {
        bpf_data *bpfd = get_bpf_data(cnx);
        for (int i = 0; i < bpfd->nb_proposed; i++) {
            if (picoquic_compare_connection_id(&ph->dest_cnx_id, &bpfd->paths[i].local_cnxid) == 0) {
                path_from = bpfd->paths[i].path;
                break;
            }
        }

    }

    return (protoop_arg_t) path_from;
}