#include "bpf.h"

/**
 * See PROTOOP_NOPARAM_GET_INCOMING_PATH
 */
protoop_arg_t get_incoming_path(picoquic_cnx_t* cnx)
{
    picoquic_packet_header* ph = (picoquic_packet_header*) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_path_t* path_0 = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
    picoquic_path_t* path_from = path_0;

    picoquic_connection_id_t *initial_cnxid = (picoquic_connection_id_t *) get_cnx(cnx, AK_CNX_INITIAL_CID, 0);
    picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_path(path_0, AK_PATH_LOCAL_CID, 0);
    picoquic_connection_id_t *destination_cnxid = (picoquic_connection_id_t *) get_ph(ph, AK_PH_DESTINATION_CNXID);

    bpf_data *bpfd = get_bpf_data(cnx);
    for (int i = 0; i < bpfd->nb_receiving_proposed; i++) {
        uniflow_data_t *ud = bpfd->receiving_uniflows[i];
        if (ud && ud->state == uniflow_active && picoquic_compare_connection_id(destination_cnxid, &ud->cnxid) == 0) {
            path_from = ud->path;
            break;
        }
    }

    if (path_from == NULL) {
        /* Avoid crashing fuzzing tests, just return path 0*/
        path_from = path_0;
    }

    return (protoop_arg_t) path_from;
}