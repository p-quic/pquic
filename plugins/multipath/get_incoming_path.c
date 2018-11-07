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
    picoquic_path_t* path_0 = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);

    picoquic_connection_id_t *initial_cnxid = (picoquic_connection_id_t *) get_cnx(cnx, CNX_AK_INITIAL_CID, 0);
    picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_path(path_0, PATH_AK_LOCAL_CID, 0);
    picoquic_connection_id_t *destination_cnxid = (picoquic_connection_id_t *) get_ph(ph, PH_AK_DESTINATION_CNXID);

    if (picoquic_compare_connection_id(destination_cnxid, initial_cnxid) == 0 ||
        picoquic_compare_connection_id(destination_cnxid, local_cnxid) == 0) {
        path_from = path_0;
    } else {
        int nb_paths = (int) get_cnx(cnx, CNX_AK_NB_PATHS, 0);
        bpf_data *bpfd = get_bpf_data(cnx);
        for (int i = 1; i < nb_paths; i++) {
            picoquic_path_t *path_i = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, i);
            picoquic_connection_id_t *local_cnxid_x = (picoquic_connection_id_t *) get_path(path_i, PATH_AK_LOCAL_CID, 0);
            if (picoquic_compare_connection_id(destination_cnxid, local_cnxid_x) == 0) {
                path_from = path_i;
                path_data_t *pd = mp_get_path_data(bpfd, path_i);
                if (pd->state == 1) {
                    pd->state = 2;
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