#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

/**
 * See PROTOOP_NOPARAM_GET_DESTINATION_CONNECTION_ID
 */
protoop_arg_t get_destination_cnx_id(picoquic_cnx_t* cnx)
{
    /* Don't use all the argument here */
    picoquic_packet_type_enum packet_type = (picoquic_packet_type_enum) get_cnx(cnx, CNX_AK_INPUT, 0);
    picoquic_path_t *path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_INPUT, 1);

    picoquic_connection_id_t *dest_cnx_id = NULL;

    picoquic_path_t *path_0 = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);

    picoquic_connection_id_t *initial_cnxid = (picoquic_connection_id_t *) get_cnx(cnx, CNX_AK_INITIAL_CID, 0);
    picoquic_connection_id_t *remote_cnxid_0 = (picoquic_connection_id_t *) get_path(path_0, PATH_AK_REMOTE_CID, 0);

    if ((packet_type == picoquic_packet_initial ||
         packet_type == picoquic_packet_0rtt_protected)
        && remote_cnxid_0->id_len == 0) /* Unwrapped picoquic_is_connection_id_null */
    {
        dest_cnx_id = initial_cnxid;
    }
    else if (path_x == path_0)
    {
        dest_cnx_id = remote_cnxid_0;
    }
    else
    {
        dest_cnx_id = (picoquic_connection_id_t *) get_path(path_x, PATH_AK_REMOTE_CID, 0);
    }

    return (protoop_arg_t) dest_cnx_id;
}