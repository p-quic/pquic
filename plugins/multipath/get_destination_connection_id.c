#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

/**
 * picoquic_packet_type_enum packet_type = cnx->protoop_inputv[0]
 * picoquic_path_t* path_x = cnx->protoop_inputv[1]
 *
 * Output: picoquic_connection_id_t* dest_cnx_id
 */
protoop_arg_t get_destination_cnx_id(picoquic_cnx_t* cnx)
{
    /* Don't use all the argument here */
    picoquic_packet_type_enum packet_type = (picoquic_packet_type_enum) cnx->protoop_inputv[0];
    picoquic_path_t *path_x = (picoquic_path_t *) cnx->protoop_inputv[1];

    picoquic_connection_id_t *dest_cnx_id = NULL;

    if ((packet_type == picoquic_packet_initial ||
         packet_type == picoquic_packet_0rtt_protected)
        && cnx->remote_cnxid.id_len == 0) /* Unwrapped picoquic_is_connection_id_null */
    {
        dest_cnx_id = &cnx->initial_cnxid;
    }
    else if (path_x == cnx->path[0])
    {
        dest_cnx_id = &cnx->remote_cnxid;
    }
    else
    {
        bpf_data *bpfd = get_bpf_data(cnx);
        path_data_t *pd = mp_get_path_data(bpfd, path_x);
        /* TODO: ensure pd is not null... */
        dest_cnx_id = &pd->remote_cnxid;
    }

    return (protoop_arg_t) dest_cnx_id;
}