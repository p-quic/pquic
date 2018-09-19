#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

/**
 * picoquic_packet_type_enum packet_type = input 0
 * picoquic_path_t* path_x = cnx->protoop_inputv[1]
 *
 * Output: header_length (uint32_t)
 */
protoop_arg_t predict_packet_header_length(picoquic_cnx_t *cnx)
{
    picoquic_packet_type_enum packet_type = (picoquic_packet_type_enum) cnx->protoop_inputv[0];
    picoquic_path_t* path_x = (picoquic_path_t*) cnx->protoop_inputv[1];

    uint32_t header_length = 0;

    if (packet_type == picoquic_packet_1rtt_protected_phi0 || 
        packet_type == picoquic_packet_1rtt_protected_phi1) {
        /* Compute length of a short packet header */
        if (cnx->path[0] == path_x) {
            header_length = 1 + cnx->remote_cnxid.id_len + 4;
        } else {
            bpf_data *bpfd = get_bpf_data(cnx);
            path_data_t *pd = mp_get_path_data(bpfd, path_x);
            /* TODO cope with pd NULL */
            header_length = 1 + pd->remote_cnxid.id_len + 4;
        }
    }
    else {
        /* Compute length of a long packet header */
        header_length = 1 + /* version */ 4 + /* cnx_id prefix */ 1;

        /* add dest-id length */
        if ((packet_type == picoquic_packet_initial ||
            packet_type == picoquic_packet_0rtt_protected)
            && cnx->remote_cnxid.id_len == 0) { /* Unwrapped picoquic_is_connection_id_null */
            header_length += cnx->initial_cnxid.id_len;
        }
        else {
            header_length += cnx->remote_cnxid.id_len;
        }

        /* add srce-id length */
        header_length += cnx->local_cnxid.id_len;

        /* add length of payload length and packet number */
        header_length += 2 + 4;

        /* add length of tokens for initial packets */
        if (packet_type == picoquic_packet_initial) {
            uint8_t useless[16];
            header_length += (uint32_t)picoquic_varint_encode(useless, 16, cnx->retry_token_length);
            header_length += (uint32_t)cnx->retry_token_length;
        }
    }

    return (protoop_arg_t) header_length;
}