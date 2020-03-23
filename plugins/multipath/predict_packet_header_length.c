#include "bpf.h"

/**
 * See PROTOOP_NOPARAM_PREDICT_PACKET_HEADER_LENGTH
 */
protoop_arg_t predict_packet_header_length(picoquic_cnx_t *cnx)
{
    picoquic_packet_type_enum packet_type = (picoquic_packet_type_enum) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_path_t* path_x = (picoquic_path_t*) get_cnx(cnx, AK_CNX_INPUT, 1);

    uint32_t header_length = 0;
    picoquic_path_t* path_0 = (picoquic_path_t*) get_cnx(cnx, AK_CNX_PATH, 0);
    picoquic_connection_id_t *remote_cnxid = (picoquic_connection_id_t *) get_path(path_0, AK_PATH_REMOTE_CID, 0);
    uint8_t remote_cnxid_len = (uint8_t) get_cnxid(remote_cnxid, AK_CNXID_LEN);

    if (packet_type == picoquic_packet_1rtt_protected_phi0 || 
        packet_type == picoquic_packet_1rtt_protected_phi1) {
        /* Compute length of a short packet header */
        if (path_0 == path_x) {
            header_length = 1 + remote_cnxid_len + 4;
        } else {
            bpf_data *bpfd = get_bpf_data(cnx);
            path_data_t *pd = mp_get_sending_path_data(bpfd, path_x);
            /* TODO cope with pd NULL */
            picoquic_connection_id_t *remote_cnxid_x = (picoquic_connection_id_t *) get_path(path_x, AK_PATH_REMOTE_CID, 0);
            header_length = 1 + remote_cnxid_len + 4;
        }
    }
    else {
        /* Compute length of a long packet header */
        header_length = 1 + /* version */ 4 + /* cnx_id prefix */ 2;

        /* add dest-id length */
        if ((packet_type == picoquic_packet_initial ||
            packet_type == picoquic_packet_0rtt_protected)
            && remote_cnxid_len == 0) { /* Unwrapped picoquic_is_connection_id_null */
            picoquic_connection_id_t *initial_cnxid = (picoquic_connection_id_t *) get_cnx(cnx, AK_CNX_INITIAL_CID, 0);
            header_length += (uint8_t) get_cnxid(initial_cnxid, AK_CNXID_LEN);
        }
        else {
            header_length += remote_cnxid_len;
        }

        /* add srce-id length */
        picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_path(path_x, AK_PATH_LOCAL_CID, 0);
        header_length += (uint8_t) get_cnxid(local_cnxid, AK_CNXID_LEN);

        /* add length of payload length and packet number */
        header_length += 2 + 4;

        /* add length of tokens for initial packets */
        if (packet_type == picoquic_packet_initial) {
            uint8_t useless[16];
            uint32_t retry_token_length = (uint32_t) get_cnx(cnx, AK_CNX_RETRY_TOKEN_LENGTH, 0);
            header_length += (uint32_t)picoquic_varint_encode(useless, 16, retry_token_length);
            header_length += (uint32_t)retry_token_length;
        }
    }

    return (protoop_arg_t) header_length;
}