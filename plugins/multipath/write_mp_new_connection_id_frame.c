#include "bpf.h"
#include "tls_api.h"

/**
 * See PROTOOP_PARAM_WRITE_FRAME
 */
protoop_arg_t write_mp_new_connection_id_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t *bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    mp_new_connection_id_ctx_t *mncic = (mp_new_connection_id_ctx_t *) get_cnx(cnx, AK_CNX_INPUT, 2);

    size_t consumed = 0;

    int ret = 0;
    int new_path_index = 0;
    bpf_data *bpfd = get_bpf_data(cnx);

    if (bytes_max - bytes < 28) {
        /* A valid frame, with our encoding, uses at least 13 bytes.
         * If there is not enough space, don't attempt to encode it.
         */
        consumed = 0;
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }
    else {
        /* First find the corresponding path_id in the bpfd
         * Create it if it is not present yet.
         */
        int path_index = mp_get_path_index(cnx, bpfd, false, mncic->path_id, &new_path_index);
        if (path_index < 0) {
            /* Stop sending NEW_CONNECTION_ID frames */
            set_cnx(cnx, AK_CNX_OUTPUT, 0, 0);
            return 0;
        }

        path_data_t *p = bpfd->receive_paths[path_index];

        if (p->state >= path_closed) {
            /* Don't complicate stuff now... */
            set_cnx(cnx, AK_CNX_OUTPUT, 0, 0);
            return 0;
        }

        /* Create the connection ID and the related reset token */
        if (!p->proposed_cid) {
            picoquic_create_random_cnx_id_for_cnx(cnx, &p->cnxid, 8);
            picoquic_create_cnxid_reset_secret_for_cnx(cnx, &p->cnxid, (uint8_t *) &p->reset_secret[0]);
            picoquic_register_cnx_id_for_cnx(cnx, &p->cnxid);
            p->proposed_cid = true;
        }

        size_t byte_index = 0;
        size_t path_id_l = 0;
        size_t seq_l = 0;

        /* Encode the first byte */
        my_memset(&bytes[byte_index++], MP_NEW_CONNECTION_ID_TYPE, 1);

        if (byte_index < bytes_max - bytes) {
            /* Path ID */
            path_id_l = picoquic_varint_encode(bytes + byte_index, (size_t) bytes_max - byte_index,
                mncic->path_id);
            byte_index += path_id_l;
        }
        if (byte_index < bytes_max - bytes) {
            /* Seq */
            seq_l = picoquic_varint_encode(bytes + byte_index, (size_t) bytes_max - byte_index,
                0);
            byte_index += seq_l;
        }
        my_memset(&bytes[byte_index++], 8, 1);
        my_memcpy(bytes + byte_index, p->cnxid.id, p->cnxid.id_len);
        byte_index += p->cnxid.id_len;
        my_memcpy(bytes + byte_index, p->reset_secret, 16);
        byte_index += 16;

        consumed = byte_index;

        /* Now that we sent the MP NEW CONNECTION ID frame, we should be active to receive packets */
        mp_receive_path_active(cnx, p, picoquic_current_time());
    }

    /* Do not freem mncic yet, do it in notify! */
    /* my_free(cnx, mncic); */
    
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) consumed);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 1);

    return (protoop_arg_t) ret;
}