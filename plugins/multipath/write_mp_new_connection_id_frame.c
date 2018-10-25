#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "tls_api.h"

/**
 * See PROTOOP_PARAM_WRITE_FRAME
 */
protoop_arg_t write_mp_new_connection_id_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0]; 
    const uint8_t *bytes_max = (const uint8_t *) cnx->protoop_inputv[1];
    mp_new_connection_id_ctx_t *mncic = (mp_new_connection_id_ctx_t *) cnx->protoop_inputv[2];
    size_t consumed = (size_t) cnx->protoop_inputv[3];

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
        int path_index = mp_get_path_index(bpfd, mncic->path_id, &new_path_index);
        if (path_index < 0) {
            /* Stop sending NEW_CONNECTION_ID frames */
            cnx->protoop_outputc_callee = 1;
            cnx->protoop_outputv[0] = 0;
            return 0;
        }

        path_data_t *p = &bpfd->paths[path_index];

        if (p->state > 0) {
            /* Don't complicate stuff now... */
            cnx->protoop_outputc_callee = 1;
            cnx->protoop_outputv[0] = 0;
            return 0;
        }

        /* Create the connection ID and the related reset token */
        picoquic_create_random_cnx_id(cnx->quic, &p->local_cnxid, 8);
        picoquic_create_cnxid_reset_secret(cnx->quic, &p->local_cnxid, (uint8_t *) &p->reset_secret[0]);
        picoquic_register_cnx_id(cnx->quic, cnx, &p->local_cnxid);

        size_t byte_index = 0;
        size_t path_id_l = 0;
        size_t seq_l = 0;

        /* Encode the first byte */
        bytes[byte_index++] = MP_NEW_CONNECTION_ID_TYPE;

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
        bytes[byte_index++] = 8;
        my_memcpy(bytes + byte_index, p->local_cnxid.id, p->local_cnxid.id_len);
        byte_index += p->local_cnxid.id_len;
        my_memcpy(bytes + byte_index, p->reset_secret, 16);
        byte_index += 16;

        consumed = byte_index;

        bpfd->nb_proposed_snt++;
        /* If we previously received a connection ID for the path ID, it is now ready */
        if (new_path_index) {
            p->state = 0;
        } else {
            mp_path_ready(cnx, p, picoquic_current_time());
        }
    }

    my_free(cnx, mncic);
    
    cnx->protoop_outputc_callee = 1;
    cnx->protoop_outputv[0] = (protoop_arg_t) consumed;

    return (protoop_arg_t) ret;
}