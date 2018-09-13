#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "tls_api.h"

/**
 * cnx->protoop_inputv[0] = uint8_t* bytes
 * cnx->protoop_inputv[1] = size_t bytes_max
 * size_t consumed = cnx->protoop_inputv[2]
 * uint64_t path_id = cnx->protoop_inputv[3]
 *
 * Output: int ret
 * cnx->protoop_outputv[0] = size_t consumed
 */
protoop_arg_t prepare_new_connection_id_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0]; 
    size_t bytes_max = (size_t) cnx->protoop_inputv[1];
    size_t consumed = (size_t) cnx->protoop_inputv[2];
    uint64_t path_id = (uint64_t) cnx->protoop_inputv[3];

    int ret = 0;
    bpf_data *bpfd = get_bpf_data(cnx);

    if (bytes_max < 27) {
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
        int path_index;
        for (path_index = 0; path_index < bpfd->num_paths; path_index++) {
            if (bpfd->paths[path_index].path_id == path_id) {
                break;
            }
        }
        if (path_index == bpfd->num_paths) {
            /* New path */
            bpfd->num_paths++;
            bpfd->paths[path_index].path_id = path_id;
        }

        path_data_t *p = &bpfd->paths[path_index];

        /* Create the connection ID and the related reset token */
        picoquic_create_random_cnx_id(cnx->quic, &p->local_cnxid, 8);
        picoquic_create_cnxid_reset_secret(cnx->quic, p->local_cnxid, (uint8_t *) &p->reset_secret[0]);
        picoquic_register_cnx_id(cnx->quic, cnx, p->local_cnxid);

        size_t byte_index = 0;
        size_t path_id_l = 0;
        size_t seq_l = 0;

        /* Encode the first byte */
        bytes[byte_index++] = picoquic_frame_type_new_connection_id;

        if (byte_index < bytes_max) {
            /* Path ID */
            path_id_l = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                path_id);
            byte_index += path_id_l;
        }
        if (byte_index < bytes_max) {
            /* Seq */
            path_id_l = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                0);
            byte_index += seq_l;
        }
        bytes[byte_index++] = 8;
        my_memcpy(bytes + byte_index, p->local_cnxid.id, p->local_cnxid.id_len);
        byte_index += p->local_cnxid.id_len;
        my_memcpy(bytes + byte_index, p->reset_secret, 16);
        byte_index += 16;

        consumed = byte_index;
    }

    cnx->protoop_outputc_callee = 1;
    cnx->protoop_outputv[0] = (protoop_arg_t) consumed;

    return (protoop_arg_t) ret;
}