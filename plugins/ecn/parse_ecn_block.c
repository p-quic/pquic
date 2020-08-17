#include "bpf.h"

/**
 * cnx->protoop_inputv[0] = uint8_t* bytes
 * cnx->protoop_inputv[1] = size_t bytes_max
 *
 * Output: None
 */
protoop_arg_t parse_ecn_block(picoquic_cnx_t *cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t *bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);

    ecn_block_t *block = my_malloc(cnx, sizeof(ecn_block_t));
    if (block == NULL) {
        bytes = NULL;
        goto exit;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &block->ect0)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &block->ect1)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &block->ectce)) == NULL) {
        goto exit;
    }

    if (get_bpf_data(cnx)->in_skip_frame) {
        my_free(cnx, block);
        block = NULL;
    }

exit:
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) block);
    return (protoop_arg_t) bytes;
}