#include "picoquic.h"
#include "../fec_protoops.h"


static inline void cpy(uint8_t *bytes, char *str, int len) {
    int i;
    for (i = 0 ; i < len ; i++) {
        str[i] = bytes[i];
    }
    str[len] = '\0';
}

/**
 * cnx->protoop_inputv[0] = uint8_t* bytes
 * cnx->protoop_inputv[1] = const uint8_t* bytes_max
 * cnx->protoop_inputv[2] = uint64_t current_time
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t parse_fec_frame(picoquic_cnx_t *cnx)
{
    PROTOOP_PRINTF(cnx, "Parse FEC FRAME\n");
    uint8_t *bytes_protected = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);//cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);//cnx->protoop_inputv[1];
    uint8_t *bytes_header = my_malloc(cnx, 1 + sizeof(fec_frame_header_t));
    if (!bytes_header){
        return PICOQUIC_ERROR_MEMORY;
    }
    my_memcpy(bytes_header, bytes_protected, 1 + sizeof(fec_frame_header_t));
    fec_frame_t *frame = my_malloc(cnx, sizeof(fec_frame_t));
    if (!frame)
        return PICOQUIC_ERROR_MEMORY;
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
    parse_fec_frame_header(&frame->header, bytes_header+1);
    PROTOOP_PRINTF(cnx, "FRAME LENGTH = %u, FIN = %u, nss = %u, nrs = %u, block_number = %u, offset = %u\n",
            frame->header.data_length, frame->header.fin_bit, frame->header.nss, frame->header.nrs,
            frame->header.repair_fec_payload_id.fec_block_number, frame->header.repair_fec_payload_id.symbol_number);
    my_free(cnx, bytes_header);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) true);
    set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) false);
    if (frame->header.data_length > (bytes_max - bytes_protected - (1 + sizeof(fec_frame_header_t)))){
        my_free(cnx, frame);
        return 0;
    }
    if (get_bpf_state(cnx)->is_in_skip_frame) {
        // return directly: we are in skip_frame, so the payload of the FEC Frame will never be handled
        return (protoop_arg_t) bytes_protected +  1 + sizeof(fec_frame_header_t) + frame->header.data_length;
    }
    uint8_t *bytes = my_malloc(cnx, (unsigned int) (bytes_max - bytes_protected - (1 + sizeof(fec_frame_header_t))));
    my_memcpy(bytes, bytes_protected + 1 + sizeof(fec_frame_header_t), (bytes_max - bytes_protected - (1 + sizeof(fec_frame_header_t))));
    frame->data = bytes;
    return (protoop_arg_t) bytes_protected +  1 + sizeof(fec_frame_header_t) + frame->header.data_length;
}