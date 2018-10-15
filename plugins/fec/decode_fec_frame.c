#include "picoquic_internal.h"
#include "bpf.h"


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
protoop_arg_t decode_fec_frame(picoquic_cnx_t *cnx)
{
    PROTOOP_PRINTF(cnx, "DECODED FEC FRAME !\n");
    protoop_arg_t args[8];
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (uint8_t *) cnx->protoop_inputv[1];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[2];
    bytes++; // skip the frame type
    fec_frame_t frame;
    fec_frame_header_t frame_header;
    frame.header = &frame_header;
    parse_fec_frame_header(frame.header, bytes);
    PROTOOP_PRINTF(cnx, "FRAME DATA LENGTH = %u\n", frame.header->data_length);
    PROTOOP_PRINTF(cnx, "FRAME LENGTH = %u, FIN = %u, nss = %u, nrs = %u, block_number = %u, offset = %u\n",
            frame.header->data_length, frame.header->fin_bit, frame.header->nss, frame.header->nrs, frame.header->repair_fec_payload_id.fec_block_number, frame.header->repair_fec_payload_id.symbol_number);

    if (frame.header->data_length > (bytes_max - bytes))
        return 0;
    bytes += sizeof(fec_frame_header_t);
    frame.data = bytes;
    process_fec_frame_helper(cnx, &frame);
    bytes += frame.header->data_length;
    return (protoop_arg_t) bytes;
}