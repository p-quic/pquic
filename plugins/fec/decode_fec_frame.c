#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

/**
 * cnx->protoop_inputv[0] = uint8_t* bytes
 * cnx->protoop_inputv[1] = const uint8_t* bytes_max
 * cnx->protoop_inputv[2] = uint64_t current_time
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t decode_fec_frame(picoquic_cnx_t *cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (uint8_t *) cnx->protoop_inputv[1];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[2];

    // ubpf is big endian so it is ok
    fec_frame_t *frame = (fec_frame_t *) bytes;
    if (frame->header->data_length > *bytes_max)
        return 0;
    process_fec_frame_helper(cnx, frame);
    bytes += sizeof(fec_frame_header_t) + frame->header->data_length;
    return (protoop_arg_t) bytes;
}