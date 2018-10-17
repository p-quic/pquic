#include "picoquic_internal.h"
#include "bpf.h"

/**
 * cnx->protoop_inputv[0] = uint8_t* bytes
 * cnx->protoop_inputv[1] = const uint8_t* bytes_max
 * cnx->protoop_inputv[2] = uint64_t current_time
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t parse_source_fpid_frame(picoquic_cnx_t *cnx)
{
    protoop_arg_t args[2];
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (uint8_t *) cnx->protoop_inputv[1];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[2];
    bytes++;    // skip the type byte
    args[0] = bytes_max-bytes;
    args[1] = sizeof(source_fpid_frame_t);
    if (bytes_max-bytes < sizeof(source_fpid_frame_t)){
        return 0;
    }
    source_fpid_frame_t *frame = my_malloc(cnx, sizeof(source_fpid_frame_t));
    if (!frame)
        return PICOQUIC_ERROR_MEMORY;
    parse_sfpid_frame(frame, bytes);
    bytes += sizeof(source_fpid_frame_t);
    args[0] = frame->source_fpid.raw;
    PROTOOP_PRINTF(cnx, "Parse FEC-proteceted packet with FPID = %u (block = %u)\n", frame->source_fpid.raw, frame->source_fpid.fec_block_number);
    cnx->protoop_outputc_callee = 3;
    cnx->protoop_outputv[0] = (protoop_arg_t) frame;
    cnx->protoop_outputv[1] = (protoop_arg_t) false;
    cnx->protoop_outputv[2] = (protoop_arg_t) false;

    return (protoop_arg_t) bytes;
}