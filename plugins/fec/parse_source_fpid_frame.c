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
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    const uint8_t* bytes_max = (uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 1);
    uint64_t current_time = (uint64_t) get_cnx(cnx, CNX_AK_INPUT, 2);
    bytes++;    // skip the type byte
    if (bytes_max-bytes < sizeof(source_fpid_frame_t)){
        return 0;
    }
    source_fpid_frame_t *frame = my_malloc(cnx, sizeof(source_fpid_frame_t));
    if (!frame)
        return PICOQUIC_ERROR_MEMORY;
    parse_sfpid_frame(frame, bytes);
    bytes += sizeof(source_fpid_frame_t);
    PROTOOP_PRINTF(cnx, "Parse FEC-proteceted packet with FPID = %u (block = %u)\n", frame->source_fpid.raw, frame->source_fpid.fec_block_number);
    set_cnx(cnx, CNX_AK_OUTPUT, 0, (protoop_arg_t) frame);
    set_cnx(cnx, CNX_AK_OUTPUT, 1, false);
    set_cnx(cnx, CNX_AK_OUTPUT, 2, false);

    return (protoop_arg_t) bytes;
}