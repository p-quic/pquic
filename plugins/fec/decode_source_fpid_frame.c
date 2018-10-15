#include "picoquic_internal.h"
#include "bpf.h"

/**
 * cnx->protoop_inputv[0] = uint8_t* bytes
 * cnx->protoop_inputv[1] = const uint8_t* bytes_max
 * cnx->protoop_inputv[2] = uint64_t current_time
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t decode_source_fpid_frame(picoquic_cnx_t *cnx)
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
    // ubpf is big endian so it is ok
    source_fpid_frame_t *frame = (source_fpid_frame_t*) bytes;
    bpf_state *state = get_bpf_state(cnx);
    uint8_t *payload = state->current_packet;
    source_symbol_t *ss = malloc_source_symbol_with_data(cnx, frame->source_fpid, payload, state->current_packet_length);
    if (!received_source_symbol_helper(cnx, state, ss)) {
        free_source_symbol(cnx, ss);
    }
    bytes += sizeof(source_fpid_frame_t);
    args[0] = frame->source_fpid.raw;
    helper_protoop_printf(cnx, "Parse FEC-proteceted packet with FPID = %u\n", args, 1);
    // TODO: split processing from decoding
    // TODO: processing
    return (protoop_arg_t) bytes;
}