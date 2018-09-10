#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"

/**
 * cnx->protoop_inputv[0] = uint8_t* bytes
 * cnx->protoop_inputv[1] = const uint8_t* bytes_max
 * cnx->protoop_inputv[2] = uint64_t current_time
 * cnx->protoop_inputv[3] = int epoch
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t decode_ack_frame(picoquic_cnx_t *cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (uint8_t *) cnx->protoop_inputv[1];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[2];
    int epoch = (int) cnx->protoop_inputv[3];

    uint64_t num_block;
    uint64_t largest;
    uint64_t ack_delay;
    size_t   consumed;
    picoquic_packet_context_enum pc = helper_context_from_epoch(epoch);
    uint8_t first_byte = bytes[0];

    if (helper_parse_ack_header(bytes, bytes_max-bytes, &num_block, 
        NULL,
        &largest, &ack_delay, &consumed,
        cnx->remote_parameters.ack_delay_exponent) != 0) {
        bytes = NULL;
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
    } else if (largest >= cnx->pkt_ctx[pc].send_sequence) {
        bytes = NULL;
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
    } else {
        bytes += consumed;

        /* Attempt to update the RTT */
        picoquic_packet_t* top_packet = helper_update_rtt(cnx, largest, current_time, ack_delay, pc);

        while (bytes != NULL) {
            uint64_t range;
            uint64_t block_to_block;

            if ((bytes = helper_frames_varint_decode(bytes, bytes_max, &range)) == NULL) {
                // DBG_PRINTF("Malformed ACK RANGE, %d blocks remain.\n", (int)num_block);
                helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            }

            range ++;
            if (largest + 1 < range) {
                // DBG_PRINTF("ack range error: largest=%" PRIx64 ", range=%" PRIx64, largest, range);
                helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            }

            if (helper_process_ack_range(cnx, pc, largest, range, &top_packet, current_time) != 0) {
                bytes = NULL;
                break;
            }

            if (range > 0) {
                helper_check_spurious_retransmission(cnx, largest + 1 - range, largest, current_time, pc);
            }

            if (num_block-- == 0)
                break;

            /* Skip the gap */
            if ((bytes = helper_frames_varint_decode(bytes, bytes_max, &block_to_block)) == NULL) {
                // DBG_PRINTF("    Malformed ACK GAP, %d blocks remain.\n", (int)num_block);
                helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            }

            block_to_block += 1; /* add 1, since zero is ruled out by varint, see spec. */
            block_to_block += range;

            if (largest < block_to_block) {
                // DBG_PRINTF("ack gap error: largest=%" PRIx64 ", range=%" PRIx64 ", gap=%" PRIu64,
                //     largest, range, block_to_block - range);
                helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            }

            largest -= block_to_block;
        }
    }

    return (protoop_arg_t) bytes;
}