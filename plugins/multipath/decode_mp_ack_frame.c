#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

/**
 * The interface for the decode_frame protocol operation is the same for all:
 * uint8_t* bytes = cnx->protoop_inputv[0]
 * const uint8_t* bytes_max = cnx->protoop_inputv[1]
 * uint64_t current_time = cnx->protoop_inputv[2]
 * int epoch = cnx->protoop_inputv[3]
 * int ack_needed = cnx->protoop_inputv[4]
 *
 * Output: uint8_t* bytes
 * cnx->protoop_outputv[0] = ack_needed
 */
protoop_arg_t decode_mp_ack_frame(picoquic_cnx_t *cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (uint8_t *) cnx->protoop_inputv[1];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[2];
    int ack_needed = (int) cnx->protoop_inputv[4];

    uint64_t num_block;
    uint64_t largest;
    uint64_t ack_delay;
    uint64_t path_id;
    size_t   consumed;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    uint8_t first_byte = bytes[0];
    
    bpf_data *bpfd = get_bpf_data(cnx);

    if (parse_mp_ack_header(bytes, bytes_max-bytes, &num_block, 
        NULL, &path_id,
        &largest, &ack_delay, &consumed,
        cnx->remote_parameters.ack_delay_exponent) != 0) {
        bytes = NULL;
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
    } else {
        int path_index = mp_get_path_index(bpfd, path_id, NULL);
        if (path_index < 0) {
            bytes = NULL;
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
        } else if (largest >= bpfd->paths[path_index].path->pkt_ctx[pc].send_sequence) {
            bytes = NULL;
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
        } else {
            picoquic_path_t *path_x = bpfd->paths[path_index].path;

            bytes += consumed;

            /* Attempt to update the RTT */
            picoquic_packet_t* top_packet = helper_update_rtt(cnx, largest, current_time, ack_delay, pc, path_x);

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

                if (helper_process_mp_ack_range(cnx, pc, largest, range, &top_packet, current_time) != 0) {
                    bytes = NULL;
                    break;
                }

                if (range > 0) {
                    helper_check_spurious_retransmission(cnx, largest + 1 - range, largest, current_time, pc, path_x);
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
    }

    cnx->protoop_outputc_callee = 1;
    cnx->protoop_outputv[0] = ack_needed;
    return (protoop_arg_t) bytes;
}