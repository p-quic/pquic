#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"

/**
 * cnx->protoop_inputv[0] = uint64_t current_time
 * cnx->protoop_inputv[1] = picoquic_packet_context_enum pc
 * cnx->protoop_inputv[2] = uint8_t* bytes
 * cnx->protoop_inputv[3] = size_t bytes_max
 * cnx->protoop_inputv[4] = size_t consumed
 *
 * Regular output: error code (int)
 * cnx->protoop_outputv[0] = size_t consumed
 */
protoop_arg_t prepare_ack_frame(picoquic_cnx_t *cnx)
{
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[0];
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) cnx->protoop_inputv[1];
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[2];
    size_t bytes_max = (size_t) cnx->protoop_inputv[3];
    size_t consumed = (size_t) cnx->protoop_inputv[4];

    int ret = 0;
    size_t byte_index = 0;
    uint64_t num_block = 0;
    size_t l_largest = 0;
    size_t l_delay = 0;
    size_t l_first_range = 0;
    picoquic_path_t* path_x = cnx->path[0];
    picoquic_packet_context_t * pkt_ctx = &path_x->pkt_ctx[pc];
    picoquic_sack_item_t* next_sack = pkt_ctx->first_sack_item.next_sack;
    uint64_t ack_delay = 0;
    uint64_t ack_range = 0;
    uint64_t ack_gap = 0;
    uint64_t lowest_acknowledged = 0;
    size_t num_block_index = 0;
    uint8_t ack_type_byte = picoquic_frame_type_ack;

    /* Check that there is enough room in the packet, and something to acknowledge */
    if (pkt_ctx->first_sack_item.start_of_sack_range == (uint64_t)((int64_t)-1)) {
        consumed = 0;
    } else if (bytes_max < 13) {
        /* A valid ACK, with our encoding, uses at least 13 bytes.
        * If there is not enough space, don't attempt to encode it.
        */
        consumed = 0;
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else {
        /* Encode the first byte */
        bytes[byte_index++] = ack_type_byte;
        /* Encode the largest seen */
        if (byte_index < bytes_max) {
            l_largest = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                pkt_ctx->first_sack_item.end_of_sack_range);
            byte_index += l_largest;
        }
        /* Encode the ack delay */
        if (byte_index < bytes_max) {
            if (current_time > pkt_ctx->time_stamp_largest_received) {
                ack_delay = current_time - pkt_ctx->time_stamp_largest_received;
                ack_delay >>= cnx->local_parameters.ack_delay_exponent;
            }
            l_delay = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                ack_delay);
            byte_index += l_delay;
        }

        if (ret == 0) {
            /* Reserve one byte for the number of blocks */
            num_block_index = byte_index;
            byte_index++;
            /* Encode the size of the first ack range */
            if (byte_index < bytes_max) {
                ack_range = pkt_ctx->first_sack_item.end_of_sack_range - pkt_ctx->first_sack_item.start_of_sack_range;
                l_first_range = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                    ack_range);
                byte_index += l_first_range;
            }
        }

        if (l_delay == 0 || l_largest == 0 || l_first_range == 0 || byte_index > bytes_max) {
            /* not enough space */
            consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else if (ret == 0) {
            /* Set the lowest acknowledged */
            lowest_acknowledged = pkt_ctx->first_sack_item.start_of_sack_range;
            /* Encode the ack blocks that fit in the allocated space */
            while (num_block < 63 && next_sack != NULL) {
                size_t l_gap = 0;
                size_t l_range = 0;

                if (byte_index < bytes_max) {
                    ack_gap = lowest_acknowledged - next_sack->end_of_sack_range - 2; /* per spec */
                    l_gap = picoquic_varint_encode(bytes + byte_index,
                        bytes_max - byte_index, ack_gap);
                }

                if (byte_index + l_gap < bytes_max) {
                    ack_range = next_sack->end_of_sack_range - next_sack->start_of_sack_range;
                    l_range = picoquic_varint_encode(bytes + byte_index + l_gap,
                        bytes_max - byte_index - l_gap, ack_range);
                }

                if (l_gap == 0 || l_range == 0) {
                    /* Not enough space to encode this gap. */
                    break;
                } else {
                    byte_index += l_gap + l_range;
                    lowest_acknowledged = next_sack->start_of_sack_range;
                    next_sack = next_sack->next_sack;
                    num_block++;
                }
            }
            /* When numbers are lower than 64, varint encoding fits on one byte */
            bytes[num_block_index] = (uint8_t)num_block;

            /* Remember the ACK value and time */
            pkt_ctx->highest_ack_sent = pkt_ctx->first_sack_item.end_of_sack_range;
            pkt_ctx->highest_ack_time = current_time;

            consumed = byte_index;
        }
    }

    if (ret == 0) {
        pkt_ctx->ack_needed = 0;
    }

    cnx->protoop_outputc_callee = 1;
    cnx->protoop_outputv[0] = (protoop_arg_t) consumed;

    return (protoop_arg_t) ret;
}