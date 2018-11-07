#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "memory.h"

static int process_ack_of_ack_frame(picoquic_cnx_t* cnx, picoquic_sack_item_t* first_sack,
    uint8_t* bytes, size_t bytes_max, size_t* consumed, int is_ecn)
{
    int ret;
    uint64_t largest;
    uint64_t ack_delay;
    uint64_t num_block;
    uint64_t ecnx3[3];

    /* Find the oldest ACK range, in order to calibrate the
     * extension of the largest number to 64 bits */

    picoquic_sack_item_t* target_sack = first_sack;
    picoquic_sack_item_t* next_sack = (picoquic_sack_item_t*) get_sack_item(target_sack, SACK_ITEM_AK_NEXT_SACK);
    while (next_sack != NULL) {
        target_sack = next_sack;
        next_sack = (picoquic_sack_item_t*) get_sack_item(target_sack, SACK_ITEM_AK_NEXT_SACK);
    }

    ret = helper_parse_ack_header(bytes, bytes_max,
        &num_block, (is_ecn)? ecnx3 : NULL, 
        &largest, &ack_delay, consumed, 0);

    if (ret == 0) {
        size_t byte_index = *consumed;

        /* Process each successive range */

        while (1) {
            uint64_t range;
            size_t l_range;
            uint64_t block_to_block;

            if (byte_index >= bytes_max) {
                ret = -1;
                break;
            }

            l_range = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &range);
            if (l_range == 0) {
                byte_index = bytes_max;
                ret = -1;
                break;
            } else {
                byte_index += l_range;
            }

            range++;
            if (largest + 1 < range) {
                // DBG_PRINTF("ack range error: largest=%" PRIx64 ", range=%" PRIx64, largest, range);
                ret = -1;
                break;
            }

            if (range > 0) {
                helper_process_ack_of_ack_range(cnx, first_sack, largest + 1 - range, largest);
            }

            if (num_block-- == 0)
                break;

            /* Skip the gap */

            if (byte_index >= bytes_max) {
                ret = -1;
                break;
            } else {
                size_t l_gap = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &block_to_block);
                if (l_gap == 0) {
                    byte_index = bytes_max;
                    ret = -1;
                    break;
                } else {
                    byte_index += l_gap;
                    block_to_block += 1; /* Add 1, since there are never 0 gaps -- see spec. */
                    block_to_block += range;
                }
            }

            if (largest < block_to_block) {
                // DBG_PRINTF("ack gap error: largest=%" PRIx64 ", range=%" PRIx64 ", gap=%" PRIu64,
                //     largest, range, block_to_block - range);
                ret = -1;
                break;
            }

            largest -= block_to_block;
        }

        *consumed = byte_index;
    }

    return ret;
}

/**
 * See PROTOOP_NOPARAM_PROCESS_POSSIBLE_ACK_OF_ACK_FRAME
 */
protoop_arg_t process_possible_ack_of_ack_frame(picoquic_cnx_t* cnx)
{
    picoquic_packet_t* p = (picoquic_packet_t*) get_cnx(cnx, CNX_AK_INPUT, 0);

    int ret = 0;
    size_t byte_index;
    int frame_is_pure_ack = 0;
    size_t frame_length = 0;

    picoquic_packet_type_enum ptype = (picoquic_packet_type_enum) get_pkt(p, PKT_AK_TYPE);

    if (ret == 0 && ptype == picoquic_packet_0rtt_protected) {
        set_cnx(cnx, CNX_AK_NB_ZERO_RTT_ACKED, 0, get_cnx(cnx, CNX_AK_NB_ZERO_RTT_ACKED, 0) + 1);
    }

    byte_index = (size_t) get_pkt(p, PKT_AK_OFFSET);
    uint32_t length = (uint32_t) get_pkt(p, PKT_AK_LENGTH);
    uint8_t *bytes = (uint8_t *) get_pkt(p, PKT_AK_BYTES);

    while (ret == 0 && byte_index < length) {
        if (bytes[byte_index] == picoquic_frame_type_ack || bytes[byte_index] == picoquic_frame_type_ack_ecn) {
            int is_ecn = bytes[byte_index] == picoquic_frame_type_ack_ecn ? 1 : 0;
            picoquic_path_t *send_path = (picoquic_path_t *) get_pkt(p, PKT_AK_SEND_PATH);
            picoquic_packet_context_enum pc = (picoquic_packet_context_enum) get_pkt(p, PKT_AK_CONTEXT);
            picoquic_packet_context_t *pkt_ctx = (picoquic_packet_context_t *) get_path(send_path, PATH_AK_PKT_CTX, pc);
            picoquic_sack_item_t *first_sack = (picoquic_sack_item_t *) get_pkt_ctx(pkt_ctx, PKT_CTX_AK_FIRST_SACK_ITEM);
            ret = process_ack_of_ack_frame(cnx, first_sack,
                &bytes[byte_index], length - byte_index, &frame_length, is_ecn);
            byte_index += frame_length;
        } else if (PICOQUIC_IN_RANGE(bytes[byte_index], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            ret = helper_process_ack_of_stream_frame(cnx, &bytes[byte_index], length - byte_index, &frame_length);
            byte_index += frame_length;
        } else {
            ret = helper_skip_frame(cnx, &bytes[byte_index],
                length - byte_index, &frame_length, &frame_is_pure_ack);
            byte_index += frame_length;
        }
    }

    return 0;
}