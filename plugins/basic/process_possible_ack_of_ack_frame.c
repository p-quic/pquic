#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "memory.h"

static void process_ack_of_ack_range(picoquic_cnx_t* cnx, picoquic_sack_item_t* first_sack,
    uint64_t start_of_range, uint64_t end_of_range)
{
    if (first_sack->start_of_sack_range == start_of_range) {
        if (end_of_range < first_sack->end_of_sack_range) {
            first_sack->start_of_sack_range = end_of_range + 1;
        } else {
            first_sack->start_of_sack_range = first_sack->end_of_sack_range;
        }
    } else {
        picoquic_sack_item_t* previous = first_sack;
        picoquic_sack_item_t* next = previous->next_sack;

        while (next != NULL) {
            if (next->end_of_sack_range == end_of_range && next->start_of_sack_range == start_of_range) {
                /* Matching range should be removed */
                previous->next_sack = next->next_sack;
                my_free(cnx, next);
                break;
            } else if (next->end_of_sack_range > end_of_range) {
                previous = next;
                next = next->next_sack;
            } else {
                break;
            }
        }
    }
}

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
    while (target_sack->next_sack != NULL) {
        target_sack = target_sack->next_sack;
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
                process_ack_of_ack_range(cnx, first_sack, largest + 1 - range, largest);
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

    if (ret == 0 && p->ptype == picoquic_packet_0rtt_protected) {
        set_cnx(cnx, CNX_AK_NB_ZERO_RTT_ACKED, 0, get_cnx(cnx, CNX_AK_NB_ZERO_RTT_ACKED, 0) + 1);
    }

    byte_index = p->offset;

    while (ret == 0 && byte_index < p->length) {
        if (p->bytes[byte_index] == picoquic_frame_type_ack || p->bytes[byte_index] == picoquic_frame_type_ack_ecn) {
            int is_ecn = p->bytes[byte_index] == picoquic_frame_type_ack_ecn ? 1 : 0;
            ret = process_ack_of_ack_frame(cnx, &p->send_path->pkt_ctx[p->pc].first_sack_item,
                &p->bytes[byte_index], p->length - byte_index, &frame_length, is_ecn);
            byte_index += frame_length;
        } else if (PICOQUIC_IN_RANGE(p->bytes[byte_index], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            ret = helper_process_ack_of_stream_frame(cnx, &p->bytes[byte_index], p->length - byte_index, &frame_length);
            byte_index += frame_length;
        } else {
            ret = helper_skip_frame(cnx, &p->bytes[byte_index],
                p->length - byte_index, &frame_length, &frame_is_pure_ack);
            byte_index += frame_length;
        }
    }

    return 0;
}