#include "bpf.h"

/**
 * See PROTOOP_PARAM_WRITE_FRAME
 */
protoop_arg_t write_mp_ack_frame(picoquic_cnx_t *cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t *bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    mp_ack_ctx_t *mac = (mp_ack_ctx_t *) get_cnx(cnx, AK_CNX_INPUT, 2);
    
    size_t consumed = 0;
    
    uint64_t current_time = picoquic_current_time();
    picoquic_path_t *path_x = mac->path_x;
    picoquic_packet_context_enum pc = mac->pc;

    int ret = 0;
    size_t byte_index = 0;
    uint64_t num_block = 0;
    size_t l_path_id = 0;
    size_t l_largest = 0;
    size_t l_delay = 0;
    size_t l_first_range = 0;
    picoquic_packet_context_t * pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, AK_PATH_PKT_CTX, pc);
    picoquic_sack_item_t* first_sack = (picoquic_sack_item_t *) get_pkt_ctx(pkt_ctx, AK_PKTCTX_FIRST_SACK_ITEM);
    picoquic_sack_item_t* next_sack = (picoquic_sack_item_t *) get_sack_item(first_sack, AK_SACKITEM_NEXT_SACK);
    uint64_t ack_delay = 0;
    uint64_t ack_range = 0;
    uint64_t ack_gap = 0;
    uint64_t lowest_acknowledged = 0;
    size_t num_block_index = 0;
    uint8_t mp_ack_type_byte = MP_ACK_TYPE;
    bpf_data *bpfd = get_bpf_data(cnx);
    path_data_t *pd = mp_get_receive_path_data(bpfd, path_x);
    

    /* Check that there is enough room in the packet, and something to acknowledge */
    uint64_t first_sack_start_range = (uint64_t) get_sack_item(first_sack, AK_SACKITEM_START_RANGE);
    if (first_sack_start_range == (uint64_t)((int64_t)-1)) {
        consumed = 0;
    } else if (bytes_max - bytes < 14) {
        /* A valid ACK, with our encoding, uses at least 13 bytes.
        * If there is not enough space, don't attempt to encode it.
        */
        consumed = 0;
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else {
        /* Encode the first byte */
        my_memset(&bytes[byte_index++], mp_ack_type_byte, 1);
        /* Encode the path ID */
        if (byte_index < bytes_max - bytes) {
            l_path_id = picoquic_varint_encode(bytes + byte_index, (size_t) (bytes_max - bytes) - byte_index,
                pd->path_id);
            byte_index += l_path_id;
        }
        /* Encode the largest seen */
        uint64_t first_sack_end_range = (uint64_t) get_sack_item(first_sack, AK_SACKITEM_END_RANGE);
        if (byte_index < bytes_max - bytes) {
            l_largest = picoquic_varint_encode(bytes + byte_index, (size_t) (bytes_max - bytes) - byte_index,
                first_sack_end_range);
            byte_index += l_largest;
        }
        /* Encode the ack delay */
        if (byte_index < bytes_max - bytes) {
            uint64_t time_stamp_largest_received = (uint64_t) get_pkt_ctx(pkt_ctx, AK_PKTCTX_TIME_STAMP_LARGEST_RECEIVED);
            if (current_time > time_stamp_largest_received) {
                ack_delay = current_time - time_stamp_largest_received;
                ack_delay >>= (uint8_t) get_cnx(cnx, AK_CNX_LOCAL_PARAMETER, TRANSPORT_PARAMETER_ACK_DELAY_EXPONENT);
            }
            l_delay = picoquic_varint_encode(bytes + byte_index, (size_t) (bytes_max - bytes) - byte_index,
                ack_delay);
            byte_index += l_delay;
        }

        if (ret == 0) {
            /* Reserve one byte for the number of blocks */
            num_block_index = byte_index;
            byte_index++;
            /* Encode the size of the first ack range */
            if (byte_index < bytes_max - bytes) {
                ack_range = first_sack_end_range - first_sack_start_range;
                l_first_range = picoquic_varint_encode(bytes + byte_index, (size_t) (bytes_max - bytes) - byte_index,
                    ack_range);
                byte_index += l_first_range;
            }
        }

        if (l_path_id == 0 || l_delay == 0 || l_largest == 0 || l_first_range == 0 || byte_index > (size_t) (bytes_max - bytes)) {
            /* not enough space */
            consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else if (ret == 0) {
            /* Set the lowest acknowledged */
            lowest_acknowledged = first_sack_start_range;
            /* Encode the ack blocks that fit in the allocated space */
            while (num_block < 63 && next_sack != NULL) {
                size_t l_gap = 0;
                size_t l_range = 0;
                uint64_t next_sack_end_range = (uint64_t) get_sack_item(next_sack, AK_SACKITEM_END_RANGE);
                uint64_t next_sack_start_range = (uint64_t) get_sack_item(next_sack, AK_SACKITEM_START_RANGE);

                if (byte_index < (size_t) (bytes_max - bytes)) {
                    ack_gap = lowest_acknowledged - next_sack_end_range - 2; /* per spec */
                    l_gap = picoquic_varint_encode(bytes + byte_index,
                        (size_t) (bytes_max - bytes) - byte_index, ack_gap);
                }

                if (byte_index + l_gap < (size_t) (bytes_max - bytes)) {
                    ack_range = next_sack_end_range - next_sack_start_range;
                    l_range = picoquic_varint_encode(bytes + byte_index + l_gap,
                        (size_t) (bytes_max - bytes) - byte_index - l_gap, ack_range);
                }

                if (l_gap == 0 || l_range == 0) {
                    /* Not enough space to encode this gap. */
                    break;
                } else {
                    byte_index += l_gap + l_range;
                    lowest_acknowledged = next_sack_start_range;
                    next_sack = (picoquic_sack_item_t *) get_sack_item(next_sack, AK_SACKITEM_NEXT_SACK);
                    num_block++;
                }
            }
            /* When numbers are lower than 64, varint encoding fits on one byte */
            my_memset(&bytes[num_block_index], (uint8_t)num_block, 1);

            /* Remember the ACK value and time */
            set_pkt_ctx(pkt_ctx, AK_PKTCTX_HIGHEST_ACK_SENT, first_sack_end_range);
            set_pkt_ctx(pkt_ctx, AK_PKTCTX_HIGHEST_ACK_TIME, current_time);

            consumed = byte_index;
        }
    }

    if (ret == 0) {
        set_pkt_ctx(pkt_ctx, AK_PKTCTX_ACK_NEEDED, 0);
    }

    my_free(cnx, mac);

    //pd->doing_ack = false;

    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) consumed);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);

    return (protoop_arg_t) ret;
}