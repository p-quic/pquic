#include "../bpf.h"

#define BLOCK_STR_LEN 1200

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN_MALLOC(cnx, parsed_frame, frame, mp_ack_frame_t)
        {
            char *block_str = my_malloc(cnx, BLOCK_STR_LEN);
            size_t ack_ofs = 0;
            uint64_t largest = frame->ack.largest_acknowledged;
            int ack_block_count = frame->ack.ack_block_count;
            for (int num_block = -1; num_block < ack_block_count; num_block++) {
                uint64_t block_to_block;
                uint64_t range;
                if (num_block == -1) {
                    range = frame->ack.first_ack_block + 1;
                } else {
                    range = frame->ack.ack_blocks[num_block].additional_ack_block + 1;
                }

                if (range <= 1)
                    ack_ofs += snprintf(block_str + ack_ofs, BLOCK_STR_LEN - ack_ofs, "[%" PRIu64 "]", largest);
                else
                    ack_ofs += snprintf(block_str + ack_ofs, BLOCK_STR_LEN - ack_ofs, "[%" PRIu64 ", %" PRIu64 "]", largest - range + 1, largest);

                ack_ofs += snprintf(block_str + ack_ofs, BLOCK_STR_LEN - ack_ofs, num_block == ack_block_count - 1 ? "" : ", ");

                if (num_block == ack_block_count - 1)
                    break;

                block_to_block = frame->ack.ack_blocks[num_block].gap + 1;
                block_to_block += range;

                largest -= block_to_block;
            }
            block_str[ack_ofs] = 0;
            char *ack_str = my_malloc(cnx, BLOCK_STR_LEN + 200);
            if (!ack_str)
                return 0;
            PROTOOP_SNPRINTF(cnx, ack_str, BLOCK_STR_LEN + 200, "{\"frame_type\": \"mp_ack\", \"path_id\": \"%" PRIu64 "\", \"ack_delay\": \"%" PRIu64 "\", \"acked_ranges\": [%s]}", frame->path_id, frame->ack.ack_delay, (protoop_arg_t) block_str);
            helper_log_frame(cnx, ack_str);
            my_free(cnx, block_str);
            my_free(cnx, ack_str);
        }
    TMP_FRAME_END_MALLOC(cnx, frame)
    return 0;
}