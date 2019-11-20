#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN_MALLOC(cnx, parsed_frame, frame, ack_frame_t)
        {
            char *ack_str = my_malloc(cnx, 800);
            if (!ack_str)
                return 0;
            size_t ack_ofs = 0;
            uint64_t largest = frame->largest_acknowledged;
            int ack_block_count = frame->ack_block_count;
            for (int num_block = -1; num_block < ack_block_count; num_block++) {
                uint64_t block_to_block;
                uint64_t range;
                if (num_block == -1) {
                    range = frame->first_ack_block + 1;
                } else {
                    range = frame->ack_blocks[num_block].additional_ack_block + 1;
                }

                if (range <= 1)
                    ack_ofs += snprintf(ack_str + ack_ofs, 800 - ack_ofs, "[%lu]", largest);
                else
                    ack_ofs += snprintf(ack_str + ack_ofs, 800 - ack_ofs, "[%lu, %lu]", largest - range + 1, largest);

                ack_ofs += snprintf(ack_str + ack_ofs, 800 - ack_ofs, num_block == ack_block_count - 1 ? "" : ", ");

                if (num_block == ack_block_count - 1)
                    break;

                block_to_block = frame->ack_blocks[num_block + 1].gap + 1;
                block_to_block += range;

                largest -= block_to_block;
            }
            ack_str[ack_ofs] = 0;
            LOG_EVENT(cnx, "FRAMES", "ACK_FRAME_PARSED", "", "{\"ptr\": \"%p\", \"largest\": %lu, \"blocks\": [%s]}", (protoop_arg_t) parsed_frame, frame->largest_acknowledged, (protoop_arg_t) ack_str);
            my_free(cnx, ack_str);
        }
    TMP_FRAME_END_MALLOC(cnx, frame)
    return 0;
}