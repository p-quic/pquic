#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, max_stream_data_frame_t)
        LOG_EVENT(cnx, "FRAMES", "MAX_STREAM_DATA_PARSED", "", "{\"ptr\": \"%p\", \"stream_id\": %lu, \"maximum_stream_data\": %lu}", (protoop_arg_t) parsed_frame, frame.stream_id, frame.maximum_stream_data);
    TMP_FRAME_END
    return 0;
}