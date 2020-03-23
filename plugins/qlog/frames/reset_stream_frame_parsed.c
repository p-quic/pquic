#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, reset_stream_frame_t)
        char *frame_str = my_malloc(cnx, 200);
        if (!frame_str) return 0;
        PROTOOP_SNPRINTF(cnx, frame_str, 200, "{\"frame_type\": \"reset_stream\", \"stream_id\": \"%" PRIu64 "\", \"error_code\": \"%" PRIu64 "\", \"final_size\": \"%" PRIu64 "\"}", frame.stream_id, frame.app_error_code, frame.final_offset);
        helper_log_frame(cnx, frame_str);
        my_free(cnx, frame_str);
    TMP_FRAME_END
    return 0;
}