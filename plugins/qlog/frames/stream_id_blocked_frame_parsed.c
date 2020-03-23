#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, streams_blocked_frame_t)
        char *frame_str = my_malloc(cnx, 200);
        if (!frame_str) return 0;
        PROTOOP_SNPRINTF(cnx, frame_str, 200, "{\"frame_type\": \"streams_blocked\", \"stream_type\": \"%s\", \"limit\": \"%" PRIu64 "\"}", (protoop_arg_t) (frame.uni == 0 ? "bidirectional" : "unidirectional"), frame.stream_limit);
        helper_log_frame(cnx, frame_str);
        my_free(cnx, frame_str);
    TMP_FRAME_END
    return 0;
}