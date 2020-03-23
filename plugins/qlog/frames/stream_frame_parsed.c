#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, stream_frame_t)
        char *frame_str = my_malloc(cnx, 200);
        if (!frame_str) return 0;
        PROTOOP_SNPRINTF(cnx, frame_str, 200, "{\"frame_type\": \"stream_frame\", \"stream_id\": \"%" PRIu64 "\", \"offset\": \"%" PRIu64 "\", \"length\": %d%s}", frame.stream_id, frame.offset, frame.data_length, (protoop_arg_t) (frame.fin ? ", \"fin\": true": ""));
        helper_log_frame(cnx, frame_str);
        my_free(cnx, frame_str);
    TMP_FRAME_END
    return 0;
}