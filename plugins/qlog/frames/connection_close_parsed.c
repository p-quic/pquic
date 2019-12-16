#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, connection_close_frame_t)
        size_t frame_str_len = 200 + frame.reason_phrase_length;
        char *frame_str = my_malloc(cnx, frame_str_len);
        if (!frame_str)
            return 0;
        PROTOOP_SNPRINTF(cnx, frame_str, frame_str_len, "{\"frame_type\": \"connection_close\", \"error_space\": \"transport\", \"raw_error_code\": %d, \"trigger_frame_type\": \"%x\", \"reason\": \"%s\"}", frame.error_code, frame.frame_type, (protoop_arg_t) (frame.reason_phrase_length > 0 ? frame.reason_phrase : ""));
        helper_log_frame(cnx, frame_str);
        my_free(cnx, frame_str);
    TMP_FRAME_END
    return 0;
}