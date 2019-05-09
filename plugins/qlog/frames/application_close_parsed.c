#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, application_close_frame_t)
        LOG_EVENT(cnx, "FRAMES", "APPLICATION_CLOSE_PARSED", "", "{\"ptr\": \"%p\", \"error\": %d, \"reason\": \"%s\"}", (protoop_arg_t) parsed_frame, frame.error_code, (protoop_arg_t) (frame.reason_phrase_length ? frame.reason_phrase : NULL));
    TMP_FRAME_END
    return 0;
}