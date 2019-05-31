#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, stop_sending_frame_t)
        LOG_EVENT(cnx, "FRAMES", "STOP_SENDING_PARSED", "", "{\"ptr\": \"%p\", \"stream_id\": %lu, \"error\": %d}", (protoop_arg_t) parsed_frame, frame.stream_id, frame.application_error_code);
    TMP_FRAME_END
    return 0;
}