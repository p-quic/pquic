#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, connection_close_frame_t)
        LOG_EVENT(cnx, "FRAMES", "CONNECTION_CLOSE_PARSED", "", "{\"ptr\": \"%p\", \"error\": %d, \"frame_type\": %lu, \"reason\": \"%s\"}", (protoop_arg_t) parsed_frame, frame.error_code, frame.frame_type, (protoop_arg_t) frame.reason_phrase);
    TMP_FRAME_END
    return 0;
}