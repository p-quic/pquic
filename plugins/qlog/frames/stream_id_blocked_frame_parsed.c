#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, stream_id_blocked_frame_t)
        LOG_EVENT(cnx, "FRAMES", "STREAM_ID_BLOCKED_FRAME_PARSED", "", "{\"ptr\": \"%p\", \"stream_id\": %lu}", (protoop_arg_t) parsed_frame, frame.stream_id);
    TMP_FRAME_END
    return 0;
}