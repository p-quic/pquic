#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, blocked_frame_t)
        LOG_EVENT(cnx, "FRAMES", "BLOCKED_FRAME_PARSED", "", "{\"ptr\": \"%p\", \"offset\": %lu}", (protoop_arg_t) parsed_frame, frame.offset);
    TMP_FRAME_END
    return 0;
}