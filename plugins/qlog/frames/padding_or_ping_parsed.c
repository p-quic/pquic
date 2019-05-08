#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, padding_or_ping_frame_t)
        LOG_EVENT(cnx, "FRAMES", frame.is_ping ? "PING_FRAME_PARSED": "PADDING_PARSED", "", "{\"ptr\": \"%p\", \"length\": %d}", (protoop_arg_t) parsed_frame, frame.num_block);
    TMP_FRAME_END
    return 0;
}