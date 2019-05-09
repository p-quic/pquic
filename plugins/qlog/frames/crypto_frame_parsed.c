#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, crypto_frame_t)
        LOG_EVENT(cnx, "FRAMES", "CRYPTO_FRAME_PARSED", "", "{\"ptr\": \"%p\", \"offset\": %lu, \"length\": %lu}", (protoop_arg_t) parsed_frame, frame.offset, frame.length);
    TMP_FRAME_END
    return 0;
}