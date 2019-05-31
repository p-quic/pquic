#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, path_challenge_frame_t)
        LOG_EVENT(cnx, "FRAMES", "PATH_CHALLENGE_PARSED", "", "{\"ptr\": \"%p\", \"data\": \"%016lx\"}", (protoop_arg_t) parsed_frame, *((uint64_t *) &frame.data));
    TMP_FRAME_END
    return 0;
}