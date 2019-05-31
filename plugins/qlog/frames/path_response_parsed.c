#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, path_response_frame_t)
        LOG_EVENT(cnx, "FRAMES", "PATH_RESPONSE_PARSED", "", "{\"ptr\": \"%p\", \"data\": \"%016lx\"}", (protoop_arg_t) parsed_frame, frame.data);
    TMP_FRAME_END
    return 0;
}