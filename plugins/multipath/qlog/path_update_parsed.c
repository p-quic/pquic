#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, path_update_t)
        {
            LOG_EVENT(cnx, "FRAMES", "PATH_UPDATE_PARSED", "", "{\"ptr\": \"%p\", \"closed_path_id\": %lu, \"proposed_path_id\": %lu}", (protoop_arg_t) parsed_frame, frame.closed_path_id, frame.proposed_path_id);
        }
    TMP_FRAME_END
    return 0;
}