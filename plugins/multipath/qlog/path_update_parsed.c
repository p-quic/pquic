#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, path_update_t)
        {
            char frame_str[100];
            PROTOOP_SNPRINTF(cnx, frame_str, sizeof(frame_str), "{\"frame_type\": \"path_update\", \"closed_path_id\": \"%" PRIu64 "\", \"proposed_path_id\": \"%" PRIu64 "\"}", frame.closed_path_id, frame.proposed_path_id);
            helper_log_frame(cnx, frame_str);
        }
    TMP_FRAME_END
    return 0;
}