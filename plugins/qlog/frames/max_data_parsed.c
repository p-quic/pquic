#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, max_data_frame_t)
        LOG_EVENT(cnx, "FRAMES", "MAX_DATA_PARSED", "", "{\"ptr\": \"%p\", \"maximum_data\": %lu}", (protoop_arg_t) parsed_frame, frame.maximum_data);
    TMP_FRAME_END
    return 0;
}