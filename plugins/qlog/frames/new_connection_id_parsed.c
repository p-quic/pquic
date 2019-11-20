#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, new_connection_id_frame_t)
        char *id_str = my_malloc(cnx, (frame.connection_id.id_len * 2) + 1);
        if (!id_str)
            return 0;
        snprintf_bytes(id_str, (frame.connection_id.id_len * 2) + 1, frame.connection_id.id, frame.connection_id.id_len);
        LOG_EVENT(cnx, "FRAMES", "NEW_CONNECTION_ID_PARSED", "", "{\"ptr\": \"%p\", \"sequence\": %lu, \"len\": %d, \"cid\": \"%s\"}", (protoop_arg_t) parsed_frame, frame.sequence, frame.connection_id.id_len, (protoop_arg_t) id_str);
        my_free(cnx, id_str);
    TMP_FRAME_END
    return 0;
}