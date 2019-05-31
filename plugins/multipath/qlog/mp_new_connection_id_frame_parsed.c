#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, mp_new_connection_id_frame_t)
        {
            char *id_str = my_malloc(cnx, (frame.ncidf.connection_id.id_len * 2) + 1);
            snprintf_bytes(id_str, (frame.ncidf.connection_id.id_len * 2) + 1, frame.ncidf.connection_id.id, (frame.ncidf.connection_id.id_len * 2) + 1);
            LOG_EVENT(cnx, "FRAMES", "MP_NEW_CONNECTION_ID_PARSED", "", "{\"ptr\": \"%p\", \"path_id\": %lu, \"sequence\": %lu, \"len\": %d, \"cid\": \"%s\"}", (protoop_arg_t) parsed_frame, frame.path_id, frame.ncidf.sequence, frame.ncidf.connection_id.id_len, (protoop_arg_t) id_str);
            my_free(cnx, id_str);
        }
    TMP_FRAME_END
    return 0;
}