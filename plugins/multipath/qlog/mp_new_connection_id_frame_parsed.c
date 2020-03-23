#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, mp_new_connection_id_frame_t)
        {
            char *id_str = my_malloc(cnx, (frame.ncidf.connection_id.id_len * 2) + 1);
            if (!id_str) return 0;
            snprintf_bytes(id_str, (frame.ncidf.connection_id.id_len * 2) + 1, frame.ncidf.connection_id.id, (frame.ncidf.connection_id.id_len * 2) + 1);
            char *frame_str = my_malloc(cnx, 200);
            if (!frame_str) {
                my_free(cnx, id_str);
                return 0;
            }
            PROTOOP_SNPRINTF(cnx, frame_str, 200, "{\"frame_type\": \"mp_new_connection_id\", \"path_id\": \"%" PRIu64 "\", \"sequence\": %" PRIu64 ", \"len\": %d, \"cid\": \"%s\"}", frame.path_id, frame.ncidf.sequence, frame.ncidf.connection_id.id_len, (protoop_arg_t) id_str);
            helper_log_frame(cnx, frame_str);
            my_free(cnx, id_str);
            my_free(cnx, frame_str);
        }
    TMP_FRAME_END
    return 0;
}