#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, new_connection_id_frame_t)
        char *id_str = my_malloc(cnx, (frame.connection_id.id_len * 2) + 1);
        if (!id_str)
            return 0;
        snprintf_bytes(id_str, (frame.connection_id.id_len * 2) + 1, frame.connection_id.id, frame.connection_id.id_len);
        char *frame_str = my_malloc(cnx, 400);
        if (!frame_str) return 0;
        PROTOOP_SNPRINTF(cnx, frame_str, 400, "{\"frame_type\": \"new_connection_id\", \"sequence_number\": \"%" PRIu64 "\", \"retire_prior_to\": \"%" PRIu64 "\", \"length\": %d, \"connection_id\": \"%s\", \"reset_token\": \"\"}", frame.sequence, frame.retire_prior_to, frame.connection_id.id_len, (protoop_arg_t) id_str);
        helper_log_frame(cnx, frame_str);
        my_free(cnx, frame_str);
        my_free(cnx, id_str);
    TMP_FRAME_END
    return 0;
}