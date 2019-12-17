#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, new_token_frame_t)
        char *token_str = my_malloc(cnx, (frame.token_length * 2) + 1);
        if (!token_str)
            return 0;
        snprintf_bytes(token_str, sizeof(token_str), frame.token_ptr, frame.token_length);
        char *frame_str = my_malloc(cnx, 300);
        if (!frame_str) return 0;
        PROTOOP_SNPRINTF(cnx, frame_str, 300, "{\"frame_type\": \"new_token\", \"length\": %d, \"token\": \"%s\"}", frame.token_length, (protoop_arg_t) token_str);
        helper_log_frame(cnx, frame_str);
        my_free(cnx, frame_str);
        my_free(cnx, token_str);
    TMP_FRAME_END
    return 0;
}