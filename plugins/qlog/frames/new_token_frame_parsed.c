#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, new_token_frame_t)
        char *token_str = my_malloc(cnx, (frame.token_length * 2) + 1);
        if (!token_str)
            return 0;
        snprintf_bytes(token_str, sizeof(token_str), frame.token_ptr, frame.token_length);
        LOG_EVENT(cnx, "FRAMES", "NEW_TOKEN_PARSED", "", "{\"ptr\": \"%p\", \"length\": %lu, \"token\": \"%s\"}", (protoop_arg_t) parsed_frame, frame.token_length, (protoop_arg_t) token_str);
        my_free(cnx, token_str);
    TMP_FRAME_END
    return 0;
}