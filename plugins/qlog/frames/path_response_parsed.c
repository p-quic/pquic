#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, path_response_frame_t)
        char challenge[17];
        challenge[16] = 0;
        snprintf_bytes(challenge, sizeof(challenge), (uint8_t *)&frame.data, 8);
        char *frame_str = my_malloc(cnx, 100);
        if (!frame_str) return 0;
        PROTOOP_SNPRINTF(cnx, frame_str, 100, "{\"frame_type\": \"path_response\", \"data\": \"%s\"}", (protoop_arg_t) challenge);
        helper_log_frame(cnx, frame_str);
        my_free(cnx, frame_str);
    TMP_FRAME_END
    return 0;
}