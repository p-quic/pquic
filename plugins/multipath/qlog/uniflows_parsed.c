#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, uniflows_frame_t)
        char *frame_str = my_malloc(cnx, 1000);
        if (!frame_str) return 0;
        size_t str_index = PROTOOP_SNPRINTF(cnx, frame_str, 1000, "{\"frame_type\": \"uniflows\", \"sequence\": \"%" PRIu64 "\", \"receiving_uniflows\": [", frame.sequence);
        for (int i = 0; i < frame.receiving_uniflows; i++) {
            str_index += PROTOOP_SNPRINTF(cnx, frame_str + str_index, 1000 - str_index, "%s{\"uniflow_id\": \"%" PRIu64 "\", \"local_address_id\": %d}", (protoop_arg_t) (i > 0 ? "," : ""),frame.receiving_uniflow_infos[i].uniflow_id, frame.receiving_uniflow_infos[i].local_address_id);
        }
        str_index += PROTOOP_SNPRINTF(cnx, frame_str + str_index, 1000 - str_index, "], \"sending_uniflows\": [");
        for (int i = 0; i < frame.active_sending_uniflows; i++) {
            str_index += PROTOOP_SNPRINTF(cnx, frame_str + str_index, 1000 - str_index, "%s{\"uniflow_id\": \"%" PRIu64 "\", \"local_address_id\": %d}", (protoop_arg_t) (i > 0 ? "," : ""),frame.sending_uniflow_infos[i].uniflow_id, frame.sending_uniflow_infos[i].local_address_id);
        }
        str_index += PROTOOP_SNPRINTF(cnx, frame_str + str_index, 1000 - str_index, "]}");
        helper_log_frame(cnx, frame_str);
        my_free(cnx, frame_str);
    TMP_FRAME_END
    return 0;
}