#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) { // TODO: Convert to stream_state_updated
    uint64_t stream_id = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 1);
    char *stream_state = NULL;
#define IS_BIDI ((stream_id & 0x2) == 0)
    switch (get_cnx(cnx, AK_CNX_INPUT, 2)) {
        case picoquic_stream_flag_fin_received:
        case picoquic_stream_flag_fin_signalled:
            stream_state = IS_BIDI ? "half_closed_remote" : "closed";
            break;
        case picoquic_stream_flag_fin_notified:
        case picoquic_stream_flag_fin_sent:
            stream_state = IS_BIDI ? "half_closed_local" : "closed";
            break;
        case picoquic_stream_flag_reset_requested:
        case picoquic_stream_flag_reset_sent:
            stream_state = "reset_sent";
            break;
        case picoquic_stream_flag_reset_received:
        case picoquic_stream_flag_reset_signalled:
            stream_state = "reset_received";
            break;
        case picoquic_stream_flag_stop_sending_requested:
        case picoquic_stream_flag_stop_sending_sent:
            break;
        case picoquic_stream_flag_stop_sending_received:
        case picoquic_stream_flag_stop_sending_signalled:
            break;
    }
    if (stream_state) {
        LOG_EVENT(cnx, "transport", "stream_state_updated", "", "{\"ptr\": \"%p\", \"stream_id\": %" PRIu64 ", \"new\": \"%s\"}", get_cnx(cnx, AK_CNX_INPUT, 0), stream_id, (protoop_arg_t) stream_state);
    }
    return 0;
}