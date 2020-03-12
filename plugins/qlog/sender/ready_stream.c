#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    picoquic_stream_head *stream = (picoquic_stream_head *) get_cnx(cnx, AK_CNX_RETURN_VALUE, 0);
    if (!stream)
        LOG_EVENT(cnx, "STREAMS", "READY_STREAM", "", "{\"stream\": null}");
    else
        LOG_EVENT(cnx, "STREAMS", "READY_STREAM", "", "{\"stream\": \"%p\", \"stream_id\": %" PRIu64 ", \"sent_offset\": %" PRIu64 "}", (protoop_arg_t) stream, get_stream_head(stream, AK_STREAMHEAD_STREAM_ID), get_stream_head(stream, AK_STREAMHEAD_SENT_OFFSET));
    return 0;
}