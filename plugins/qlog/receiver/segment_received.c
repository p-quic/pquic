#include "../bpf.h"

protoop_arg_t segment_received(picoquic_cnx_t *cnx)
{
    qlog_t *qlog = get_qlog_t(cnx);
    char *hdr_str = sprint_header(cnx, qlog);
    char *frame_str = sprint_frames(cnx, qlog);

    LOG_EVENT(cnx, "transport", "packet_received", "", "{\"packet_type\": \"%s\", \"header\": %s, \"frames\": %s}", (protoop_arg_t) ptype(qlog->pkt_hdr.ptype), (protoop_arg_t) hdr_str, (protoop_arg_t) (frame_str ? frame_str : "[]"));

    if (frame_str) {
        my_free(cnx, frame_str);
    }
    if (hdr_str) {
        my_free(cnx, hdr_str);
    }
    return 0;
}