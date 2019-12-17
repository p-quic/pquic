#include "../bpf.h"

protoop_arg_t segment_prepared(picoquic_cnx_t *cnx)
{
    qlog_t *qlog = get_qlog_t(cnx);
    picoquic_packet_t *pkt = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    uint8_t *bytes = (uint8_t *) get_pkt(pkt, AK_PKT_BYTES);
    size_t len = (size_t) get_pkt(pkt, AK_PKT_LENGTH);

    int ret = 0;
    size_t consumed = (size_t) get_pkt(pkt, AK_PKT_OFFSET);
    while (ret == 0 && consumed < len) {
        size_t skip_consumed = 0;
        int pure_ack = 0;
        ret = helper_skip_frame(cnx, bytes + consumed, len - consumed, &skip_consumed, &pure_ack);
        consumed += skip_consumed;
    }

    qlog->pkt_hdr.ptype = (picoquic_packet_type_enum) get_pkt(pkt, AK_PKT_TYPE);
    qlog->pkt_hdr.pn = (uint64_t) get_pkt(pkt, AK_PKT_SEQUENCE_NUMBER);
    char *hdr_str = sprint_header(cnx, qlog);
    char *frame_str = sprint_frames(cnx, qlog);

    LOG_EVENT(cnx, "transport", "packet_sent", "", "{\"packet_type\": \"%s\", \"header\": %s, \"frames\": %s}", (protoop_arg_t) ptype(qlog->pkt_hdr.ptype), (protoop_arg_t) hdr_str, (protoop_arg_t) (frame_str ? frame_str : "[]"));

    if (frame_str) {
        my_free(cnx, frame_str);
    }
    if (hdr_str) {
        my_free(cnx, hdr_str);
    }
    return 0;
}