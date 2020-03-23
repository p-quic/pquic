#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    if (get_cnx(cnx, AK_CNX_RETURN_VALUE, 0)) {
        char *reason = (char *) get_cnx(cnx, AK_CNX_OUTPUT, 2);
        picoquic_packet_t *packet = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 3);
        uint64_t pn = get_pkt(packet, AK_PKT_SEQUENCE_NUMBER);
        char *packet_type = ptype(get_pkt(packet, AK_PKT_TYPE));
        LOG_EVENT(cnx, "recovery", "retransmission", reason, "{\"path\": \"%p\", \"packet_type\": \"%s\", \"packet_number\": \"%" PRIu64 "\"}", get_cnx(cnx, AK_CNX_INPUT, 1), (protoop_arg_t) packet_type, pn);
    }
    return 0;
}